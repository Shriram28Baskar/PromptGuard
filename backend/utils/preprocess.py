"""
Preprocessing / normalization utilities.

Attackers frequently try to dodge rule-matching with whitespace tricks,
unicode homoglyphs, zero-width characters, or mixed-case obfuscation.
This module normalizes text BEFORE it hits any detection layer so all
downstream layers see a canonical form.

Base64 heuristic (detect_base64_instructions)
---------------------------------------------
Indirect injection attacks sometimes encode their payload in Base64 to
bypass keyword-based rules. detect_base64_instructions() finds plausible
Base64 blocks (≥ 20 chars), decodes them, and — only if the decoded text
contains injection-shaped keywords — injects a readable marker:

    [DECODED_B64: <decoded_text>]

after the original encoded block. Rule engine pattern `indirect_split_chunk`
matches this marker. The original encoded block is preserved so SBERT still
sees the full document context.

CALL ORDER CONTRACT
-------------------
preprocess() is called FIRST in pipeline.py. The processed text is then
passed to windowing.split_windows() for tool_output inputs. This means:
  1. Base64 markers are injected BEFORE the text is split into windows.
  2. A [DECODED_B64:...] marker (≤ 15 words) fits within a single window
     and is never split across two windows (window overlap is 20 words).
  3. rule_engine.match_rules() always receives the fully preprocessed text
     (including markers) before windowing occurs.

Limitations:
  - Only UTF-8 decodable blocks are decoded; binary payloads are ignored.
  - Base64 padding is inferred when missing (common in URLs and JWTs).
  - Only a fixed keyword list is checked; novel obfuscation keywords not
    in that list will not trigger the marker. This is declared as a
    Non-goal in the README.
"""
import base64 as _b64
import re
import unicodedata

ZERO_WIDTH_CHARS = [
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # BOM
    "\u2060",  # word joiner
]

_MULTI_WHITESPACE_RE = re.compile(r"\s+")

# Matches plausible Base64 blocks: ≥ 20 chars of the Base64 alphabet
# optionally followed by 0–2 padding chars. We require ≥ 20 chars to
# avoid false-positive matches on short alphanumeric strings (e.g., IDs,
# hashes, version strings). JWTs are matched because they contain long
# encoded segments separated by dots; the regex fires on each segment.
_B64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Keywords whose presence in a decoded block marks it as a potential
# injection payload. Covers the most common injection framing.
# Deliberately kept narrow to limit false positives on legitimate
# base64-encoded data (config blobs, certificates, etc.).
_INJECTION_KEYWORDS = frozenset([
    "ignore", "override", "disregard", "bypass",
    "system prompt", "reveal", "instructions",
    "jailbreak", "forget previous", "act as",
    "pretend you", "developer mode", "dan ",
])


def strip_zero_width(text: str) -> str:
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    return text


def normalize_unicode(text: str) -> str:
    """NFKC normalization collapses many homoglyph / fullwidth tricks
    (e.g. fullwidth Latin letters used to dodge keyword matches)."""
    return unicodedata.normalize("NFKC", text)


def detect_base64_instructions(text: str) -> str:
    """Find Base64 blocks and inject markers for any that decode to injection content.

    For each match of _B64_PATTERN:
      1. Attempt UTF-8 decode (with inferred padding).
      2. If decoding fails or the block is not valid UTF-8, leave it unchanged.
      3. If the decoded text contains any keyword from _INJECTION_KEYWORDS,
         append [DECODED_B64: <decoded_text>] after the original block.
      4. Otherwise leave the block unchanged.

    PURELY IN-MEMORY — no I/O, no network calls, no external state.
    The original encoded block is always preserved in the output.
    """
    def _replace(m: re.Match) -> str:
        b64_str = m.group(0)
        # Infer missing padding (Base64 length must be divisible by 4)
        padding_needed = (4 - len(b64_str) % 4) % 4
        try:
            raw = _b64.b64decode(b64_str + "=" * padding_needed)
            decoded = raw.decode("utf-8")
        except Exception:
            return b64_str  # binary or invalid UTF-8 — leave unchanged

        decoded_lower = decoded.lower()
        if any(kw in decoded_lower for kw in _INJECTION_KEYWORDS):
            return f"{b64_str} [DECODED_B64: {decoded}]"
        return b64_str

    return _B64_PATTERN.sub(_replace, text)


def collapse_whitespace(text: str) -> str:
    return _MULTI_WHITESPACE_RE.sub(" ", text).strip()


def preprocess(text: str) -> str:
    """Full normalization pipeline. Returns the canonical string used
    for rule matching and embedding. The ORIGINAL text is still kept
    for display/logging purposes by the caller.

    Order (DO NOT reorder — see CALL ORDER CONTRACT in module docstring):
      1. normalize_unicode  — NFKC, collapses fullwidth/homoglyph tricks
      2. strip_zero_width   — removes invisible separator characters
      3. detect_base64_instructions — injects [DECODED_B64:] markers BEFORE
                                      windowing or rule matching occur
      4. collapse_whitespace — normalises repeated whitespace last, so
                               inserted markers are also whitespace-clean
    """
    if text is None:
        return ""
    text = normalize_unicode(text)
    text = strip_zero_width(text)
    text = detect_base64_instructions(text)   # must run before windowing
    text = collapse_whitespace(text)
    return text


def lowercase_fold(text: str) -> str:
    return text.lower()
