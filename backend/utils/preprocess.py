"""
Preprocessing / normalization utilities.

Attackers frequently try to dodge rule-matching with whitespace tricks,
unicode homoglyphs, zero-width characters, or mixed-case obfuscation.
This module normalizes text BEFORE it hits any detection layer so all
downstream layers see a canonical form.
"""
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


def strip_zero_width(text: str) -> str:
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    return text


def normalize_unicode(text: str) -> str:
    """NFKC normalization collapses many homoglyph / fullwidth tricks
    (e.g. fullwidth Latin letters used to dodge keyword matches)."""
    return unicodedata.normalize("NFKC", text)


def collapse_whitespace(text: str) -> str:
    return _MULTI_WHITESPACE_RE.sub(" ", text).strip()


def preprocess(text: str) -> str:
    """Full normalization pipeline. Returns the canonical string used
    for rule matching and embedding. The ORIGINAL text is still kept
    for display/logging purposes by the caller."""
    if text is None:
        return ""
    text = normalize_unicode(text)
    text = strip_zero_width(text)
    text = collapse_whitespace(text)
    return text


def lowercase_fold(text: str) -> str:
    return text.lower()
