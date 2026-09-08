"""
utils/windowing.py — Sliding-window text splitter for tool_output scoring.

MOTIVATION
----------
Layer B (SBERT semantic similarity) and Layer C (LR classifier) were calibrated
on short attack phrases (~10–40 tokens). When a short injection payload is embedded
inside a 200–400-word document, scoring the whole document as a single vector
dilutes the payload's contribution and can cause Layer B/C to under-score even
when Layer A (rule_engine) correctly flags the span.

This module splits already-preprocessed tool_output text into overlapping
sentence-level windows before Layer B/C scoring. pipeline.py then takes the
MAX-risk score across all windows (rather than an average), so a single
high-confidence window surfaces the attack regardless of surrounding benign context.

CALL ORDER CONTRACT
-------------------
split_windows() MUST receive text that has ALREADY been run through preprocess().
This is enforced by pipeline.py calling preprocess() first, then passing the
result here. Specifically:
  - preprocess() already injected any [DECODED_B64: ...] markers.
  - NFKC normalization and zero-width char stripping are done.
  - Whitespace is collapsed.
Calling split_windows() on raw (un-preprocessed) text is incorrect and will
miss obfuscated attacks that preprocess() normalizes.

OVERLAP GUARANTEE
-----------------
With default overlap=20 words and window_size=80 words:
  - Consecutive windows share 20 words at their boundary.
  - A [DECODED_B64: ...] marker is ≤ 15 words — it always fits inside a single
    window and cannot straddle a boundary. (If it did, it would appear in BOTH
    the preceding and following window due to the overlap, so at least one window
    contains it in full.)
  - An attack phrase ≤ 20 words that falls at a window boundary appears complete
    in at least one window. Longer attacks spanning both sides of a boundary
    still produce high signal in the window containing the larger portion.
"""
from typing import List


def split_windows(
    text: str,
    window_size: int = 35,
    overlap: int = 15,
) -> List[str]:
    """Split preprocessed text into overlapping sentence- and token-level windows.

    Algorithm:
        1. Extract individual sentences (splitting on [.!?\\n]).
        2. Extract sliding windows of `window_size` words with `overlap` words.
        3. Combine both sets of windows, deduplicate, and return.

    This dual approach guarantees:
        - Natural sentences containing an attack are isolated without dilution.
        - Unpunctuated text or attacks spanning sentence boundaries are caught
          by the overlapping sliding windows.
        - Always returns at least one window (never empty list).

    Args:
        text:        Already-preprocessed text (preprocess() must run first).
        window_size: Target window width in words. Default 35.
        overlap:     Words shared between consecutive windows. Default 15.

    Returns:
        List of non-empty window strings. Minimum one element.
    """
    import re

    if not text or not text.strip():
        return [""]

    words = text.split()
    n = len(words)

    windows: List[str] = []

    # 1. Sliding word windows
    if n <= window_size:
        windows.append(text)
    else:
        step = max(1, window_size - overlap)
        start = 0
        while start < n:
            end = min(start + window_size, n)
            windows.append(" ".join(words[start:end]))
            if end >= n:
                break
            start += step

    # 2. Sentence-level windows (if punctuation exists)
    sentences = [s.strip() for s in re.split(r"(?<=[.!?\n])\s+", text) if s.strip()]
    for s in sentences:
        s_words = s.split()
        if 3 <= len(s_words) <= 60:
            windows.append(s)

    # Deduplicate while preserving order
    seen = set()
    deduped: List[str] = []
    for w in windows:
        clean_w = w.strip()
        if clean_w and clean_w not in seen:
            seen.add(clean_w)
            deduped.append(clean_w)

    return deduped if deduped else [text]


def word_count(text: str) -> int:
    """Return approximate word count (whitespace-split)."""
    return len(text.split()) if text else 0


def length_bucket(text: str) -> str:
    """Classify a document into a length bucket for evaluation reporting.

    Buckets:
        short:  <= 80 words
        medium: 81–200 words
        long:   > 200 words
    """
    wc = word_count(text)
    if wc <= 80:
        return "short"
    elif wc <= 200:
        return "medium"
    else:
        return "long"
