"""
Layer C — Trained classifier.

For the hackathon MVP this is a lightweight Logistic Regression over a
small handcrafted feature vector (rule score, semantic score, prompt
length, suspicious-word density, history score) rather than a fine-tuned
transformer — judges care about working architecture and explainability,
not whether the classifier is DeBERTa or logistic regression (see the
architecture notes). `models/train.py` retrains this model from
data/attacks.csv + data/benign.csv; `classifier.pkl` is the persisted
artifact loaded at runtime. Falls back to a rule-based heuristic if no
trained artifact is present yet, so the API keeps working out of the box.
"""
import os
import re
from dataclasses import dataclass

import numpy as np

import config

_SUSPICIOUS_WORDS = [
    "ignore", "disregard", "override", "bypass", "jailbreak", "dan",
    "developer mode", "system prompt", "unrestricted", "unfiltered",
    "no rules", "no restrictions", "pretend", "act as",
]

# Extra cheap, hand-crafted signals (review item #2): these cost nothing
# to compute relative to the embedding/classifier layers and add
# robustness against attacks that don't hit a known phrase but still
# "look" adversarial (shouting, heavy punctuation, obfuscated unicode).
_OVERRIDE_KEYWORDS = [
    "ignore", "disregard", "override", "bypass", "forget", "reset",
    "unlock", "unrestricted", "unfiltered", "no restrictions", "no rules",
]

_MODEL_PATH = os.path.join(config.MODEL_DIR, "detector.pkl")

FEATURE_NAMES = [
    "Rule score",
    "Semantic score",
    "Prompt length",
    "Suspicious-word density",
    "History score",
    "Imperative opening",
    "Override-keyword density",
    "Capitalization ratio",
    "Punctuation density",
    "Unicode obfuscation",
]


@dataclass
class ClassifierResult:
    probability: float
    features: dict


def _capitalization_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    upper = sum(1 for c in letters if c.isupper())
    return upper / len(letters)


def _punctuation_density(text: str) -> float:
    if not text:
        return 0.0
    punct = sum(1 for c in text if c in "!?.,;:\"'`~^*_")
    return min(punct / max(len(text), 1) * 5.0, 1.0)  # scaled so "normal" prose stays low


def _unicode_obfuscation_score(text: str) -> float:
    """Flags zero-width characters, non-ASCII lookalikes, and other
    tricks used to slip banned words past a naive rule/keyword matcher."""
    if not text:
        return 0.0
    zero_width = sum(1 for c in text if c in "\u200b\u200c\u200d\ufeff")
    non_ascii = sum(1 for c in text if ord(c) > 127)
    score = (zero_width * 2 + non_ascii) / max(len(text), 1)
    return min(score, 1.0)


def _override_keyword_count(folded: str) -> float:
    hits = sum(1 for w in _OVERRIDE_KEYWORDS if w in folded)
    return min(hits / 4.0, 1.0)


def _extract_features(text: str, rule_score: float, semantic_score: float, history_score: float) -> np.ndarray:
    folded = text.lower()
    length_norm = min(len(text) / 500.0, 1.0)
    suspicious_hits = sum(1 for w in _SUSPICIOUS_WORDS if w in folded)
    suspicious_density = min(suspicious_hits / 5.0, 1.0)
    imperative = 1.0 if re.match(r"^\s*(ignore|disregard|act|pretend|reveal|override|bypass)\b", folded) else 0.0

    override_density = _override_keyword_count(folded)
    cap_ratio = _capitalization_ratio(text)
    punct_density = _punctuation_density(text)
    unicode_score = _unicode_obfuscation_score(text)

    return np.array([
        rule_score,
        semantic_score,
        length_norm,
        suspicious_density,
        history_score,
        imperative,
        override_density,
        cap_ratio,
        punct_density,
        unicode_score,
    ])


class Classifier:
    _instance = None

    def __init__(self):
        self.model = None
        if os.path.exists(_MODEL_PATH):
            try:
                import joblib
                self.model = joblib.load(_MODEL_PATH)
            except Exception:
                self.model = None

    @classmethod
    def instance(cls) -> "Classifier":
        if cls._instance is None:
            cls._instance = Classifier()
        return cls._instance

    def predict(self, text: str, rule_score: float, semantic_score: float, history_score: float = 0.0) -> ClassifierResult:
        features = _extract_features(text, rule_score, semantic_score, history_score)

        if self.model is not None:
            proba = float(self.model.predict_proba(features.reshape(1, -1))[0][1])
        else:
            # Heuristic fallback (weighted sum of features) used until
            # `models/train.py` has been run to produce detector.pkl.
            # Rule/semantic still dominate; the four new cheap features
            # each get a small weight since none is individually decisive.
            weights = np.array([0.30, 0.30, 0.04, 0.12, 0.04, 0.04, 0.06, 0.04, 0.03, 0.03])
            proba = float(np.clip(np.dot(features, weights), 0.0, 1.0))

        return ClassifierResult(
            probability=round(proba, 4),
            features={
                "rule_score": round(float(features[0]), 4),
                "semantic_score": round(float(features[1]), 4),
                "length_norm": round(float(features[2]), 4),
                "suspicious_density": round(float(features[3]), 4),
                "history_score": round(float(features[4]), 4),
                "imperative_opening": bool(features[5]),
                "override_keyword_density": round(float(features[6]), 4),
                "capitalization_ratio": round(float(features[7]), 4),
                "punctuation_density": round(float(features[8]), 4),
                "unicode_obfuscation_score": round(float(features[9]), 4),
            },
        )
