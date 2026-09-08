"""
Risk score combination + tier mapping.

Implements the multi-layer agreement gate from PRD 5.2 Layer E: a lone
rule match is never sufficient for HIGH severity. HIGH requires the rule
match to be corroborated by BOTH elevated embedding similarity AND
elevated classifier probability. This is the fix for "over-defense"
(InjecGuard, 2024) where rule-only guards flag benign trigger-word
prompts like "ignore the typo in my message".
"""
from dataclasses import dataclass
from typing import Optional

import config


@dataclass
class SeverityResult:
    score: float
    tier: str  # SAFE / LOW / MEDIUM / HIGH
    action: str  # pass / sanitize / block


def compute_risk_score(rule_score: float, embed_score: float, classifier_prob: float, drift_score: float) -> float:
    score = (
        config.WEIGHT_RULE * (1.0 if rule_score >= 0.5 else 0.0) * rule_score
        + config.WEIGHT_EMBEDDING * embed_score
        + config.WEIGHT_CLASSIFIER * classifier_prob
        + config.WEIGHT_DRIFT * drift_score
    )
    return min(round(score, 4), 1.0)


def get_tier(
    score: float,
    rule_score: float,
    embed_score: float,
    classifier_prob: float,
    is_tool_output: bool = False,
    matched_rules=None,
) -> str:
    high_embed_th = config.HIGH_EMBED_THRESHOLD
    high_clf_th = config.HIGH_CLASSIFIER_THRESHOLD
    if is_tool_output:
        # Layer F: stricter thresholds for indirect injection via tool
        # output / RAG retrieval, since it has no legitimate reason to
        # contain instruction-like language directed at the model.
        high_embed_th += config.TOOL_OUTPUT_EMBED_DELTA
        high_clf_th += config.TOOL_OUTPUT_CLASSIFIER_DELTA

    rule_match = rule_score >= 0.5
    matched_rules = matched_rules or []
    content_harm_match = any(rule.startswith("content_harm_") for rule in matched_rules)

    if content_harm_match:
        return "HIGH"
    elif rule_match and embed_score > high_embed_th and classifier_prob > high_clf_th:
        return "HIGH"
    elif score >= config.MEDIUM_SCORE_THRESHOLD:
        return "MEDIUM"
    elif rule_match and (
        embed_score > config.MEDIUM_EMBED_THRESHOLD
        or classifier_prob > config.MEDIUM_CLASSIFIER_THRESHOLD
    ):
        return "MEDIUM"
    elif score >= config.LOW_SCORE_THRESHOLD or rule_match:
        return "LOW"
    else:
        return "SAFE"


_TIER_ACTION = {
    "SAFE": "pass",
    "LOW": "pass",
    "MEDIUM": "sanitize",
    "HIGH": "block",
}


def _drift_has_correlated_signal(rule_score: float, embed_score: float, classifier_prob: float, matched_rules) -> bool:
    matched = set(matched_rules or [])
    if rule_score >= 0.5:
        return True
    if embed_score >= config.MEDIUM_EMBED_THRESHOLD or classifier_prob >= config.MEDIUM_CLASSIFIER_THRESHOLD:
        return True
    if "soft_trigger:override" in matched and ({"soft_trigger:secret", "soft_trigger:secrets"} & matched):
        return True
    if "soft_trigger:ignore" in matched and "soft_trigger:system" in matched:
        return True
    return False


def evaluate(
    rule_score: float,
    embed_score: float,
    classifier_prob: float,
    drift_score: float,
    is_tool_output: bool = False,
    matched_rules=None,
) -> SeverityResult:
    score = compute_risk_score(rule_score, embed_score, classifier_prob, drift_score)
    tier = get_tier(score, rule_score, embed_score, classifier_prob, is_tool_output, matched_rules)
    if (
        drift_score >= config.DRIFT_ALERT_THRESHOLD
        and tier in ("SAFE", "LOW")
        and _drift_has_correlated_signal(rule_score, embed_score, classifier_prob, matched_rules)
    ):
        tier = "MEDIUM"
    action = _TIER_ACTION[tier]
    return SeverityResult(score=score, tier=tier, action=action)
