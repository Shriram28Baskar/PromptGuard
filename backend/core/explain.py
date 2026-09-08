"""
Layer for explainability (differentiator #1). Every flagged message must
have a non-empty, specific reason string — never just a bare score.
"""
from typing import List, Optional


def build_explanation(
    tier: str,
    action: str,
    matched_rules: List[str],
    matched_spans: List[str],
    nearest_attack: Optional[str],
    nearest_attack_cluster: Optional[str],
    attack_similarity: float,
    classifier_prob: float,
    drift_flagged: bool,
    drift_score: float,
    is_tool_output: bool = False,
) -> str:
    if tier == "SAFE" or tier == "LOW":
        if not matched_rules:
            return "No injection signals detected. Message passed all layers cleanly."
        return (
            f"Low-confidence signal only (matched: {', '.join(matched_rules)}) — "
            f"not corroborated by embedding similarity or classifier score, "
            f"so this was logged but not acted on (over-defense guard)."
        )

    parts = []
    if matched_rules:
        rule_desc = ", ".join(matched_rules)
        span_desc = f" ('{matched_spans[0]}')" if matched_spans else ""
        if any(rule.startswith("content_harm_") for rule in matched_rules):
            parts.append(f"harmful-content request matched: {rule_desc}{span_desc}")
        else:
            parts.append(f"matched pattern: {rule_desc}{span_desc}")

    if attack_similarity and nearest_attack_cluster:
        parts.append(f"semantic similarity {attack_similarity:.2f} to known cluster '{nearest_attack_cluster}'")
    elif attack_similarity:
        parts.append(f"semantic similarity {attack_similarity:.2f} to known attack corpus")

    if classifier_prob:
        parts.append(f"classifier confidence {classifier_prob * 100:.0f}%")

    if drift_flagged:
        parts.append(f"session intent drift {drift_score:.2f} exceeds threshold across recent turns")

    if is_tool_output:
        parts.append("flagged in tool/retrieved output — indirect injection")

    verb = {"block": "Blocked", "sanitize": "Sanitized", "pass": "Passed"}[action]
    reason = " + ".join(parts) if parts else "combined signal score exceeded threshold"
    return f"{verb} — {reason}."
