"""
core/pipeline.py — the heart of the gateway.

Order of operations (matches the PRD architecture diagram):

  Prompt
    -> Preprocessing
    -> Rule Detection            (Layer A)
    -> Semantic Similarity       (Layer B, dual-corpus anchored — Layer E)
    -> ML Classifier             (Layer C)
    -> Conversation Drift        (Layer D, session-aware)
    -> Severity Score + Agreement Gate (Layer E)
    -> Explanation Generator
    -> Sanitize / Pass / Block
    -> Store Log
    -> Dashboard
"""
from dataclasses import dataclass, field
from typing import List, Optional

from core import explain, rule_engine, sanitize, severity
from core.classifier import Classifier
from core.drift import DriftTracker
from core.semantic_engine import SemanticEngine
from utils.helpers import new_id, now_ts
from utils.preprocess import preprocess


@dataclass
class DetectionResult:
    id: str
    timestamp: float
    original_prompt: str
    processed_prompt: str
    source: str  # "user_message" | "tool_output"
    tier: str
    score: float
    action: str
    explanation: str
    rule_score: float
    matched_rules: List[str]
    matched_spans: List[str]
    embedding_score: float
    nearest_attack: Optional[str]
    nearest_attack_cluster: Optional[str]
    benign_similarity: float
    classifier_prob: float
    classifier_features: dict
    drift_score: float
    drift_flagged: bool
    sanitized_output: Optional[str] = None
    session_id: Optional[str] = None


def detect(prompt: str, session_id: Optional[str] = None, source: str = "user_message") -> DetectionResult:
    """Runs a single prompt through the full detection pipeline.

    source: "user_message" for direct user input, or "tool_output" for
    content returned from a tool call / RAG retrieval (Layer F — indirect
    injection inspection uses the same layers with stricter thresholds).
    """
    is_tool_output = source == "tool_output"

    # 1. Preprocessing
    processed = preprocess(prompt)

    # 2a. Rule Detection (Layer A)
    rule_result = rule_engine.match_rules(processed)

    # 2b. Semantic Similarity (Layer B + dual-corpus anchoring)
    semantic_engine = SemanticEngine.instance()
    semantic_result = semantic_engine.analyze(processed)

    # 2c. Multi-turn drift (Layer D) — only tracked for user_message turns
    # tied to a session; tool_output is analyzed statelessly.
    drift_score, drift_flagged = 0.0, False
    if session_id and not is_tool_output:
        drift_tracker = DriftTracker.instance()
        drift_result = drift_tracker.update(session_id, processed)
        drift_score, drift_flagged = drift_result.drift_score, drift_result.flagged

    # 2d. ML Classifier (Layer C)
    classifier = Classifier.instance()
    classifier_result = classifier.predict(
        processed, rule_result.score, semantic_result.context_anchored_score, drift_score
    )

    # 3. Severity score + agreement gate (Layer E)
    severity_result = severity.evaluate(
        rule_score=rule_result.score,
        embed_score=semantic_result.context_anchored_score,
        classifier_prob=classifier_result.probability,
        drift_score=drift_score,
        is_tool_output=is_tool_output,
        matched_rules=rule_result.matched,
    )

    # 4. Explanation
    explanation = explain.build_explanation(
        tier=severity_result.tier,
        action=severity_result.action,
        matched_rules=rule_result.matched,
        matched_spans=rule_result.matched_spans,
        nearest_attack=semantic_result.nearest_attack,
        nearest_attack_cluster=semantic_result.nearest_attack_cluster,
        attack_similarity=semantic_result.context_anchored_score,
        classifier_prob=classifier_result.probability,
        drift_flagged=drift_flagged,
        drift_score=drift_score,
        is_tool_output=is_tool_output,
    )

    # 5. Sanitize / Pass / Block
    sanitized_output = None
    if severity_result.action == "sanitize":
        sanitized_output = sanitize.sanitize(processed, rule_result.matched_spans, technique="quarantine")

    return DetectionResult(
        id=new_id("det"),
        timestamp=now_ts(),
        original_prompt=prompt,
        processed_prompt=processed,
        source=source,
        tier=severity_result.tier,
        score=severity_result.score,
        action=severity_result.action,
        explanation=explanation,
        rule_score=rule_result.score,
        matched_rules=rule_result.matched,
        matched_spans=rule_result.matched_spans,
        embedding_score=semantic_result.context_anchored_score,
        nearest_attack=semantic_result.nearest_attack,
        nearest_attack_cluster=semantic_result.nearest_attack_cluster,
        benign_similarity=semantic_result.benign_similarity,
        classifier_prob=classifier_result.probability,
        classifier_features=classifier_result.features,
        drift_score=drift_score,
        drift_flagged=drift_flagged,
        sanitized_output=sanitized_output,
        session_id=session_id,
    )
