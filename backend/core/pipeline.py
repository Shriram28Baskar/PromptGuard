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
    # Windowing metadata (populated only for tool_output inputs)
    window_count: int = 1
    max_risk_window: Optional[str] = None


def detect(prompt: str, session_id: Optional[str] = None, source: str = "user_message") -> DetectionResult:
    """Runs a single prompt through the full detection pipeline.

    source: "user_message" for direct user input, or "tool_output" for
    content returned from a tool call / RAG retrieval (Layer F — indirect
    injection inspection uses the same layers A–E but with stricter
    thresholds via TOOL_OUTPUT_EMBED_DELTA, and Layers B+C score the
    max-risk window rather than the whole document to prevent dilution).

    CALL ORDER CONTRACT
    -------------------
    preprocess() → rule_engine (full text) → [windowing for tool_output]
    → classifier (full text) → severity → explain → sanitize

    preprocess() must run BEFORE split_windows() so that:
      - [DECODED_B64: ...] markers are injected before windowing.
      - Windowed texts are already NFKC-normalized and zero-width-stripped.
    This order is enforced by the structure of this function.
    """
    is_tool_output = source == "tool_output"

    # ----------------------------------------------------------------
    # 1. Preprocessing — MUST run before windowing and rule matching.
    #    After this call, `processed` contains Base64 markers,
    #    NFKC-normalized text, and stripped zero-width characters.
    # ----------------------------------------------------------------
    processed = preprocess(prompt)

    # ----------------------------------------------------------------
    # 2a. Rule Detection (Layer A) — always on the FULL processed text.
    #     Windowing is NOT applied here: regex patterns rely on full
    #     phrase context and benefit from seeing complete sentences.
    # ----------------------------------------------------------------
    rule_result = rule_engine.match_rules(processed)

    # ----------------------------------------------------------------
    # 2b. Multi-turn drift (Layer D) — only for user_message sessions.
    #     tool_output is stateless (no drift tracking per retrieval).
    # ----------------------------------------------------------------
    drift_score, drift_flagged = 0.0, False
    if session_id and not is_tool_output:
        drift_tracker = DriftTracker.instance()
        drift_result = drift_tracker.update(session_id, processed)
        drift_score, drift_flagged = drift_result.drift_score, drift_result.flagged

    # ----------------------------------------------------------------
    # 2c. Semantic Similarity (Layer B) & Classifier (Layer C)
    #
    # MOTIVATION: Layer B (SBERT) and Layer C (Classifier) were calibrated
    # on short attack phrases (~10–40 tokens). A 300-word document embedding
    # dilutes a 10-word payload. For tool_output, we split the preprocessed
    # text into sentence- and token-level windows, score each window
    # through both Layer B and Layer C independently, and pass the
    # MAX-risk window's scores into severity (Layer E).
    #
    # For user_message (always short), the whole-document score is used
    # unchanged — windowing adds no value there.
    # ----------------------------------------------------------------
    semantic_engine = SemanticEngine.instance()
    classifier = Classifier.instance()
    window_count = 1
    max_risk_window: Optional[str] = None

    if is_tool_output:
        from utils.windowing import split_windows
        windows = split_windows(processed)   # receives already-preprocessed text
        window_count = len(windows)

        best_sem = None
        best_clf = None
        max_risk_metric = -1.0

        for w in windows:
            w_rule = rule_engine.match_rules(w)
            eff_rule_score = max(rule_result.score, w_rule.score)
            sem = semantic_engine.analyze(w)
            clf = classifier.predict(
                w, eff_rule_score, sem.context_anchored_score, drift_score
            )
            risk_metric = sem.context_anchored_score + clf.probability
            if risk_metric > max_risk_metric:
                max_risk_metric = risk_metric
                best_sem = sem
                best_clf = clf
                max_risk_window = w

        # Also score the full document so windowing never underperforms full-doc
        full_sem = semantic_engine.analyze(processed)
        full_clf = classifier.predict(
            processed, rule_result.score, full_sem.context_anchored_score, drift_score
        )

        if best_sem is not None and best_clf is not None:
            semantic_result = (
                best_sem if best_sem.context_anchored_score >= full_sem.context_anchored_score
                else full_sem
            )
            classifier_result = (
                best_clf if best_clf.probability >= full_clf.probability
                else full_clf
            )
        else:
            semantic_result = full_sem
            classifier_result = full_clf
            max_risk_window = processed
    else:
        semantic_result = semantic_engine.analyze(processed)
        classifier_result = classifier.predict(
            processed, rule_result.score, semantic_result.context_anchored_score, drift_score
        )

    # ----------------------------------------------------------------
    # 3. Severity score + agreement gate (Layer E)
    # ----------------------------------------------------------------
    severity_result = severity.evaluate(
        rule_score=rule_result.score,
        embed_score=semantic_result.context_anchored_score,
        classifier_prob=classifier_result.probability,
        drift_score=drift_score,
        is_tool_output=is_tool_output,
        matched_rules=rule_result.matched,
    )

    # ----------------------------------------------------------------
    # 4. Explanation
    # ----------------------------------------------------------------
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

    # ----------------------------------------------------------------
    # 5. Sanitize / Pass / Block
    # ----------------------------------------------------------------
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
        window_count=window_count,
        max_risk_window=max_risk_window,
    )
