"""
POST /detect   — inspect a single message (user_message or tool_output)
POST /simulate — run a scripted multi-turn session through the pipeline
"""
from typing import List, Literal, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from core.pipeline import DetectionResult, detect
from database import db

router = APIRouter()


class DetectRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None
    source: Literal["user_message", "tool_output"] = "user_message"


class DetectResponse(BaseModel):
    id: str
    timestamp: float
    tier: str
    score: float
    action: str
    explanation: str
    sanitized_output: Optional[str] = None
    details: dict


def _to_response(result: DetectionResult) -> DetectResponse:
    return DetectResponse(
        id=result.id,
        timestamp=result.timestamp,
        tier=result.tier,
        score=result.score,
        action=result.action,
        explanation=result.explanation,
        sanitized_output=result.sanitized_output,
        details={
            "source": result.source,
            "rule_score": result.rule_score,
            "matched_rules": result.matched_rules,
            "matched_spans": result.matched_spans,
            "embedding_score": result.embedding_score,
            "nearest_attack": result.nearest_attack,
            "nearest_attack_cluster": result.nearest_attack_cluster,
            "benign_similarity": result.benign_similarity,
            "classifier_prob": result.classifier_prob,
            "classifier_features": result.classifier_features,
            "drift_score": result.drift_score,
            "drift_flagged": result.drift_flagged,
            "session_id": result.session_id,
        },
    )


@router.post("/detect", response_model=DetectResponse)
def detect_prompt(payload: DetectRequest):
    result = detect(payload.prompt, session_id=payload.session_id, source=payload.source)
    db.insert_log(result)
    return _to_response(result)


class SimulateRequest(BaseModel):
    session_id: str = Field(default="sim-session")
    turns: List[str]


class SimulateResponse(BaseModel):
    session_id: str
    results: List[DetectResponse]


@router.post("/simulate", response_model=SimulateResponse)
def simulate_session(payload: SimulateRequest):
    """Runs a scripted multi-turn conversation through the pipeline in
    order, so drift (Layer D) accumulates turn over turn — this powers
    the "multi-turn demo" in the pitch script."""
    responses = []
    for turn in payload.turns:
        result = detect(turn, session_id=payload.session_id, source="user_message")
        db.insert_log(result)
        responses.append(_to_response(result))

    return SimulateResponse(session_id=payload.session_id, results=responses)
