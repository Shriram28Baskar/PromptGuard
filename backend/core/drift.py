"""
Layer D — Multi-turn / session-level drift detector.

Scoped down deliberately for hackathon time (see PRD 5.2): track the last
N=5 turns of a session, compute a rolling "session intent vector" as the
mean embedding of those turns, and measure cosine distance between the
current session-intent vector and the session-intent vector at turn 0.
A session can be flagged even when no single message looks malicious,
because the cumulative intent has drifted from the original request.
"""
from dataclasses import dataclass, field
from typing import Dict, List

import numpy as np

import config
from models.embedding import Embedder, cosine_similarity


@dataclass
class SessionState:
    turn_vectors: List[np.ndarray] = field(default_factory=list)
    initial_vector: np.ndarray = None


@dataclass
class DriftResult:
    drift_score: float
    flagged: bool
    turns_considered: int


class DriftTracker:
    """In-memory session store. Swappable for Redis in a real deployment;
    fine for a single-process hackathon demo."""

    _instance = None

    def __init__(self):
        self.embedder = Embedder.instance()
        self.sessions: Dict[str, SessionState] = {}

    @classmethod
    def instance(cls) -> "DriftTracker":
        if cls._instance is None:
            cls._instance = DriftTracker()
        return cls._instance

    def _get_session(self, session_id: str) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState()
        return self.sessions[session_id]

    def update(self, session_id: str, text: str) -> DriftResult:
        state = self._get_session(session_id)
        vec = self.embedder.encode(text)

        if state.initial_vector is None:
            state.initial_vector = vec

        state.turn_vectors.append(vec)
        window = state.turn_vectors[-config.DRIFT_WINDOW:]

        session_intent_vector = np.mean(window, axis=0)
        similarity = cosine_similarity(session_intent_vector, state.initial_vector)
        drift = 1.0 - similarity  # cosine distance

        flagged = drift >= config.DRIFT_ALERT_THRESHOLD and len(state.turn_vectors) > 1

        return DriftResult(
            drift_score=round(float(max(0.0, drift)), 4),
            flagged=flagged,
            turns_considered=len(window),
        )

    def reset(self, session_id: str):
        self.sessions.pop(session_id, None)
