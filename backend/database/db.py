"""
SQLite storage for detection logs. One table is enough for the MVP
(PRD Section 7 — no need for a production DB for the hackathon).

PS15 extension: five new columns for the ARGUS decision trace are added via
backward-compatible ALTER TABLE in init_db().  Existing rows and existing
callers are unaffected — the new columns default to NULL / "N/A" / 0.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from typing import List, Optional

import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    session_id TEXT,
    source TEXT NOT NULL,
    prompt TEXT NOT NULL,
    sanitized_output TEXT,
    tier TEXT NOT NULL,
    score REAL NOT NULL,
    action TEXT NOT NULL,
    explanation TEXT NOT NULL,
    rule_score REAL,
    matched_rules TEXT,
    embedding_score REAL,
    nearest_attack_cluster TEXT,
    classifier_prob REAL,
    drift_score REAL,
    drift_flagged INTEGER
);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_tier ON logs(tier);
"""

# PS15 — new audit columns added via backward-compatible ALTER TABLE.
# SQLite does not support IF NOT EXISTS for ALTER TABLE, so we attempt each
# column individually and ignore the OperationalError if it already exists.
_ARGUS_COLUMNS = [
    ("proposed_action",  "TEXT"),     # JSON of ProposedAction (or NULL)
    ("policy_verdict",   "TEXT"),     # "ALLOW" | "DENY" | "N/A"
    ("policy_reason",    "TEXT"),     # human-readable reason string
    ("execution_result", "TEXT"),     # "EXECUTED" | "NOT_EXECUTED" | "N/A"
    ("argus_reached",    "INTEGER"),  # 1 if ARGUS simulator was called, else 0
]


def init_db():
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript(_SCHEMA)
        # Migrate: add PS15 columns to any pre-existing database.
        for col_name, col_type in _ARGUS_COLUMNS:
            try:
                conn.execute(f"ALTER TABLE logs ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass  # Column already exists — safe to ignore.


@contextmanager
def get_conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert_log(result) -> None:
    """result: core.pipeline.DetectionResult

    Inserts a detection-only log row.  PS15 ARGUS columns default to NULL / 0
    so existing callers (detect.py, chat.py) require no changes.
    """
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO logs (
                id, timestamp, session_id, source, prompt, sanitized_output,
                tier, score, action, explanation, rule_score, matched_rules,
                embedding_score, nearest_attack_cluster, classifier_prob,
                drift_score, drift_flagged,
                proposed_action, policy_verdict, policy_reason,
                execution_result, argus_reached
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result.id,
                result.timestamp,
                result.session_id,
                result.source,
                result.original_prompt,
                result.sanitized_output,
                result.tier,
                result.score,
                result.action,
                result.explanation,
                result.rule_score,
                json.dumps(result.matched_rules),
                result.embedding_score,
                result.nearest_attack_cluster,
                result.classifier_prob,
                result.drift_score,
                int(result.drift_flagged),
                # PS15 columns — NULL for detection-only rows
                None,   # proposed_action
                "N/A",  # policy_verdict
                "N/A",  # policy_reason
                "N/A",  # execution_result
                0,      # argus_reached
            ),
        )


def insert_argus_log(
    result,
    proposed_action_json: str,
    policy_verdict: str,
    policy_reason: str,
    execution_result: str,
    argus_reached: bool,
) -> None:
    """Insert a full PS15 audit row (detection + ARGUS decision trace).

    Called only by api/argus.py after the full security + policy evaluation.
    Uses INSERT OR REPLACE so that if the detection row was already written by
    a prior insert_log() call with the same ID, it is replaced with the full
    ARGUS trace.  In practice argus.py does NOT call insert_log() separately —
    it calls insert_argus_log() once, carrying all columns.
    """
    with get_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO logs (
                id, timestamp, session_id, source, prompt, sanitized_output,
                tier, score, action, explanation, rule_score, matched_rules,
                embedding_score, nearest_attack_cluster, classifier_prob,
                drift_score, drift_flagged,
                proposed_action, policy_verdict, policy_reason,
                execution_result, argus_reached
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result.id,
                result.timestamp,
                result.session_id,
                result.source,
                result.original_prompt,
                result.sanitized_output,
                result.tier,
                result.score,
                result.action,
                result.explanation,
                result.rule_score,
                json.dumps(result.matched_rules),
                result.embedding_score,
                result.nearest_attack_cluster,
                result.classifier_prob,
                result.drift_score,
                int(result.drift_flagged),
                proposed_action_json,
                policy_verdict,
                policy_reason,
                execution_result,
                int(argus_reached),
            ),
        )


def fetch_logs(tier: Optional[str] = None, limit: int = 200) -> List[dict]:
    query = "SELECT * FROM logs"
    params = []
    if tier:
        query += " WHERE tier = ?"
        params.append(tier.upper())
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def fetch_statistics() -> dict:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
        by_tier = conn.execute(
            "SELECT tier, COUNT(*) c FROM logs GROUP BY tier"
        ).fetchall()
        by_action = conn.execute(
            "SELECT action, COUNT(*) c FROM logs GROUP BY action"
        ).fetchall()
        avg_score = conn.execute("SELECT AVG(score) a FROM logs").fetchone()["a"] or 0.0

    return {
        "total_requests": total,
        "by_tier": {r["tier"]: r["c"] for r in by_tier},
        "by_action": {r["action"]: r["c"] for r in by_action},
        "average_risk_score": round(avg_score, 4),
    }


def clear_logs():
    with get_conn() as conn:
        conn.execute("DELETE FROM logs")
