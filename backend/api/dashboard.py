"""
GET /statistics — aggregate counts for dashboard cards
GET /stress-test — runs the benign + trigger-word corpora live and
                    reports the false-positive / over-defense rate
                    (this is the "Benign Stress Test" button — PRD 5.5)
"""
import pandas as pd
from fastapi import APIRouter

import config
from core.pipeline import detect
from database import db

router = APIRouter()


@router.get("/statistics")
def get_statistics():
    return db.fetch_statistics()


@router.get("/stress-test")
def run_stress_test():
    general_benign = pd.read_csv(config.BENIGN_CORPUS_PATH)["text"].tolist()
    trigger_benign = pd.read_csv(config.TRIGGER_BENIGN_CORPUS_PATH)["text"].tolist()

    def _run(prompts, label):
        flagged = 0
        rows = []
        for p in prompts:
            result = detect(p, session_id=None, source="user_message")
            is_fp = result.action != "pass"
            flagged += int(is_fp)
            rows.append({
                "prompt": p,
                "tier": result.tier,
                "action": result.action,
                "false_positive": is_fp,
            })
        rate = round(flagged / len(prompts), 4) if prompts else 0.0
        return {"label": label, "total": len(prompts), "flagged": flagged, "false_positive_rate": rate, "rows": rows}

    general_result = _run(general_benign, "General benign set")
    trigger_result = _run(trigger_benign, "Benign trigger-word set (over-defense)")

    return {
        "general": general_result,
        "trigger_word": trigger_result,
        "summary": {
            "overall_false_positive_rate": round(
                (general_result["flagged"] + trigger_result["flagged"])
                / max(1, general_result["total"] + trigger_result["total"]),
                4,
            ),
            "over_defense_accuracy": round(
                1 - trigger_result["false_positive_rate"], 4
            ),
        },
    }
