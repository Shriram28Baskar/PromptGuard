"""
GET /logs — recent detection log entries, optionally filtered by tier
"""
from typing import Optional

from fastapi import APIRouter, Query

from database import db

router = APIRouter()


@router.get("/logs")
def get_logs(tier: Optional[str] = Query(default=None), limit: int = Query(default=200, le=1000)):
    return {"logs": db.fetch_logs(tier=tier, limit=limit)}


@router.delete("/logs")
def clear_logs():
    db.clear_logs()
    return {"status": "cleared"}
