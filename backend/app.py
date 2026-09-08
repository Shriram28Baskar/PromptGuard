"""
FastAPI entry point for the Prompt Injection Detection Gateway.

Run with:  uvicorn app:app --reload --port 8000   (from backend/)
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config
from api import argus, chat, dashboard, detect, logs
from database.db import init_db

app = FastAPI(
    title="Prompt Injection Detection Gateway",
    description="Explainable, severity-aware gateway that inspects prompts "
                 "before they reach an LLM.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()


app.include_router(detect.router, tags=["detection"])
app.include_router(chat.router, tags=["aegis-chat"])
app.include_router(dashboard.router, tags=["dashboard"])
app.include_router(logs.router, tags=["logs"])
app.include_router(argus.router)  # PS15 — /argus/propose, /argus/demo/{scenario}


@app.get("/health")
def health():
    return {"status": "ok"}
