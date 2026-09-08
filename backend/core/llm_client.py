"""
Downstream LLM client used by the Aegis chat surface.

The gateway decision happens before this module is called. This client is
deliberately small and stdlib-only so the demo does not need another SDK
install: set GROQ_API_KEY and optionally GROQ_MODEL / GROQ_BASE_URL.
"""
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List

import config


class LLMConfigurationError(RuntimeError):
    pass


class LLMProviderError(RuntimeError):
    pass


@dataclass
class LLMMessage:
    role: str
    content: str


@dataclass
class LLMResult:
    provider: str
    model: str
    text: str


def _extract_text(payload: dict) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return str(message.get("content") or "").strip()


def call_groq(messages: List[LLMMessage]) -> LLMResult:
    if not config.GROQ_API_KEY:
        raise LLMConfigurationError("GROQ_API_KEY is not configured.")

    url = config.GROQ_BASE_URL.rstrip("/") + "/chat/completions"
    body = {
        "model": config.GROQ_MODEL,
        "messages": [{"role": message.role, "content": message.content} for message in messages],
        "temperature": 0.4,
        "max_completion_tokens": 700,
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {config.GROQ_API_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Aegis-Gateway/0.1",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMProviderError(f"Groq request failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMProviderError(f"Groq request failed: {exc.reason}") from exc

    text = _extract_text(payload)
    if not text:
        raise LLMProviderError("Groq response did not contain output text.")

    return LLMResult(provider="groq", model=config.GROQ_MODEL, text=text)
