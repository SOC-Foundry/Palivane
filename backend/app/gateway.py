"""LLM gateway — automatic capture & enforcement for first-party AI calls.

Two OpenAI/Anthropic-compatible entry points so apps just repoint their client:

  POST /v1/chat/completions   — OpenAI shape (OpenAI SDK, OpenAI-compatible tools)
  POST /v1/messages           — Anthropic shape (Claude Code, Anthropic SDK)

Each scans the prompt on the `llm_io` surface, records a finding, blocks at/above
`GATEWAY_BLOCK_SEVERITY` in enforce mode, and forwards allowed calls to the configured
upstream (or returns a stub when none is set). A per-tool policy (policy.py) suppresses
categories that are expected for a sanctioned tool — e.g. source code from Claude Code.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .detectors import AnalysisInput, Surface
from .models import ApiKey, User
from .policy import detect_tool, signal_filter_for
from .security import TokenError, decode_token, hash_token, looks_like_api_key
from .service import run_analysis

router = APIRouter(prefix="/v1", tags=["gateway"])

_SEVERITY_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}


@dataclass
class Principal:
    tenant_id: int
    actor: str  # who/what to attribute findings to (user email or API-key label)


def _resolve_api_key(token: str, db: Session) -> Principal:
    key = (
        db.query(ApiKey)
        .filter(ApiKey.prefix == token[:11], ApiKey.active.is_(True))
        .first()
    )
    if key is None or not hmac.compare_digest(key.token_hash, hash_token(token)):
        raise HTTPException(status_code=401, detail="invalid API key")
    if key.expires_at and key.expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
        raise HTTPException(status_code=401, detail="API key expired")
    try:  # best-effort last-used stamp
        key.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
    except Exception:
        db.rollback()
    return Principal(tenant_id=key.tenant_id, actor=key.actor or key.label or "api-key")


def get_gateway_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    """Authenticate a gateway call by a long-lived API key (`ak_…`) or a user JWT, from
    `x-api-key` (Anthropic clients) or `Authorization: Bearer` (OpenAI clients)."""
    token = request.headers.get("x-api-key") or ""
    if not token:
        scheme, _, rest = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "bearer":
            token = rest
    if not token:
        raise HTTPException(status_code=401, detail="missing API key",
                            headers={"WWW-Authenticate": "Bearer"})
    if looks_like_api_key(token):
        return _resolve_api_key(token, db)
    try:
        payload = decode_token(token)
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    user = db.get(User, int(payload.get("sub", 0)))
    if user is None or not user.active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    return Principal(tenant_id=user.tenant_id, actor=user.email)


def _blocked(verdict: dict) -> int:
    return _SEVERITY_RANK.get(verdict["severity"], 0) >= _SEVERITY_RANK.get(settings.gateway_block_severity, 3)


def _text_from_content(c) -> str:
    if isinstance(c, str):
        return c
    if isinstance(c, dict) and isinstance(c.get("parts"), list):   # ChatGPT web shape
        return "\n".join(p for p in c["parts"] if isinstance(p, str))
    if isinstance(c, list):                                         # Anthropic block list
        return "\n".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _scan_messages(messages: list, system=None) -> str:
    parts = []
    if system:
        parts.append(_text_from_content(system))
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role = (m.get("author") or {}).get("role") if isinstance(m.get("author"), dict) else m.get("role")
        if role in (None, "user", "system"):
            parts.append(_text_from_content(m.get("content")))
    return "\n".join(p for p in parts if p).strip()


def _capture(prompt: str, model: str, tool: str, principal: Principal, db: Session) -> dict:
    item = AnalysisInput(content=prompt or "(empty)", subject=model, sender=principal.actor,
                         channel=tool, surface=Surface.LLM_IO)
    return run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                        signal_filter=signal_filter_for(tool))


# --- OpenAI shape ---------------------------------------------------------------------

def _openai_error(verdict: dict) -> JSONResponse:
    top = verdict["signals"][0]["title"] if verdict.get("signals") else "policy violation"
    return JSONResponse(status_code=403, content={"error": {
        "message": f"Blocked by Warden: {top} (risk {verdict['risk_score']}/{verdict['severity']}).",
        "type": "warden_blocked", "code": "prompt_blocked",
        "warden": {"risk_score": verdict["risk_score"], "severity": verdict["severity"],
                     "finding_id": verdict.get("finding_id")},
    }})


def _openai_stub(model: str, verdict: dict) -> dict:
    now = int(time.time())
    return {
        "id": f"warden-{now}", "object": "chat.completion", "created": now, "model": model,
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant",
                     "content": "[Warden gateway: no upstream configured — prompt passed inspection.]"}}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "warden": {"risk_score": verdict["risk_score"], "severity": verdict["severity"]},
    }


@router.post("/chat/completions")
async def chat_completions(request: Request, principal: Principal = Depends(get_gateway_principal),
                           db: Session = Depends(get_db)):
    payload = await request.json()
    model = payload.get("model", "unknown")
    tool = detect_tool(request.headers.get("user-agent", ""), request.headers.get("x-warden-tool", ""))
    verdict = _capture(_scan_messages(payload.get("messages", [])), model, tool, principal, db)

    if settings.gateway_enforce and _blocked(verdict):
        return _openai_error(verdict)
    if settings.gateway_upstream_base:
        url = settings.gateway_upstream_base.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if settings.gateway_upstream_key:
            headers["Authorization"] = f"Bearer {settings.gateway_upstream_key}"
        with httpx.Client(timeout=60) as c:
            r = c.post(url, json=payload, headers=headers)
        return JSONResponse(status_code=r.status_code, content=r.json())
    return JSONResponse(content=_openai_stub(model, verdict))


# --- Anthropic shape (Claude Code, Anthropic SDK) -------------------------------------

def _anthropic_error(verdict: dict) -> JSONResponse:
    sigs = ", ".join(s["category"] for s in verdict.get("signals", [])[:4]) or "policy violation"
    return JSONResponse(status_code=403, content={"type": "error", "error": {
        "type": "permission_error",
        "message": f"Blocked by Warden: {sigs} (risk {verdict['risk_score']}/{verdict['severity']}).",
    }})


def _anthropic_stub(model: str, verdict: dict) -> dict:
    return {
        "id": f"msg_warden_{int(time.time())}", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": "[Warden gateway: no upstream configured — prompt passed inspection.]"}],
        "stop_reason": "end_turn", "usage": {"input_tokens": 0, "output_tokens": 0},
        "warden": {"risk_score": verdict["risk_score"], "severity": verdict["severity"]},
    }


@router.post("/messages")
async def messages(request: Request, principal: Principal = Depends(get_gateway_principal),
                   db: Session = Depends(get_db)):
    payload = await request.json()
    model = payload.get("model", "unknown")
    tool = detect_tool(request.headers.get("user-agent", ""), request.headers.get("x-warden-tool", ""))
    prompt = _scan_messages(payload.get("messages", []), payload.get("system"))
    verdict = _capture(prompt, model, tool, principal, db)

    if settings.gateway_enforce and _blocked(verdict):
        return _anthropic_error(verdict)

    if _anthropic_key():
        return _forward_anthropic("/v1/messages", payload, request)
    return JSONResponse(content=_anthropic_stub(model, verdict))


def _anthropic_key() -> str:
    return settings.gateway_anthropic_key or settings.anthropic_api_key


def _anthropic_headers(request: Request) -> dict:
    """Headers for forwarding to Anthropic — preserve version AND beta (Claude Code
    relies on both; dropping anthropic-beta breaks beta features)."""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": _anthropic_key(),
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
    }
    beta = request.headers.get("anthropic-beta")
    if beta:
        headers["anthropic-beta"] = beta
    return headers


def _forward_anthropic(path: str, payload: dict, request: Request) -> JSONResponse:
    url = settings.gateway_anthropic_base.rstrip("/") + path
    with httpx.Client(timeout=120) as c:
        r = c.post(url, json=payload, headers=_anthropic_headers(request))
    return JSONResponse(status_code=r.status_code, content=r.json())


@router.post("/messages/count_tokens")
async def count_tokens(request: Request, principal: Principal = Depends(get_gateway_principal)):
    """Token-counting pre-flight Claude Code issues before a turn. Authenticated
    passthrough to Anthropic (or a stub offline); no finding — the paired /v1/messages
    call is where capture and enforcement happen."""
    payload = await request.json()
    if _anthropic_key():
        return _forward_anthropic("/v1/messages/count_tokens", payload, request)
    return JSONResponse(content={"input_tokens": 0})
