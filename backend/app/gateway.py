"""LLM gateway — automatic capture & enforcement for first-party AI calls.

Three provider-compatible entry points so apps just repoint their client:

  POST /v1/chat/completions                      — OpenAI shape (OpenAI SDK, OpenAI-compatible tools)
  POST /v1/messages                              — Anthropic shape (Claude Code, Anthropic SDK)
  POST /v1beta/models/{model}:generateContent    — Gemini shape (google-genai SDK, Gemini CLI)

Each scans the prompt on the `llm_io` surface, records a finding, blocks at/above
`GATEWAY_BLOCK_SEVERITY` in enforce mode, and forwards allowed calls to the configured
upstream (or returns a stub when none is set). A per-tool policy (policy.py) suppresses
categories that are expected for a sanctioned tool — e.g. source code from Claude Code.

It also inspects **agentic tool-use** on the `mcp` surface: an AI coding agent's tool
calls, their arguments, and their results all round-trip the model, so they're visible in
this LLM traffic even when the tool is a *local* stdio MCP server — letting Warden catch
sensitive-file access, dangerous commands, tool poisoning, and secrets-in-results with no
endpoint agent. This runs on the **request** (the tool_use/tool_result already in history)
*and* on the **response** (the tool_use the model just requested) — so a dangerous action
can be blocked before the client executes it. (Response-side covers non-streaming
responses; SSE streaming inspection is a separate follow-up.)
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .detectors import AnalysisInput, Surface
from .models import ApiKey, User
from .policy import detect_tool, signal_filter_for
from .security import TokenError, decode_token, hash_token, looks_like_api_key
from .metering import record_and_check
from .service import run_analysis
from .upstreams import resolve as resolve_upstream

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
    `x-api-key` (Anthropic clients), `Authorization: Bearer` (OpenAI clients), or
    `x-goog-api-key` / `?key=` (Gemini clients)."""
    token = request.headers.get("x-api-key") or request.headers.get("x-goog-api-key") or ""
    if not token:
        scheme, _, rest = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "bearer":
            token = rest
    if not token:
        token = request.query_params.get("key") or ""
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


_RETRY_HEADER = {"Retry-After": "60"}


def _rate_limited(db: Session, principal: "Principal", shape: str) -> JSONResponse | None:
    """Count this request; return a provider-shaped 429 if the tenant is over its limit."""
    allowed, count, limit = record_and_check(db, principal.tenant_id)
    if allowed:
        return None
    msg = f"Warden rate limit exceeded ({limit}/min)."
    if shape == "anthropic":
        body = {"type": "error", "error": {"type": "rate_limit_error", "message": msg}}
    elif shape == "gemini":
        body = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": msg}}
    else:
        body = {"error": {"message": msg, "type": "rate_limited", "code": "rate_limited"}}
    return JSONResponse(status_code=429, content=body, headers=_RETRY_HEADER)


def _text_from_content(c) -> str:
    if isinstance(c, str):
        return c
    if isinstance(c, dict) and isinstance(c.get("parts"), list):   # ChatGPT web shape
        return "\n".join(p for p in c["parts"] if isinstance(p, str))
    if isinstance(c, list):                                         # Anthropic block list
        return "\n".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _scan_messages(messages: list, system=None) -> str:
    """Scan only the *current* outbound user turn — the last user-role message's text.

    Agents (e.g. Claude Code) resend the whole conversation history and large system
    prompts / tool results on every request. Scanning all of that means one secret
    anywhere in the history poisons every later turn (cascading false positives), and
    re-flags the same content repeatedly. We only inspect what the user is sending now:
    the text of the latest user message (text blocks only — tool-result/file-context
    blocks are excluded)."""
    for m in reversed(messages or []):
        if not isinstance(m, dict):
            continue
        role = (m.get("author") or {}).get("role") if isinstance(m.get("author"), dict) else m.get("role")
        if role == "user":
            return _text_from_content(m.get("content")).strip()
    return ""


def _capture(prompt: str, model: str, tool: str, principal: Principal, db: Session) -> dict:
    item = AnalysisInput(content=prompt or "(empty)", subject=model, sender=principal.actor,
                         channel=tool, surface=Surface.LLM_IO)
    return run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                        signal_filter=signal_filter_for(tool))


# --- Agentic tool-use inspection (agentless MCP over the LLM API) ----------------------
# An AI coding agent's tool calls, their arguments, and their results all round-trip the
# model — so they're visible right here in the LLM API traffic, even when the tool is a
# *local* stdio MCP server. We inspect the current turn's tool activity on the `mcp`
# surface (sensitive-file access, dangerous commands, tool poisoning, secrets in results)
# with no endpoint agent. Only the latest tool_use/tool_result pair is scanned, so each
# action is inspected exactly once (cascade-safe, like _scan_messages).

_MCP_DROP = {"source_code_leak", "unsanctioned_ai"}  # code is normal for an agent; no ext destination


def _mcp_sig_filter(signals: list) -> list:
    return [s for s in signals if s.category.value not in _MCP_DROP]


def _harvest_strings(obj, out: list) -> None:
    if isinstance(obj, str):
        if len(obj) >= 2:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _harvest_strings(v, out)


def _agentic_activity(payload: dict) -> dict | None:
    """Extract the current-turn agentic tool activity from an OpenAI/Anthropic request:
    advertised tool descriptions, the latest tool_use (name + args), and its tool_result
    output. Returns a normalized mcp-activity dict, or None if there's no tool activity."""
    descs: list[str] = []
    for t in payload.get("tools") or []:
        if not isinstance(t, dict):
            continue
        if isinstance(t.get("description"), str):                     # Anthropic tool
            descs.append(t["description"])
        fn = t.get("function")                                        # OpenAI tool
        if isinstance(fn, dict) and isinstance(fn.get("description"), str):
            descs.append(fn["description"])

    messages = payload.get("messages") or []
    tool_name, args_parts, result_parts = "", [], []

    # Latest assistant tool_use — Anthropic content blocks or OpenAI tool_calls.
    for m in reversed(messages):
        if not isinstance(m, dict) or m.get("role") != "assistant":
            continue
        content = m.get("content")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    tool_name = tool_name or b.get("name", "")
                    _harvest_strings(b.get("input", {}), args_parts)
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") if isinstance(tc, dict) else None
            if isinstance(fn, dict):
                tool_name = tool_name or fn.get("name", "")
                if isinstance(fn.get("arguments"), str):
                    args_parts.append(fn["arguments"])
        if tool_name or args_parts:
            break

    # Latest tool_result — Anthropic user tool_result blocks or OpenAI role=tool message.
    for m in reversed(messages):
        if not isinstance(m, dict):
            continue
        if m.get("role") == "tool":                                   # OpenAI
            if isinstance(m.get("content"), str):
                result_parts.append(m["content"])
            break
        content = m.get("content")
        if isinstance(content, list):
            trs = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]
            if trs:
                for b in trs:
                    rc = b.get("content")
                    if isinstance(rc, str):
                        result_parts.append(rc)
                    elif isinstance(rc, list):
                        result_parts.extend(x.get("text", "") for x in rc if isinstance(x, dict))
                break

    if not (descs or tool_name or args_parts or result_parts):
        return None
    method = "tools/call" if (tool_name or args_parts) else (
        "tools/advertised" if descs else "tool_result")
    return {"method": method, "tool": tool_name,
            "args_text": "\n".join(args_parts)[:20000],
            "result_text": "\n".join(p for p in result_parts if p)[:20000],
            "tool_descriptions": descs}


def _capture_agentic(payload: dict, tool: str, principal: Principal, db: Session) -> dict | None:
    act = _agentic_activity(payload)
    if not act:
        return None
    content = "\n".join(p for p in [act["args_text"], act["result_text"],
                                    "\n".join(act["tool_descriptions"])] if p)
    if not content:
        return None
    item = AnalysisInput(
        content=content, subject=f"agent {act['method']}".strip(), sender=principal.actor,
        channel=tool or "agent", surface=Surface.MCP,
        metadata={"method": act["method"], "tool": act["tool"],
                  "args_text": act["args_text"], "tool_descriptions": act["tool_descriptions"]},
    )
    return run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                        signal_filter=_mcp_sig_filter)


def _response_activity(resp: dict) -> dict | None:
    """Extract the tool_use the model just requested from an upstream response — Anthropic
    `content[].tool_use` or OpenAI `choices[].message.tool_calls`. Inspecting this lets the
    gateway block a dangerous action *before* the client executes it (non-streaming path)."""
    if not isinstance(resp, dict):
        return None
    tool_name, args = "", []
    for b in resp.get("content") or []:                       # Anthropic
        if isinstance(b, dict) and b.get("type") == "tool_use":
            tool_name = tool_name or b.get("name", "")
            _harvest_strings(b.get("input", {}), args)
    for ch in resp.get("choices") or []:                      # OpenAI
        msg = ch.get("message") if isinstance(ch, dict) else None
        for tc in (msg or {}).get("tool_calls") or []:
            fn = tc.get("function") if isinstance(tc, dict) else None
            if isinstance(fn, dict):
                tool_name = tool_name or fn.get("name", "")
                if isinstance(fn.get("arguments"), str):
                    args.append(fn["arguments"])
    if not args:
        return None
    return {"method": "tools/call", "tool": tool_name, "args_text": "\n".join(args)[:20000]}


def _capture_response_agentic(resp: dict, tool: str, principal: Principal, db: Session) -> dict | None:
    act = _response_activity(resp)
    if not act:
        return None
    item = AnalysisInput(
        content=act["args_text"], subject=f"agent {act['tool']}".strip(), sender=principal.actor,
        channel=tool or "agent", surface=Surface.MCP,
        metadata={"method": act["method"], "tool": act["tool"], "args_text": act["args_text"]})
    return run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                        signal_filter=_mcp_sig_filter)


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
    limited = _rate_limited(db, principal, "openai")
    if limited:
        return limited
    payload = await request.json()
    model = payload.get("model", "unknown")
    tool = detect_tool(request.headers.get("user-agent", ""), request.headers.get("x-warden-tool", ""))
    verdict = _capture(_scan_messages(payload.get("messages", [])), model, tool, principal, db)

    if settings.gateway_enforce and _blocked(verdict):
        return _openai_error(verdict)
    # Agentic tool-use inspection (agentless MCP over the LLM API).
    agentic = _capture_agentic(payload, tool, principal, db)
    if settings.gateway_enforce and agentic and _blocked(agentic):
        return _openai_error(agentic)
    base, key = resolve_upstream("openai", principal.tenant_id, db)
    if base:
        url = base.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        with httpx.Client(timeout=60) as c:
            r = c.post(url, json=payload, headers=headers)
        data = r.json()
        if settings.gateway_enforce:
            ragentic = _capture_response_agentic(data, tool, principal, db)
            if ragentic and _blocked(ragentic):
                return _openai_error(ragentic)
        return JSONResponse(status_code=r.status_code, content=data)
    return JSONResponse(content=_openai_stub(model, verdict))


# --- Anthropic shape (Claude Code, Anthropic SDK) -------------------------------------

def _anthropic_error(verdict: dict) -> JSONResponse:
    sigs = ", ".join(s["category"] for s in verdict.get("signals", [])[:4]) or "policy violation"
    # Use 400/invalid_request_error, not 403/permission_error: clients (e.g. Claude Code)
    # treat 403 as an auth failure and prompt re-login, hiding our reason. A 400 surfaces
    # the message directly. 403 stays reserved for genuine auth problems (bad/missing key).
    return JSONResponse(status_code=400, content={"type": "error", "error": {
        "type": "invalid_request_error",
        "message": (f"Blocked by Warden: {sigs} (risk {verdict['risk_score']}/{verdict['severity']}). "
                    f"Remove the secret/PII — run /clear to reset the conversation."),
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
    limited = _rate_limited(db, principal, "anthropic")
    if limited:
        return limited
    payload = await request.json()
    model = payload.get("model", "unknown")
    tool = detect_tool(request.headers.get("user-agent", ""), request.headers.get("x-warden-tool", ""))
    prompt = _scan_messages(payload.get("messages", []), payload.get("system"))
    verdict = _capture(prompt, model, tool, principal, db)

    if settings.gateway_enforce and _blocked(verdict):
        return _anthropic_error(verdict)
    # Agentic tool-use inspection (agentless MCP over the LLM API).
    agentic = _capture_agentic(payload, tool, principal, db)
    if settings.gateway_enforce and agentic and _blocked(agentic):
        return _anthropic_error(agentic)

    base, key = resolve_upstream("anthropic", principal.tenant_id, db)
    if key:
        status, data = _post_upstream_anthropic("/v1/messages", payload, request, base, key)
        # Response-side: block a dangerous tool_use the model just requested, before the
        # client executes it (non-streaming responses).
        if settings.gateway_enforce:
            ragentic = _capture_response_agentic(data, tool, principal, db)
            if ragentic and _blocked(ragentic):
                return _anthropic_error(ragentic)
        return JSONResponse(status_code=status, content=data)
    return JSONResponse(content=_anthropic_stub(model, verdict))


def _anthropic_headers(request: Request, key: str) -> dict:
    """Headers for forwarding to Anthropic — preserve version AND beta (Claude Code
    relies on both; dropping anthropic-beta breaks beta features)."""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": key,
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
    }
    beta = request.headers.get("anthropic-beta")
    if beta:
        headers["anthropic-beta"] = beta
    return headers


def _post_upstream_anthropic(path: str, payload: dict, request: Request,
                             base: str, key: str) -> tuple[int, dict]:
    url = base.rstrip("/") + path
    with httpx.Client(timeout=120) as c:
        r = c.post(url, json=payload, headers=_anthropic_headers(request, key))
    return r.status_code, r.json()


def _forward_anthropic(path: str, payload: dict, request: Request, base: str, key: str) -> JSONResponse:
    status, data = _post_upstream_anthropic(path, payload, request, base, key)
    return JSONResponse(status_code=status, content=data)


@router.post("/messages/count_tokens")
async def count_tokens(request: Request, principal: Principal = Depends(get_gateway_principal),
                       db: Session = Depends(get_db)):
    """Token-counting pre-flight Claude Code issues before a turn. Authenticated
    passthrough to Anthropic (or a stub offline); no finding — the paired /v1/messages
    call is where capture and enforcement happen."""
    payload = await request.json()
    base, key = resolve_upstream("anthropic", principal.tenant_id, db)
    if key:
        return _forward_anthropic("/v1/messages/count_tokens", payload, request, base, key)
    return JSONResponse(content={"input_tokens": 0})


# --- Gemini shape (google-genai SDK, Gemini CLI) --------------------------------------
#
# Gemini diverges from OpenAI/Anthropic: the model and action live in the path
# (`/v1beta/models/{model}:generateContent`), the prompt is under `contents[].parts[].text`
# with an optional `systemInstruction`, and the error envelope is Google's `{error:{code,
# message,status}}`. Its own router because the path prefix is `/v1beta`, not `/v1`.

gemini_router = APIRouter(prefix="/v1beta", tags=["gateway"])


def _scan_gemini(contents: list, system_instruction=None) -> str:
    """Pull user-authored text from a Gemini request (contents[].parts[].text)."""
    def _parts_text(node) -> str:
        parts = node.get("parts") if isinstance(node, dict) else None
        if not isinstance(parts, list):
            return ""
        return "\n".join(p.get("text", "") for p in parts
                         if isinstance(p, dict) and isinstance(p.get("text"), str))

    chunks = []
    if system_instruction:
        chunks.append(_parts_text(system_instruction))
    for c in contents or []:
        if not isinstance(c, dict):
            continue
        if c.get("role") in (None, "user", "system"):   # skip prior "model" turns
            chunks.append(_parts_text(c))
    return "\n".join(p for p in chunks if p).strip()


def _gemini_error(verdict: dict) -> JSONResponse:
    sigs = ", ".join(s["category"] for s in verdict.get("signals", [])[:4]) or "policy violation"
    return JSONResponse(status_code=403, content={"error": {
        "code": 403, "status": "PERMISSION_DENIED",
        "message": f"Blocked by Warden: {sigs} (risk {verdict['risk_score']}/{verdict['severity']}).",
    }})


def _gemini_stub(model: str, verdict: dict) -> dict:
    return {
        "candidates": [{"content": {"role": "model", "parts": [
            {"text": "[Warden gateway: no upstream configured — prompt passed inspection.]"}]},
            "finishReason": "STOP", "index": 0}],
        "usageMetadata": {"promptTokenCount": 0, "candidatesTokenCount": 0, "totalTokenCount": 0},
        "modelVersion": model,
        "warden": {"risk_score": verdict["risk_score"], "severity": verdict["severity"]},
    }


def _forward_gemini(model: str, method: str, payload: dict, request: Request,
                    base: str, key: str) -> Response:
    """Passthrough to Gemini, preserving query params (e.g. ?alt=sse) but swapping in our
    upstream key. Returns the upstream bytes verbatim so both JSON and streaming work."""
    url = f"{base.rstrip('/')}/v1beta/models/{model}:{method}"
    params = {k: v for k, v in request.query_params.items() if k != "key"}
    headers = {"Content-Type": "application/json", "x-goog-api-key": key}
    with httpx.Client(timeout=120) as c:
        r = c.post(url, json=payload, params=params, headers=headers)
    return Response(content=r.content, status_code=r.status_code,
                    media_type=r.headers.get("content-type", "application/json"))


async def _gemini_entry(model: str, method: str, request: Request,
                        principal: Principal, db: Session) -> Response:
    limited = _rate_limited(db, principal, "gemini")
    if limited:
        return limited
    payload = await request.json()
    tool = detect_tool(request.headers.get("user-agent", ""), request.headers.get("x-warden-tool", ""))
    prompt = _scan_gemini(payload.get("contents", []), payload.get("systemInstruction") or payload.get("system_instruction"))
    verdict = _capture(prompt, model, tool, principal, db)

    if settings.gateway_enforce and _blocked(verdict):
        return _gemini_error(verdict)
    base, key = resolve_upstream("gemini", principal.tenant_id, db)
    if key:
        return _forward_gemini(model, method, payload, request, base, key)
    return JSONResponse(content=_gemini_stub(model, verdict))


@gemini_router.post("/models/{model}:generateContent")
async def gemini_generate(model: str, request: Request,
                          principal: Principal = Depends(get_gateway_principal),
                          db: Session = Depends(get_db)):
    return await _gemini_entry(model, "generateContent", request, principal, db)


@gemini_router.post("/models/{model}:streamGenerateContent")
async def gemini_stream_generate(model: str, request: Request,
                                 principal: Principal = Depends(get_gateway_principal),
                                 db: Session = Depends(get_db)):
    return await _gemini_entry(model, "streamGenerateContent", request, principal, db)
