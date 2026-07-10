"""LLM gateway — automatic capture & enforcement for first-party AI calls.

Three provider-compatible entry points so apps just repoint their client:

  POST /v1/chat/completions                      — OpenAI shape (OpenAI SDK, OpenAI-compatible tools)
  POST /v1/responses                             — OpenAI Responses API (Codex CLI, newer SDKs)
  POST /v1/messages                              — Anthropic shape (Claude Code, Anthropic SDK)
  POST /v1beta/models/{model}:generateContent    — Gemini shape (google-genai SDK, Gemini CLI)

Each scans the prompt on the `llm_io` surface, records a finding, blocks at/above
`GATEWAY_BLOCK_SEVERITY` in enforce mode, and forwards allowed calls to the configured
upstream (or returns a stub when none is set). A per-tool policy (policy.py) suppresses
categories that are expected for a sanctioned tool — e.g. source code from Claude Code.

**Response-side DLP** (`GATEWAY_SCAN_RESPONSES`, default on): the model's *output* is also
scanned for secrets/PII — a jailbroken/compromised model echoing credentials, RAG/tool
output surfacing data the user shouldn't see, or exfiltration via the completion. Recorded
in monitor mode; in enforce mode a leaking response is blocked instead of delivered.
Covers non-streaming replies, enforce-mode buffered streams, AND monitor-mode live streams
(a *tee* records the finding after the last token — no client-facing latency).

It also inspects **agentic tool-use** on the `mcp` surface: an AI coding agent's tool
calls, their arguments, and their results all round-trip the model, so they're visible in
this LLM traffic even when the tool is a *local* stdio MCP server — letting Warden catch
sensitive-file access, dangerous commands, tool poisoning, and secrets-in-results with no
endpoint agent. This runs on the **request** (the tool_use/tool_result already in history)
*and* on the **response** (the tool_use the model just requested) — so a dangerous action
can be blocked before the client executes it. **Streaming (SSE)** is handled too: monitor
mode streams through live (recorded request-side next turn), enforce mode buffers the turn,
inspects the assembled tool_use, and blocks or replays it verbatim.
"""

from __future__ import annotations

import hmac
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .detectors import AnalysisInput, Surface
from .models import Agent, ApiKey, Tenant, User
from .policy import detect_tool, signal_filter_for
from .security import (TokenError, decode_token, hash_token, looks_like_agent_token,
                       looks_like_api_key)
from .metering import record_and_check
from .service import run_analysis
from .upstreams import resolve as resolve_upstream

router = APIRouter(prefix="/v1", tags=["gateway"])

_SEVERITY_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}


@dataclass
class Principal:
    tenant_id: int
    actor: str  # who/what to attribute findings to (user email or API-key label)
    agent: str = ""  # resolved agent name (authenticated ag_ token), for least-privilege authz


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
    if looks_like_agent_token(token):        # an agent authenticating with its own ag_ token
        ag = (db.query(Agent).filter(Agent.token_hash == hash_token(token), Agent.active.is_(True))
              .one_or_none())
        if ag is None:
            raise HTTPException(status_code=401, detail="invalid agent token")
        return Principal(tenant_id=ag.tenant_id, actor=ag.name, agent=ag.name)
    if looks_like_api_key(token):
        p = _resolve_api_key(token, db)
    else:
        try:
            payload = decode_token(token)
        except TokenError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        user = db.get(User, int(payload.get("sub", 0)))
        if user is None or not user.active:
            raise HTTPException(status_code=401, detail="user not found or inactive")
        p = Principal(tenant_id=user.tenant_id, actor=user.email)
    p.agent = _resolve_gateway_agent(request, token, p.tenant_id, db)
    return p


def _resolve_gateway_agent(request: Request, primary: str, tenant_id: int, db: Session) -> str:
    """Authenticated agent name for least-privilege authz on the gateway: an `ag_…` token in
    `X-Warden-Agent` (or as the primary credential) that belongs to this tenant. Empty
    otherwise. The name is never self-asserted — it's resolved from a hashed token, so a
    caller can't claim a more-privileged agent to widen its role."""
    from .security import hash_token, looks_like_agent_token
    tok = (request.headers.get("x-warden-agent") or "").strip() or primary
    if not looks_like_agent_token(tok):
        return ""
    ag = (db.query(Agent).filter(Agent.token_hash == hash_token(tok), Agent.active.is_(True))
          .one_or_none())
    return ag.name if (ag is not None and ag.tenant_id == tenant_id) else ""


@dataclass
class GatewayPolicy:
    """A tenant's effective enforcement posture (its override, else the global default)."""
    enforce: bool
    block_severity: str


def _tenant_policy(tenant_id: int | None, db: Session) -> GatewayPolicy:
    t = db.get(Tenant, tenant_id) if tenant_id is not None else None
    enforce = t.gateway_enforce if t and t.gateway_enforce is not None else settings.gateway_enforce
    sev = (t.gateway_block_severity or "").strip() if t else ""
    return GatewayPolicy(enforce=bool(enforce), block_severity=sev or settings.gateway_block_severity)


def _blocked(verdict: dict, pol: GatewayPolicy) -> int:
    return _SEVERITY_RANK.get(verdict["severity"], 0) >= _SEVERITY_RANK.get(pol.block_severity, 3)


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
    """Scan the current outbound turn: the system prompt plus the latest user message.

    Agents (e.g. Claude Code) resend the whole conversation history and large tool results
    on every request. Scanning all of that means one secret anywhere in the history poisons
    every later turn (cascading false positives) and re-flags the same content. So we inspect
    what the user is sending now — the latest user message's text — AND the `system` prompt
    (instructions; previously accepted but never scanned, letting an injection/secret ride in
    the system field unchecked). tool-result/file-context blocks are still excluded."""
    parts = []
    sys_text = _text_from_content(system).strip() if system else ""
    if sys_text:
        parts.append(sys_text)
    got_user = False
    for m in reversed(messages or []):
        if not isinstance(m, dict):
            continue
        role = (m.get("author") or {}).get("role") if isinstance(m.get("author"), dict) else m.get("role")
        if role == "system":                       # OpenAI-style system message (in the array)
            parts.append(_text_from_content(m.get("content")).strip())
        elif role == "user" and not got_user:      # the latest user turn only
            parts.append(_text_from_content(m.get("content")).strip())
            got_user = True
    return "\n".join(p for p in parts if p)


def _tenant_suppress(tenant_id: int | None, db: Session) -> str:
    """The tenant's per-tool suppression spec, else the global GATEWAY_TOOL_SUPPRESS."""
    t = db.get(Tenant, tenant_id) if tenant_id is not None else None
    return (t.tool_suppress or "").strip() if t and (t.tool_suppress or "").strip() \
        else settings.gateway_tool_suppress


def _capture(prompt: str, model: str, tool: str, principal: Principal, db: Session) -> dict:
    item = AnalysisInput(content=prompt or "(empty)", subject=model, sender=principal.actor,
                         channel=tool, surface=Surface.LLM_IO)
    return run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                        signal_filter=signal_filter_for(tool, _tenant_suppress(principal.tenant_id, db)))


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


def _capture_activity_dict(act: dict | None, tool: str, principal: Principal, db: Session) -> dict | None:
    """Analyze a normalized agentic-activity dict (advertised descs + latest tool_use/result)
    on the mcp surface. Shared by the OpenAI/Anthropic and Responses-API request paths."""
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
    filt, dec = _gw_authz(principal, "", act["tool"], act["args_text"], db)
    result = run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                          signal_filter=filt, agent=principal.agent)
    if dec["enforce"] and dec["denied"]:
        result["authz_block"] = True
    return result


def _authz_signal_gw(enforce: bool, reason: str, agent: str, what: str):
    from .detectors.base import Category, Signal
    return Signal(
        category=Category.AGENT_AUTHZ, title="Agent action outside its role",
        detail=f"{reason} ({'enforce' if enforce else 'monitor'})",
        weight=0.85 if enforce else 0.55, confidence=0.9, detector="authz",
        evidence=f"{agent} → {(what or '')[:60]}", check="agent_authz")


def _gw_authz(principal: Principal, server: str, tool: str, args_text: str, db: Session):
    """(signal_filter, decision) for an authenticated gateway agent's tool call. The filter
    records the least-privilege verdict; the caller hard-blocks on enforce+denied regardless
    of severity — same authoritative control as the ingest path. Falls back to the plain MCP
    filter when there's no agent/role."""
    from .authz import role_context, decision as authz_decide
    dec = {"enforce": False, "denied": False, "reason": ""}
    ctx = role_context(db, principal.tenant_id, principal.agent) if principal.agent else None
    if ctx is None:
        return _mcp_sig_filter, dec
    role_d, enforce = ctx
    dec["enforce"] = enforce

    def _filter(signals):
        out = _mcp_sig_filter(signals)
        cats = {s.category.value for s in signals}
        denied, reason = authz_decide(role_d, server, tool, args_text, cats)
        if denied:
            dec["denied"] = True
            dec["reason"] = reason
            out.append(_authz_signal_gw(enforce, reason, principal.agent, tool or server))
        return out

    return _filter, dec


def _agentic_block(v: dict | None, pol: "GatewayPolicy") -> bool:
    """Whether an agentic verdict should block: an authenticated agent's role denied it
    (hard, role-governed), or the gateway is enforcing and the content crossed the bar."""
    if not v:
        return False
    return bool(v.get("authz_block")) or (pol.enforce and bool(_blocked(v, pol)))


def _capture_agentic(payload: dict, tool: str, principal: Principal, db: Session) -> dict | None:
    return _capture_activity_dict(_agentic_activity(payload), tool, principal, db)


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
    names = []
    for b in resp.get("content") or []:
        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name"):
            names.append(b["name"])
    for ch in resp.get("choices") or []:
        for tc in ((ch.get("message") if isinstance(ch, dict) else None) or {}).get("tool_calls") or []:
            fn = tc.get("function") if isinstance(tc, dict) else None
            if isinstance(fn, dict) and fn.get("name"):
                names.append(fn["name"])
    return {"method": "tools/call", "tool": tool_name, "tools": names or [tool_name],
            "args_text": "\n".join(args)[:20000]}


def _gw_extra_tools_denied(principal: Principal, tools: list, db: Session) -> bool:
    """Least-privilege check for EVERY tool in a parallel/multi tool_use (the assembler
    flattens args but names only the first). Action authz only — content is already scanned.
    True if an enforcing role forbids any of them."""
    if not principal.agent or not tools or len(tools) <= 1:
        return False
    from .authz import role_context, authorize
    ctx = role_context(db, principal.tenant_id, principal.agent)
    if ctx is None:
        return False
    role_d, enforce = ctx
    return enforce and any(not authorize(role_d, "", t, "")[0] for t in tools)


def _capture_tool_activity(tool_name: str, args_text: str, tool: str,
                           principal: Principal, db: Session, tools: list | None = None) -> dict | None:
    """Analyze one assembled tool call on the mcp surface (shared by the response-side and
    streaming paths). `tools` lists every name in a parallel tool_use so authz covers all."""
    if not args_text:
        return None
    item = AnalysisInput(
        content=args_text, subject=f"agent {tool_name}".strip(), sender=principal.actor,
        channel=tool or "agent", surface=Surface.MCP,
        metadata={"method": "tools/call", "tool": tool_name, "args_text": args_text})
    filt, dec = _gw_authz(principal, "", tool_name, args_text, db)
    result = run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                          signal_filter=filt, agent=principal.agent)
    if (dec["enforce"] and dec["denied"]) or _gw_extra_tools_denied(principal, tools or [], db):
        result["authz_block"] = True
    return result


def _capture_response_agentic(resp: dict, tool: str, principal: Principal, db: Session) -> dict | None:
    act = _response_activity(resp)
    if not act:
        return None
    return _capture_tool_activity(act["tool"], act["args_text"], tool, principal, db, act.get("tools"))


# --- Response-side DLP: scan the MODEL'S OUTPUT for secrets/PII ------------------------
# The request-side scan catches what the user sends; this catches what the model returns —
# a jailbroken/compromised model echoing secrets, RAG/tool output surfacing data the user
# shouldn't see, or exfiltration via the completion. Only data-loss categories apply to an
# output (a model returning code is normal; prompt-attack categories are about the input).
_RESPONSE_DLP_KEEP = {"secret_leak", "pii_exposure"}


def _response_dlp_filter(signals: list) -> list:
    return [s for s in signals if s.category.value in _RESPONSE_DLP_KEEP]


def _response_output_text(resp: dict) -> str:
    """Assistant-authored text from an upstream reply across all four shapes."""
    if not isinstance(resp, dict):
        return ""
    parts: list[str] = []
    for ch in resp.get("choices") or []:                       # OpenAI chat
        msg = ch.get("message") if isinstance(ch, dict) else None
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            parts.append(msg["content"])
    for item in resp.get("output") or []:                      # OpenAI Responses
        for c in (item.get("content") or []) if isinstance(item, dict) else []:
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                parts.append(c["text"])
    for b in resp.get("content") or []:                        # Anthropic
        if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str):
            parts.append(b["text"])
    for cand in resp.get("candidates") or []:                  # Gemini
        for p in ((cand.get("content") or {}).get("parts") or []) if isinstance(cand, dict) else []:
            if isinstance(p, dict) and isinstance(p.get("text"), str):
                parts.append(p["text"])
    return "\n".join(parts)[:200000]


def _stream_output_text(sse: str) -> str:
    """Reassemble the model's output text from a buffered streamed reply (all four shapes),
    so enforce mode can DLP-scan streamed output before replaying it to the client."""
    parts: list[str] = []
    for evt in _sse_json(sse):
        for ch in evt.get("choices") or []:                    # OpenAI chat deltas
            d = ch.get("delta") if isinstance(ch, dict) else None
            if isinstance(d, dict) and isinstance(d.get("content"), str):
                parts.append(d["content"])
        if evt.get("type") == "content_block_delta":           # Anthropic text deltas
            d = evt.get("delta") or {}
            if d.get("type") == "text_delta" and isinstance(d.get("text"), str):
                parts.append(d["text"])
        if evt.get("type") == "response.output_text.delta" and isinstance(evt.get("delta"), str):
            parts.append(evt["delta"])                         # OpenAI Responses deltas
        for cand in evt.get("candidates") or []:               # Gemini SSE
            for p in ((cand.get("content") or {}).get("parts") or []) if isinstance(cand, dict) else []:
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    parts.append(p["text"])
    return "".join(parts)[:200000]


def _capture_response_dlp(text: str, model: str, tool: str, principal: Principal, db: Session) -> dict | None:
    """Scan model output text for secrets/PII. Uses the ai_usage surface (where the secret
    + high-entropy + PII detectors run — llm_io only does PII), then filters to the two
    data-loss categories that make sense for an *output*. Tagged as a response via subject."""
    if not text:
        return None
    item = AnalysisInput(content=text, subject=f"LLM response ({model})", sender=principal.actor,
                         channel=tool or "gateway", surface=Surface.AI_USAGE,
                         metadata={"direction": "response"})
    return run_analysis(item, persist=True, db=db, tenant_id=principal.tenant_id,
                        signal_filter=_response_dlp_filter)


def _scan_response(data: dict, model: str, tool: str, pol: "GatewayPolicy",
                   principal: Principal, db: Session):
    """Response-side DLP + agentic check, shared by the non-streaming handlers. Returns a
    blocking verdict (to turn into a provider error) or None."""
    if settings.gateway_scan_responses:
        v = _capture_response_dlp(_response_output_text(data), model, tool, principal, db)
        if pol.enforce and v and _blocked(v, pol):
            return v
    # Capture the response tool_use always (not just when the gateway enforces) so an
    # agent whose *role* enforces is blocked even under a monitor-mode gateway.
    ragentic = _capture_response_agentic(data, tool, principal, db)
    if _agentic_block(ragentic, pol):
        return ragentic
    return None
    return None


# --- Streaming (SSE) tool_use inspection ----------------------------------------------

def _sse_json(text: str):
    """Yield parsed JSON objects from SSE `data:` lines."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    yield json.loads(payload)
                except (ValueError, TypeError):
                    pass


def _stream_tool_use_anthropic(text: str) -> dict | None:
    """Assemble tool_use (name + input) from an Anthropic streamed response — content_block_start
    carries the tool name, input_json_delta fragments accumulate the input JSON."""
    idx_name, idx_json = {}, {}
    for evt in _sse_json(text):
        t = evt.get("type")
        if t == "content_block_start":
            cb = evt.get("content_block") or {}
            if cb.get("type") == "tool_use":
                idx_name[evt.get("index")] = cb.get("name", "")
                idx_json.setdefault(evt.get("index"), "")
        elif t == "content_block_delta":
            d = evt.get("delta") or {}
            if d.get("type") == "input_json_delta" and evt.get("index") in idx_json:
                idx_json[evt.get("index")] += d.get("partial_json", "")
    return _assemble_tool_use(idx_name, idx_json)


def _stream_tool_use_openai(text: str) -> dict | None:
    """Assemble tool_use from an OpenAI streamed response — choices[].delta.tool_calls[]
    with a name (first fragment) and accumulating function.arguments."""
    idx_name, idx_json = {}, {}
    for evt in _sse_json(text):
        for ch in evt.get("choices") or []:
            for tc in (ch.get("delta") or {}).get("tool_calls") or []:
                i = tc.get("index", 0)
                fn = tc.get("function") or {}
                if fn.get("name"):
                    idx_name[i] = fn["name"]
                    idx_json.setdefault(i, "")
                if isinstance(fn.get("arguments"), str):
                    idx_json[i] = idx_json.get(i, "") + fn["arguments"]
    return _assemble_tool_use(idx_name, idx_json)


def _assemble_tool_use(idx_name: dict, idx_json: dict) -> dict | None:
    if not idx_name:
        return None
    names, args = [], []
    for i, name in idx_name.items():
        names.append(name)
        raw = idx_json.get(i, "")
        try:
            _harvest_strings(json.loads(raw), args)
        except (ValueError, TypeError):
            if raw:
                args.append(raw)
    return {"tool": names[0], "tools": names, "args_text": "\n".join(args)[:20000]}


def _read_stream(url: str, payload: dict, headers: dict) -> tuple[int, str, bytes]:
    """Buffer a streamed upstream response (enforce mode needs the whole turn to inspect
    the tool_use before it reaches the client). Factored out so tests can stub it."""
    chunks: list[bytes] = []
    with httpx.Client(timeout=120) as c:
        with c.stream("POST", url, json=payload, headers=headers) as r:
            status, ctype = r.status_code, r.headers.get("content-type", "text/event-stream")
            for b in r.iter_bytes():
                chunks.append(b)
    return status, ctype, b"".join(chunks)


def _record_stream_dlp(raw: bytes, model: str, tool: str, principal: Principal) -> None:
    """Post-stream response DLP for monitor mode: scan the assembled output and record a
    finding after the client already got it (monitor can't block anyway). Best-effort, on a
    fresh session, never raises — the client's stream must not be affected."""
    try:
        text = _stream_output_text(raw.decode("utf-8", "replace"))
        if not text:
            return
        from .database import SessionLocal
        db = SessionLocal()
        try:
            _capture_response_dlp(text, model, tool, principal, db)
        finally:
            db.close()
    except Exception:
        pass


_STREAM_TEE_CAP = 2_000_000   # cap the accumulated copy so a huge stream can't blow memory


def _passthrough_stream(url: str, payload: dict, headers: dict, model: str = "",
                        tool: str = "", principal: Principal | None = None) -> StreamingResponse:
    """Pass-through streaming (monitor mode) — forward chunks as they arrive so the client
    keeps live output. When response DLP is on, also *tee* a bounded copy and scan the
    assembled output once the stream ends (no client-facing latency — the scan happens after
    the last token). The action is also recorded request-side on the next turn."""
    scan = principal is not None and settings.gateway_scan_responses

    def gen():
        buf: list[bytes] = []
        acc = 0
        try:
            with httpx.Client(timeout=120) as c:
                with c.stream("POST", url, json=payload, headers=headers) as r:
                    for b in r.iter_bytes():
                        if scan and acc < _STREAM_TEE_CAP:
                            buf.append(b)
                            acc += len(b)
                        yield b
        finally:
            if scan and buf:
                _record_stream_dlp(b"".join(buf), model, tool, principal)
    return StreamingResponse(gen(), media_type="text/event-stream")


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
    pol = _tenant_policy(principal.tenant_id, db)

    if pol.enforce and _blocked(verdict, pol):
        return _openai_error(verdict)
    # Agentic tool-use inspection (agentless MCP over the LLM API).
    agentic = _capture_agentic(payload, tool, principal, db)
    if _agentic_block(agentic, pol):
        return _openai_error(agentic)
    base, key = resolve_upstream("openai", principal.tenant_id, db)
    if base:
        url = base.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if payload.get("stream"):
            if not pol.enforce:
                return _passthrough_stream(url, payload, headers, model, tool, principal)  # monitor: live output (teed)
            status, ctype, raw = _read_stream(url, payload, headers)
            decoded = raw.decode("utf-8", "replace")
            act = _stream_tool_use_openai(decoded)
            if act:
                v = _capture_tool_activity(act["tool"], act["args_text"], tool, principal, db, act.get("tools"))
                if _agentic_block(v, pol):
                    return _openai_error(v)
            if settings.gateway_scan_responses:
                dlp = _capture_response_dlp(_stream_output_text(decoded), model, tool, principal, db)
                if dlp and _blocked(dlp, pol):
                    return _openai_error(dlp)
            return Response(content=raw, status_code=status, media_type=ctype)
        with httpx.Client(timeout=60) as c:
            r = c.post(url, json=payload, headers=headers)
        data = r.json()
        blocked = _scan_response(data, model, tool, pol, principal, db)
        if blocked:
            return _openai_error(blocked)
        return JSONResponse(status_code=r.status_code, content=data)
    return JSONResponse(content=_openai_stub(model, verdict))


# --- OpenAI Responses API (Codex CLI, newer OpenAI SDKs) ------------------------------
#
# The Responses API replaces `messages` with `input` (a string, or a list of typed items:
# messages, function_call, function_call_output) and returns an `output` array. Codex CLI
# uses it by default. Same OpenAI upstream/base and error envelope as chat/completions.

def _responses_text(c) -> str:
    """Text from a Responses content value: a string, or a list of typed blocks each with
    a `text` field (input_text / output_text / summary_text)."""
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(b.get("text", "") for b in c
                         if isinstance(b, dict) and isinstance(b.get("text"), str))
    return ""


def _responses_user_text(inp) -> str:
    """The current outbound user turn — mirrors _scan_messages (only the latest user item,
    so resent history doesn't cascade). `input` may be a bare string or an item list."""
    if isinstance(inp, str):
        return inp.strip()
    if isinstance(inp, list):
        for item in reversed(inp):
            if not isinstance(item, dict):
                continue
            role = (item.get("author") or {}).get("role") if isinstance(item.get("author"), dict) else item.get("role")
            if role == "user":
                return _responses_text(item.get("content")).strip()
    return ""


def _responses_agentic(payload: dict) -> dict | None:
    """Current-turn agentic activity from a Responses request: advertised tool descriptions,
    the latest function_call (name + args), and the latest function_call_output."""
    descs = [t["description"] for t in (payload.get("tools") or [])
             if isinstance(t, dict) and isinstance(t.get("description"), str)]
    inp = payload.get("input")
    tool_name, args_parts, result_parts = "", [], []
    if isinstance(inp, list):
        for item in reversed(inp):
            if isinstance(item, dict) and item.get("type") == "function_call":
                tool_name = item.get("name", "")
                if isinstance(item.get("arguments"), str):
                    args_parts.append(item["arguments"])
                break
        for item in reversed(inp):
            if isinstance(item, dict) and item.get("type") == "function_call_output":
                out = item.get("output")
                if isinstance(out, str):
                    result_parts.append(out)
                elif out is not None:
                    _harvest_strings(out, result_parts)
                break
    if not (descs or tool_name or args_parts or result_parts):
        return None
    method = "tools/call" if (tool_name or args_parts) else (
        "tools/advertised" if descs else "tool_result")
    return {"method": method, "tool": tool_name,
            "args_text": "\n".join(args_parts)[:20000],
            "result_text": "\n".join(p for p in result_parts if p)[:20000],
            "tool_descriptions": descs}


def _response_activity_responses(resp: dict) -> dict | None:
    """The tool_use the model just requested in a Responses reply — output[].function_call."""
    if not isinstance(resp, dict):
        return None
    tool_name, args = "", []
    for item in resp.get("output") or []:
        if isinstance(item, dict) and item.get("type") == "function_call":
            tool_name = tool_name or item.get("name", "")
            if isinstance(item.get("arguments"), str):
                args.append(item["arguments"])
    if not args:
        return None
    return {"method": "tools/call", "tool": tool_name, "args_text": "\n".join(args)[:20000]}


def _stream_tool_use_responses(text: str) -> dict | None:
    """Assemble a function_call from a streamed Responses reply — output_item.added carries
    the name, function_call_arguments.delta fragments accumulate the arguments. Best-effort:
    on any shape mismatch it returns None and the buffered stream is replayed verbatim."""
    idx_name, idx_json = {}, {}
    for evt in _sse_json(text):
        t = evt.get("type")
        if t == "response.output_item.added":
            item = evt.get("item") or {}
            if item.get("type") == "function_call":
                oi = evt.get("output_index", 0)
                idx_name[oi] = item.get("name", "")
                idx_json.setdefault(oi, "")
        elif t == "response.function_call_arguments.delta":
            oi = evt.get("output_index", 0)
            idx_json[oi] = idx_json.get(oi, "") + (evt.get("delta") or "")
    return _assemble_tool_use(idx_name, idx_json)


def _responses_stub(model: str, verdict: dict) -> dict:
    now = int(time.time())
    return {
        "id": f"resp_warden_{now}", "object": "response", "created_at": now, "model": model,
        "status": "completed",
        "output": [{"type": "message", "role": "assistant", "status": "completed", "content": [
            {"type": "output_text",
             "text": "[Warden gateway: no upstream configured — prompt passed inspection.]"}]}],
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        "warden": {"risk_score": verdict["risk_score"], "severity": verdict["severity"]},
    }


@router.post("/responses")
async def responses(request: Request, principal: Principal = Depends(get_gateway_principal),
                    db: Session = Depends(get_db)):
    limited = _rate_limited(db, principal, "openai")
    if limited:
        return limited
    payload = await request.json()
    model = payload.get("model", "unknown")
    tool = detect_tool(request.headers.get("user-agent", ""), request.headers.get("x-warden-tool", ""))
    verdict = _capture(_responses_user_text(payload.get("input")), model, tool, principal, db)
    pol = _tenant_policy(principal.tenant_id, db)

    if pol.enforce and _blocked(verdict, pol):
        return _openai_error(verdict)
    agentic = _capture_activity_dict(_responses_agentic(payload), tool, principal, db)
    if _agentic_block(agentic, pol):
        return _openai_error(agentic)
    base, key = resolve_upstream("openai", principal.tenant_id, db)
    if base:
        url = base.rstrip("/") + "/responses"
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if payload.get("stream"):
            if not pol.enforce:
                return _passthrough_stream(url, payload, headers, model, tool, principal)  # monitor: live output (teed)
            status, ctype, raw = _read_stream(url, payload, headers)
            decoded = raw.decode("utf-8", "replace")
            act = _stream_tool_use_responses(decoded)
            if act:
                v = _capture_tool_activity(act["tool"], act["args_text"], tool, principal, db, act.get("tools"))
                if _agentic_block(v, pol):
                    return _openai_error(v)
            if settings.gateway_scan_responses:
                dlp = _capture_response_dlp(_stream_output_text(decoded), model, tool, principal, db)
                if dlp and _blocked(dlp, pol):
                    return _openai_error(dlp)
            return Response(content=raw, status_code=status, media_type=ctype)
        with httpx.Client(timeout=120) as c:
            r = c.post(url, json=payload, headers=headers)
        data = r.json()
        if settings.gateway_scan_responses:
            dlp = _capture_response_dlp(_response_output_text(data), model, tool, principal, db)
            if pol.enforce and dlp and _blocked(dlp, pol):
                return _openai_error(dlp)
        if pol.enforce:
            ragentic = _capture_response_agentic(data, tool, principal, db) or \
                _capture_response_agentic_responses(data, tool, principal, db)
            if _agentic_block(ragentic, pol):
                return _openai_error(ragentic)
        return JSONResponse(status_code=r.status_code, content=data)
    return JSONResponse(content=_responses_stub(model, verdict))


def _capture_response_agentic_responses(resp: dict, tool: str, principal: Principal, db: Session) -> dict | None:
    act = _response_activity_responses(resp)
    if not act:
        return None
    return _capture_tool_activity(act["tool"], act["args_text"], tool, principal, db, act.get("tools"))


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
    pol = _tenant_policy(principal.tenant_id, db)

    if pol.enforce and _blocked(verdict, pol):
        return _anthropic_error(verdict)
    # Agentic tool-use inspection (agentless MCP over the LLM API).
    agentic = _capture_agentic(payload, tool, principal, db)
    if _agentic_block(agentic, pol):
        return _anthropic_error(agentic)

    base, key = resolve_upstream("anthropic", principal.tenant_id, db)
    if key:
        if payload.get("stream"):
            url = base.rstrip("/") + "/v1/messages"
            headers = _anthropic_headers(request, key)
            if not pol.enforce:
                return _passthrough_stream(url, payload, headers, model, tool, principal)  # monitor: live output (teed)
            # enforce: buffer, inspect the assembled tool_use, block or replay verbatim.
            status, ctype, raw = _read_stream(url, payload, headers)
            decoded = raw.decode("utf-8", "replace")
            act = _stream_tool_use_anthropic(decoded)
            if act:
                v = _capture_tool_activity(act["tool"], act["args_text"], tool, principal, db, act.get("tools"))
                if _agentic_block(v, pol):
                    return _anthropic_error(v)
            if settings.gateway_scan_responses:
                dlp = _capture_response_dlp(_stream_output_text(decoded), model, tool, principal, db)
                if dlp and _blocked(dlp, pol):
                    return _anthropic_error(dlp)
            return Response(content=raw, status_code=status, media_type=ctype)
        status, data = _post_upstream_anthropic("/v1/messages", payload, request, base, key)
        # Response-side: DLP on the model's output (secrets/PII), and block a dangerous
        # tool_use it just requested, before the client sees/executes it (non-streaming).
        if settings.gateway_scan_responses:
            dlp = _capture_response_dlp(_response_output_text(data), model, tool, principal, db)
            if pol.enforce and dlp and _blocked(dlp, pol):
                return _anthropic_error(dlp)
        if pol.enforce:
            ragentic = _capture_response_agentic(data, tool, principal, db)
            if _agentic_block(ragentic, pol):
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
    pol = _tenant_policy(principal.tenant_id, db)

    if pol.enforce and _blocked(verdict, pol):
        return _gemini_error(verdict)
    base, key = resolve_upstream("gemini", principal.tenant_id, db)
    if key:
        resp = _forward_gemini(model, method, payload, request, base, key)
        # Response-side DLP on the non-streaming JSON reply (streaming is passed through).
        if settings.gateway_scan_responses and method == "generateContent":
            try:
                data = json.loads(resp.body)
            except (ValueError, TypeError):
                data = None
            if isinstance(data, dict):
                dlp = _capture_response_dlp(_response_output_text(data), model, tool, principal, db)
                if pol.enforce and dlp and _blocked(dlp, pol):
                    return _gemini_error(dlp)
        return resp
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
