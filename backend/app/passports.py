"""Capability passports: what an agent may do, signed, short-lived, checked where it acts.

Attestation proves who an agent is; a role says what it may do in general. A passport is
narrower and shorter: a signed token that names this agent, this organisation, a scope
(which MCP servers and tools, which shell commands, which model providers) and an expiry
of at most a day. The hook presents it as the agent identity on every tool call and the
agent presents it to the gateway as its credential, and both check the scope before the
action, independent of scoring and of the role. Outside the scope, the call is refused
and the finding says so. Revoking the passport, or disabling the agent, ends it at once.

Least privilege enforced at the resource, not hoped for at the prompt. Once an org's
tools check passports, switching vendors means re-issuing trust for every agent.
"""
from __future__ import annotations

import fnmatch
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .models import Agent, Passport

MAX_TTL_MIN = 24 * 60
PROVIDERS = ("anthropic", "openai", "gemini")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _globs(values) -> list[str]:
    out = []
    for v in values or []:
        v = str(v).strip().lower()
        if v and v not in out:
            out.append(v[:120])
    return out[:50]


def clean_scope(scope: dict | None) -> dict:
    s = scope or {}
    providers = [p for p in _globs(s.get("providers")) if p in PROVIDERS]
    return {"servers": _globs(s.get("servers")), "tools": _globs(s.get("tools")),
            "commands": _globs(s.get("commands")), "providers": providers}


def issue(db: Session, tenant_id: int, agent: Agent, scope: dict, ttl_minutes: int, by: str,
          note: str = "") -> tuple[str, Passport]:
    from .security import create_token
    ttl = max(1, min(int(ttl_minutes or 60), MAX_TTL_MIN))
    sc = clean_scope(scope)
    jti = secrets.token_hex(12)
    now = _now()
    row = Passport(tenant_id=tenant_id, agent_id=agent.id, agent_name=agent.name, jti=jti, scope=sc,
                   note=(note or "")[:200], issued_by=(by or "")[:320], issued_at=now,
                   expires_at=now + timedelta(minutes=ttl), uses=0)
    db.add(row)
    db.commit()
    db.refresh(row)
    token = create_token({"typ": "passport", "agent_id": agent.id, "tenant": tenant_id, "jti": jti,
                          "scope": sc}, ttl=ttl * 60)
    return token, row


def resolve(db: Session, token: str) -> tuple[Agent, Passport]:
    """The agent and the live passport row behind a token, or 401. The row is re-read on
    every call, so a revoke or a disabled agent ends the passport at once."""
    from .security import TokenError, decode_token
    try:
        payload = decode_token(token)
    except TokenError as e:
        raise HTTPException(status_code=401, detail=str(e))
    if payload.get("typ") != "passport":
        raise HTTPException(status_code=401, detail="not a passport")
    row = (db.query(Passport).filter(Passport.jti == str(payload.get("jti") or "")).one_or_none())
    if row is None or row.tenant_id != int(payload.get("tenant", -1)):
        raise HTTPException(status_code=401, detail="unknown passport")
    if row.revoked_at is not None:
        raise HTTPException(status_code=401, detail="passport revoked")
    if row.expires_at and row.expires_at < _now():
        raise HTTPException(status_code=401, detail="passport expired")
    ag = db.get(Agent, row.agent_id)
    if ag is None or not ag.active or ag.tenant_id != row.tenant_id:
        raise HTTPException(status_code=401, detail="agent not found or disabled")
    row.uses = (row.uses or 0) + 1
    row.last_used_at = _now()
    db.commit()
    return ag, row


def is_passport(token: str) -> bool:
    from .security import jwt_unverified_claims, looks_like_jwt
    if not looks_like_jwt(token or ""):
        return False
    try:
        return jwt_unverified_claims(token).get("typ") == "passport"
    except Exception:  # noqa: BLE001
        return False


def _ok(value: str, patterns: list[str]) -> bool:
    """Empty patterns = unrestricted for that dimension. Otherwise the value must match one."""
    if not patterns:
        return True
    v = (value or "").lower()
    return any(fnmatch.fnmatch(v, p) for p in patterns)


def decide_tool(scope: dict, server: str, tool: str, command: str = "") -> tuple[bool, str]:
    """(denied, reason) for an MCP/agent tool call under the passport's scope."""
    sc = scope or {}
    if server and not _ok(server, sc.get("servers") or []):
        return True, f"server '{server}' is outside the passport (allowed: {', '.join(sc['servers'])})"
    if tool and not _ok(tool, sc.get("tools") or []):
        return True, f"tool '{tool}' is outside the passport (allowed: {', '.join(sc['tools'])})"
    cmds = sc.get("commands") or []
    if cmds and command:
        from .authz import command_parts
        for part in command_parts(command) or [command]:
            head = (part.strip().split() or [""])[0]
            if not (_ok(part.strip(), cmds) or _ok(head, cmds)):
                return True, f"command '{part.strip()[:60]}' is outside the passport (allowed: {', '.join(cmds)})"
    return False, ""


def decide_provider(scope: dict, provider: str) -> tuple[bool, str]:
    provs = (scope or {}).get("providers") or []
    if provs and provider and provider not in provs:
        return True, f"provider '{provider}' is outside the passport (allowed: {', '.join(provs)})"
    return False, ""


def listing(db: Session, tenant_id: int, include_ended: bool = False) -> list[dict]:
    q = db.query(Passport).filter(Passport.tenant_id == tenant_id)
    now = _now()
    if not include_ended:
        q = q.filter(Passport.revoked_at.is_(None), Passport.expires_at > now)
    rows = q.order_by(Passport.issued_at.desc()).limit(500).all()
    return [r.to_dict(now) for r in rows]


def revoke(db: Session, tenant_id: int, passport_id: int, by: str) -> Passport:
    row = db.get(Passport, passport_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="passport not found")
    if row.revoked_at is None:
        row.revoked_at = _now()
        row.revoked_by = (by or "")[:320]
        db.commit()
    return row


def verify(db: Session, tenant_id: int, token: str) -> dict:
    """What a third party (an MCP server, a gateway in front of a tool) can ask: is this
    passport live, whose is it, what does it allow. Never bumps the use count."""
    from .security import TokenError, decode_token
    try:
        payload = decode_token(token)
    except TokenError as e:
        return {"valid": False, "reason": str(e)}
    if payload.get("typ") != "passport" or int(payload.get("tenant", -1)) != tenant_id:
        return {"valid": False, "reason": "not one of this organisation's passports"}
    row = db.query(Passport).filter(Passport.jti == str(payload.get("jti") or "")).one_or_none()
    if row is None:
        return {"valid": False, "reason": "unknown passport"}
    now = _now()
    if row.revoked_at is not None:
        return {"valid": False, "reason": "revoked", **row.to_dict(now)}
    if row.expires_at and row.expires_at < now:
        return {"valid": False, "reason": "expired", **row.to_dict(now)}
    ag = db.get(Agent, row.agent_id)
    if ag is None or not ag.active:
        return {"valid": False, "reason": "agent disabled", **row.to_dict(now)}
    return {"valid": True, **row.to_dict(now)}
