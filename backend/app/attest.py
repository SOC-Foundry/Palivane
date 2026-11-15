"""Commit attestations: which commits were AI-assisted, and were they checked.

`palivane-hook git-install` puts two git hooks in a repo. prepare-commit-msg reads the hook's
session ledger and, when a coding agent worked in that repo since the last commit, writes it
into the message as trailers:

    Palivane-AI-Assisted: yes
    Palivane-Scan: agent=claude-code; tool-calls=12; files=3; blocked=0; window=...

post-commit then registers the commit here (POST /api/attest/commit) with the device's
capture key. The server fills in what the device cannot know: how many findings Palivane
raised for that person in the window, and which, and signs the row with a token derived
from the app secret, so an auditor reading `git log` can check any commit against the
console (GET /api/attest/verify?sha=). The EU AI Act's transparency duty, and the SOC 2
question "which code was AI-written and was it reviewed", answered by the commit itself.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .models import CommitAttestation, Finding

_AGENT_SURFACES = ("agent_tools", "mcp", "ai_usage", "llm_io")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        return None


def token_for(tenant_id: int, sha: str) -> str:
    from .security import _secret
    key = hmac.new(_secret(), b"palivane-commit-attest", hashlib.sha256).digest()
    return hmac.new(key, f"{tenant_id}:{sha}".encode(), hashlib.sha256).hexdigest()[:24]


def register(db: Session, tenant_id: int, actor: str, body: dict) -> CommitAttestation:
    """Store (or refresh) the attestation for one commit, counting the person's findings in
    the window the trailer names, widened by a minute each side for clock skew."""
    sha = (body.get("sha") or "").strip().lower()
    start, end = _parse(body.get("window_start")), _parse(body.get("window_end"))
    ids: list[int] = []
    if actor and start and end:
        q = (db.query(Finding.id)
               .filter(Finding.tenant_id == tenant_id,
                       or_(func.lower(Finding.sender) == actor.lower(),
                           func.lower(Finding.agent) == actor.lower()),
                       Finding.surface.in_(_AGENT_SURFACES),
                       Finding.last_seen >= start - timedelta(minutes=1),
                       Finding.last_seen <= end + timedelta(minutes=1))
               .order_by(Finding.id.asc()).limit(200))
        ids = [i for (i,) in q.all()]
    row = (db.query(CommitAttestation)
             .filter(CommitAttestation.tenant_id == tenant_id, CommitAttestation.sha == sha)
             .one_or_none())
    if row is None:
        row = CommitAttestation(tenant_id=tenant_id, sha=sha, created_at=_now())
        db.add(row)
    row.repo = (body.get("repo") or "")[:300]
    row.branch = (body.get("branch") or "")[:120]
    row.author = (body.get("author") or "")[:320]
    row.actor = (actor or "")[:320]
    row.subject = (body.get("subject") or "")[:200]
    row.agent = (body.get("agent") or "")[:120]
    row.tool_calls = int(body.get("tool_calls") or 0)
    row.files = int(body.get("files") or 0)
    row.blocked = int(body.get("blocked") or 0)
    row.findings = len(ids)
    row.finding_ids = ids
    row.window_start, row.window_end = start, end
    row.token = token_for(tenant_id, sha)
    db.commit()
    db.refresh(row)
    return row


def listing(db: Session, tenant_id: int, limit: int = 200) -> list[dict]:
    rows = (db.query(CommitAttestation).filter(CommitAttestation.tenant_id == tenant_id)
              .order_by(CommitAttestation.created_at.desc()).limit(limit).all())
    return [r.to_dict() for r in rows]


def verify(db: Session, tenant_id: int, sha: str) -> dict:
    sha = (sha or "").strip().lower()
    row = (db.query(CommitAttestation)
             .filter(CommitAttestation.tenant_id == tenant_id, CommitAttestation.sha == sha)
             .one_or_none())
    if row is None:
        # A prefix is fine for a human pasting a short sha.
        if 7 <= len(sha) < 40:
            row = (db.query(CommitAttestation)
                     .filter(CommitAttestation.tenant_id == tenant_id, CommitAttestation.sha.like(sha + "%"))
                     .order_by(CommitAttestation.created_at.desc()).first())
    if row is None:
        return {"sha": sha, "attested": False}
    return {"sha": row.sha, "attested": True, "valid": hmac.compare_digest(row.token or "", token_for(tenant_id, row.sha)),
            **row.to_dict()}
