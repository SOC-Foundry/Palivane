"""Tenant allowlists: commands and paths an org has decided are fine, each for a limited time.

Without this, the only way to stop a rule flagging something expected (the team's own installer, a
fixtures directory full of fake keys) was to switch the whole check off for a user, for good. This is
narrower and it lapses: an admin names the exact statement or path, says why, and picks an expiry
(capped; there is no "never"). The entry stops applying on its own, is listed with how often it was
actually used, and every change is audited.

What an entry can and cannot say is decided in `detectors/allow.py` (the matching, which the
detectors run without a database). This module is the other half: which entries are written down
(validation that keeps an entry from being broader than the admin meant), who may write them, how
they reach the detectors, and the housekeeping.

The rules for what is accepted exist to stop a footgun, not a malicious admin: an admin can already
turn a check off. So an entry must be a statement a rule actually flags (an entry that can never
match is a typo), must not store a credential, and must not be so wide that a wildcard stretches
past what was reviewed.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from . import audit_log, excerpts
from .auth import require_admin
from .config import settings
from .database import get_db
from .detectors import mcp_guard
from .detectors.allow import collapse_ws, statements
from .models import AllowEntry, Finding, User

router = APIRouter(prefix="/api", tags=["allowlist"])
_log = logging.getLogger(__name__)

DEFAULT_DAYS = 30
MAX_ACTIVE = 200          # per org: a long list is a policy nobody has read
KEEP_DAYS = 90            # a lapsed or revoked entry stays listed this long, for the record

_DRIVE = re.compile(r"^[A-Za-z]:/")
_BAD_PATH_CHARS = re.compile(r"[\x00-\x1f$`\[\]{}]")


class AllowError(ValueError):
    """An entry that cannot be accepted; the message is shown to the admin as written."""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --- validation -------------------------------------------------------------------------------

def _check_clean(pattern: str) -> None:
    """An entry is configuration, stored and listed as written: it must not carry a credential or a
    personal identifier, and must not carry a `«redacted»` marker copied from a finding (which would
    be a literal that never matches anything)."""
    if "«redacted" in pattern:
        raise AllowError("That text has a «redacted» marker from the finding in it. Replace the "
                         "masked part with * (for one argument) so the entry says what you mean.")
    if excerpts.mask_text(pattern, fuzzy=True) != pattern:
        raise AllowError("That looks like it contains a credential or a personal identifier. "
                         "Replace it with * so the entry does not store it.")


def validate_command(raw: str) -> str:
    """The pattern as stored, or AllowError. One shell statement that a command rule flags."""
    p = collapse_ws(raw)
    if not p:
        raise AllowError("Enter the command.")
    if len(p) > 500:
        raise AllowError("A command entry is at most 500 characters.")
    _check_clean(p)
    spans = statements(p)
    if len(spans) != 1 or spans[0] != (0, len(p)):
        raise AllowError("An entry is ONE statement: that has several (split by ; && || & or a new "
                         "line). Add one entry for each. A pipe (a | b) is fine: a pipeline is one "
                         "statement.")
    wild = p.count("*")
    if wild > 3:
        raise AllowError("At most 3 wildcards (*) in an entry.")
    tokens = p.split(" ")
    if "*" in tokens[0]:
        raise AllowError("The command name itself cannot be a wildcard.")
    for tok in tokens:
        if "://" in tok and "*" in tok.split("://", 1)[1].split("/", 1)[0]:
            raise AllowError("The host in a URL cannot be a wildcard: that would allow the command "
                             "against any server.")
    literal = len(p.replace("*", "").replace(" ", ""))
    if literal < 6 or (wild and literal < 16):
        raise AllowError("That is too short or too wildcarded to be a command anyone reviewed. "
                         "Spell out more of it.")
    if not mcp_guard._would_flag(p.replace("*", "x")):
        raise AllowError("No command rule flags that text, so allowing it would do nothing. Copy "
                         "the command from the finding exactly (one statement, as written).")
    return p


def validate_path(raw: str) -> str:
    """The glob as stored, or AllowError. `*` is within one directory, `**` crosses directories,
    `?` is one character; `..`, shell expansions and URLs are not accepted."""
    p = re.sub(r"/+", "/", str(raw or "").strip().replace("\\", "/"))
    if not p:
        raise AllowError("Enter the path.")
    if len(p) > 400:
        raise AllowError("A path entry is at most 400 characters.")
    if p.startswith("file:") or ("://" in p) or (":" in p and not _DRIVE.match(p)):
        raise AllowError("Enter a local path, not a URL.")
    if _BAD_PATH_CHARS.search(p):
        raise AllowError("Shell expansions ($, backticks), brackets and braces are not supported "
                         "in a path entry. Use * (one directory level), ** (any depth) or ?.")
    if ".." in p.split("/"):
        raise AllowError("Write the real path: .. is not accepted.")
    if p.endswith("/"):
        raise AllowError("A path entry names files. To allow a directory, end it with /** .")
    _check_clean(p)
    segments = [x for x in p.split("/") if x]
    wildcard = any("*" in x or "?" in x for x in segments)
    rooted = p.startswith(("/", "~/")) or bool(_DRIVE.match(p))
    if not rooted and not any(len(re.sub(r"[*?]", "", seg)) >= 3 for seg in segments[:-1]):
        # `.env` and `**/.env` name that file in EVERY project. Anchor it to a directory.
        raise AllowError("Name the directory as well as the file, for example /srv/app/.env or "
                         "**/fixtures/**/service-account.json. A bare file name would allow it "
                         "everywhere.")
    if wildcard and rooted:
        lead = []
        for seg in segments:
            if "*" in seg or "?" in seg:
                break
            if seg != "~":
                lead.append(seg)
        if len(lead) < 2:
            raise AllowError("Anchor the pattern deeper than one directory: /home/** would cover "
                             "every home directory. For example /home/alice/project/**.")
    if len(re.sub(r"[*?/]", "", p)) < 8:
        raise AllowError("That path is too short or too wildcarded to be reviewed. Spell out more of it.")
    return p


def validate(kind: str, raw: str) -> str:
    if kind == "command":
        return validate_command(raw)
    if kind == "path":
        return validate_path(raw)
    raise AllowError("kind must be 'command' or 'path'.")


# --- what the detectors are given -----------------------------------------------------------------

def active_entries(db: Session, tenant_id: int | None, actor: str, tool: str,
                   now: datetime | None = None, claimed: bool = False) -> list[AllowEntry]:
    """The entries that apply to this actor and tool right now: not revoked, not lapsed, and
    whose own narrowing (actor, tool) fits. An entry narrowed to an actor is that person's
    exemption, so a claimed actor (see policies.resolve_disabled) doesn't get it — only
    entries that apply to everyone."""
    if tenant_id is None:
        return []
    now = now or _now()
    rows = (db.query(AllowEntry)
              .filter(AllowEntry.tenant_id == tenant_id, AllowEntry.revoked_at.is_(None),
                      AllowEntry.expires_at > now)
              .all())
    who, what = (actor or "").strip().lower(), (tool or "").strip().lower()
    return [r for r in rows
            if (not r.actor or (not claimed and r.actor.lower() == who))
            and (not r.tool or r.tool.lower() == what)]


def attach(db: Session, tenant_id: int | None, actor: str, tool: str, metadata: dict,
           claimed: bool = False) -> dict | None:
    """Put the tenant's applicable entries into `metadata["allow"]` as plain data for the
    detectors, and return that holder so the caller can `record_hits` once the analysis is done.
    None (and nothing attached) when there are none. A failure here means NO allowlist, which can
    only cost an alert: every call is judged exactly as it would be without one."""
    try:
        rows = active_entries(db, tenant_id, actor, tool, claimed=claimed)
    except Exception:
        _log.warning("allowlist lookup failed; judging this call without it", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass
        return None
    if not rows:
        return None
    holder = {
        "commands": [{"id": r.id, "pattern": r.pattern} for r in rows if r.kind == "command"],
        "paths": [{"id": r.id, "pattern": r.pattern} for r in rows if r.kind == "path"],
        "hits": [],
    }
    metadata["allow"] = holder
    return holder


def record_hits(db: Session, holder: dict | None) -> None:
    """Count the entries that silenced something in this analysis. Best-effort: never fails a call."""
    ids = [i for i in ((holder or {}).get("hits") or []) if isinstance(i, int)]
    if not ids:
        return
    try:
        db.query(AllowEntry).filter(AllowEntry.id.in_(ids)).update(
            {AllowEntry.hit_count: func.coalesce(AllowEntry.hit_count, 0) + 1,
             AllowEntry.last_hit_at: _now()}, synchronize_session=False)
        db.commit()
    except Exception:
        _log.warning("could not record allowlist hits", exc_info=True)
        try:
            db.rollback()
        except Exception:
            pass


def expiring_soon(db: Session, tenant_id: int, now: datetime | None = None, days: int = 7) -> list[AllowEntry]:
    """Active entries that lapse within `days`, soonest first: what an admin should renew or let go
    before the alerts it was holding back return."""
    now = now or _now()
    return (db.query(AllowEntry)
              .filter(AllowEntry.tenant_id == tenant_id, AllowEntry.revoked_at.is_(None),
                      AllowEntry.expires_at > now, AllowEntry.expires_at <= now + timedelta(days=days))
              .order_by(AllowEntry.expires_at.asc(), AllowEntry.id.asc()).all())


def recently_lapsed(db: Session, tenant_id: int, now: datetime | None = None,
                    days: int = 7) -> list[AllowEntry]:
    """Entries that lapsed (were not revoked, and not renewed since) in the last `days`, most
    recent first: their commands and paths are being flagged again."""
    now = now or _now()
    return (db.query(AllowEntry)
              .filter(AllowEntry.tenant_id == tenant_id, AllowEntry.revoked_at.is_(None),
                      AllowEntry.expires_at <= now, AllowEntry.expires_at > now - timedelta(days=days))
              .order_by(AllowEntry.expires_at.desc(), AllowEntry.id.desc()).all())


def prune(db: Session) -> int:
    """Delete entries that lapsed or were revoked more than KEEP_DAYS ago. Rows younger than that
    stay listed: they are the record of what was allowed, for how long, and by whom."""
    cutoff = _now() - timedelta(days=KEEP_DAYS)
    n = (db.query(AllowEntry)
           .filter((AllowEntry.expires_at < cutoff) | (AllowEntry.revoked_at < cutoff))
           .delete(synchronize_session=False))
    db.commit()
    return n


# --- API (admin only) ---------------------------------------------------------------------------

class AllowIn(BaseModel):
    kind: Literal["command", "path"]
    pattern: str = Field(min_length=1, max_length=600)
    reason: str = Field(min_length=3, max_length=500)
    expires_in_days: int = Field(DEFAULT_DAYS, ge=1)
    actor: str = Field("", max_length=320)          # "" = anyone
    tool: str = Field("", max_length=64)            # "" = any tool
    finding_id: int | None = None


class RenewIn(BaseModel):
    expires_in_days: int = Field(DEFAULT_DAYS, ge=1)


def _days(n: int) -> int:
    if n > settings.allowlist_max_days:
        raise HTTPException(status_code=400, detail=(
            f"An entry can last at most {settings.allowlist_max_days} days: it is meant to be "
            "reviewed again, not to become permanent."))
    return n


def _entry(db: Session, tenant_id: int, entry_id: int) -> AllowEntry:
    row = (db.query(AllowEntry)
             .filter(AllowEntry.id == entry_id, AllowEntry.tenant_id == tenant_id).one_or_none())
    if row is None:
        raise HTTPException(status_code=404, detail="allowlist entry not found")
    return row


@router.get("/allowlist")
def list_entries(status: Literal["active", "lapsed", "all"] = "all",
                 current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """This org's entries (newest first), each with its status, time left, and how often it was
    actually used. `lapsed` is expired or revoked."""
    now = _now()
    rows = (db.query(AllowEntry).filter(AllowEntry.tenant_id == current.tenant_id)
              .order_by(AllowEntry.id.desc()).all())
    out = [r.to_dict(now) for r in rows]
    if status == "active":
        out = [r for r in out if r["status"] == "active"]
    elif status == "lapsed":
        out = [r for r in out if r["status"] != "active"]
    return {"entries": out,
            "limits": {"default_days": DEFAULT_DAYS, "max_days": settings.allowlist_max_days,
                       "max_active": MAX_ACTIVE, "keep_days": KEEP_DAYS}}


@router.post("/allowlist", status_code=201)
def create_entry(body: AllowIn, current: User = Depends(require_admin), db: Session = Depends(get_db)):
    days = _days(body.expires_in_days)
    try:
        pattern = validate(body.kind, body.pattern)
    except AllowError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    reason = collapse_ws(body.reason)
    if len(reason) < 3:
        raise HTTPException(status_code=400, detail="Say why: a reason is required.")
    actor, tool = body.actor.strip().lower(), body.tool.strip()
    now = _now()
    live = [r for r in db.query(AllowEntry).filter(
        AllowEntry.tenant_id == current.tenant_id, AllowEntry.revoked_at.is_(None),
        AllowEntry.expires_at > now).all()]
    if len(live) >= MAX_ACTIVE:
        raise HTTPException(status_code=400, detail=f"An org can have at most {MAX_ACTIVE} active "
                            "entries. Revoke ones that are no longer needed.")
    dup = next((r for r in live if r.kind == body.kind and r.pattern == pattern
                and (r.actor or "").lower() == actor and (r.tool or "").lower() == tool.lower()), None)
    if dup is not None:
        raise HTTPException(status_code=409, detail=(
            f"That is already allowed until {dup.expires_at:%Y-%m-%d} (entry {dup.id}). Renew it "
            "instead of adding it again."))
    finding_id = None
    if body.finding_id is not None:
        f = db.get(Finding, body.finding_id)
        if f is not None and f.tenant_id == current.tenant_id:
            finding_id = f.id
    row = AllowEntry(tenant_id=current.tenant_id, kind=body.kind, pattern=pattern, actor=actor,
                     tool=tool, reason=reason, created_by=current.email, created_at=now,
                     expires_at=now + timedelta(days=days), finding_id=finding_id, hit_count=0)
    db.add(row)
    db.commit()
    db.refresh(row)
    audit_log.record(db, current.tenant_id, current.email, "allowlist.create", target=str(row.id),
                     detail={"kind": row.kind, "pattern": row.pattern, "actor": row.actor,
                             "tool": row.tool, "reason": row.reason, "days": days,
                             "expires_at": row.expires_at.isoformat(), "finding_id": finding_id})
    return row.to_dict(now)


@router.post("/allowlist/{entry_id}/renew")
def renew_entry(entry_id: int, body: RenewIn, current: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    """Set a new expiry, counted from now. A revoked entry cannot be renewed: revoking was a
    decision, so make a new entry if you have changed your mind."""
    days = _days(body.expires_in_days)
    row = _entry(db, current.tenant_id, entry_id)
    if row.revoked_at is not None:
        raise HTTPException(status_code=409, detail="That entry was revoked. Add a new one instead.")
    old = row.expires_at
    now = _now()
    row.expires_at = now + timedelta(days=days)
    db.commit()
    db.refresh(row)
    audit_log.record(db, current.tenant_id, current.email, "allowlist.renew", target=str(row.id),
                     detail={"pattern": row.pattern, "days": days,
                             "was": old.isoformat() if old else None,
                             "expires_at": row.expires_at.isoformat()})
    return row.to_dict(now)


@router.post("/allowlist/{entry_id}/revoke")
def revoke_entry(entry_id: int, current: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = _entry(db, current.tenant_id, entry_id)
    now = _now()
    if row.revoked_at is None:
        row.revoked_at = now
        row.revoked_by = current.email
        db.commit()
        db.refresh(row)
        audit_log.record(db, current.tenant_id, current.email, "allowlist.revoke", target=str(row.id),
                         detail={"pattern": row.pattern, "hit_count": row.hit_count or 0})
    return row.to_dict(now)
