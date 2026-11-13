"""Where a credential travelled, and proof that its rotation took.

When a key is found in a prompt, the question is not "block the next one" but "where else
did this exact value go in the last 90 days, through which tools, from which people", and
after the key is rotated, "has the old value stopped appearing". Findings store masked
evidence, not the value, so the value is kept as a keyed fingerprint: an HMAC under the app
secret, separated by purpose, that the same value always maps to and nothing maps back
from. One sighting row per (secret, finding); one rotation row per secret, verified the day
the old value has not been seen for VERIFY_AFTER following the rotation.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from .detectors.base import AnalysisInput
from .detectors.patterns import find_secret_matches
from .models import Finding, SecretRotation, SecretSighting

VERIFY_AFTER = timedelta(days=7)
MAX_PER_EVENT = 20


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _key() -> bytes:
    from .security import _secret
    return hmac.new(_secret(), b"palivane-secrets-ledger", hashlib.sha256).digest()


def fingerprint(tenant_id: int, value: str) -> str:
    """The keyed fingerprint of a secret value for one org: stable, one-way, 32 hex chars.
    Per tenant, so the same leaked key in two orgs is two unrelated fingerprints."""
    return hmac.new(_key(), f"{tenant_id}:{value.strip()}".encode(), hashlib.sha256).hexdigest()[:32]


def _cat(s) -> str:
    c = s.get("category") if isinstance(s, dict) else getattr(s, "category", "")
    return getattr(c, "value", c) or ""


def record(db: Session, tenant_id: int | None, item: AnalysisInput, signals, finding_id: int) -> int:
    """After a finding with a secret is persisted: a sighting per distinct secret value in
    the event, under the finding. One row per (secret, finding): a recurrence that folds
    into the same finding refreshes the row's seen_at rather than adding another, so the
    rotation watch still sees the value come back. Best-effort; never raises."""
    if tenant_id is None or db is None or not finding_id:
        return 0
    if not any(_cat(s) == "secret_leak" for s in signals or []):
        return 0
    text = "\n".join(p for p in (item.content, (item.metadata or {}).get("args_text", "")) if p)
    matches = find_secret_matches(text)[:MAX_PER_EVENT]
    if not matches:
        return 0
    added = 0
    try:
        now = _now()
        surface = getattr(item.surface, "value", item.surface)
        for label, value in matches:
            fp = fingerprint(tenant_id, value)
            prior = (db.query(SecretSighting)
                       .filter(SecretSighting.tenant_id == tenant_id, SecretSighting.secret_fp == fp,
                               SecretSighting.finding_id == finding_id).first())
            if prior is not None:
                # A recurrence folds into the same finding, but it is a fresh sighting: the
                # value was sent again, which is exactly what a rotation watch must see.
                prior.seen_at = now
                continue
            db.add(SecretSighting(tenant_id=tenant_id, secret_fp=fp, label=label[:64],
                                  finding_id=finding_id, actor=(item.sender or "")[:320],
                                  surface=(surface or "")[:32], channel=(item.channel or "")[:64],
                                  seen_at=now))
            added += 1
        db.commit()
    except Exception:
        db.rollback()
        return 0
    return added


def rotation_status(rot: SecretRotation | None, last_seen: datetime | None, now: datetime | None = None) -> dict:
    """What the rotation record says: none, watching (rotated, waiting for the old value
    to stay gone), verified (not seen for VERIFY_AFTER since the rotation), or still_seen
    (seen after the rotation: the rotation did not take, or a copy is still in use)."""
    now = now or _now()
    if rot is None:
        return {"status": "none"}
    base = {"status": "watching", "rotated_at": rot.rotated_at.isoformat() if rot.rotated_at else None,
            "rotated_by": rot.rotated_by or "", "note": rot.note or "",
            "verified_at": rot.verified_at.isoformat() if rot.verified_at else None}
    if last_seen and rot.rotated_at and last_seen > rot.rotated_at:
        return {**base, "status": "still_seen", "last_seen_after": last_seen.isoformat()}
    if rot.verified_at:
        return {**base, "status": "verified"}
    if rot.rotated_at and now - rot.rotated_at >= VERIFY_AFTER:
        return {**base, "status": "verified", "verified_at": (rot.rotated_at + VERIFY_AFTER).isoformat()}
    due = (rot.rotated_at + VERIFY_AFTER).isoformat() if rot.rotated_at else None
    return {**base, "verify_due": due}


def travel(db: Session, tenant_id: int, fp: str, days: int = 90, now: datetime | None = None) -> dict:
    """Everywhere one secret has been seen in the window: counts, people, tools, findings,
    and the rotation status."""
    now = now or _now()
    since = now - timedelta(days=days)
    rows = (db.query(SecretSighting)
              .filter(SecretSighting.tenant_id == tenant_id, SecretSighting.secret_fp == fp,
                      SecretSighting.seen_at >= since)
              .order_by(SecretSighting.seen_at.desc()).limit(500).all())
    rot = (db.query(SecretRotation)
             .filter(SecretRotation.tenant_id == tenant_id, SecretRotation.secret_fp == fp).one_or_none())
    last_seen = rows[0].seen_at if rows else None
    status = rotation_status(rot, last_seen, now)
    if rot is not None and status["status"] == "verified" and rot.verified_at is None:
        rot.verified_at = now
        db.commit()
    return {
        "secret": fp, "label": (rows[0].label if rows else (rot.label if rot else "")),
        "sightings": len(rows),
        "first_seen": rows[-1].seen_at.isoformat() if rows else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "actors": sorted({r.actor for r in rows if r.actor}),
        "tools": sorted({f"{r.surface}/{r.channel}" if r.channel else r.surface for r in rows}),
        "findings": sorted({r.finding_id for r in rows}, reverse=True)[:20],
        "rotation": status,
    }


def for_finding(db: Session, tenant_id: int, finding_id: int, now: datetime | None = None) -> list[dict]:
    fps = [fp for (fp,) in (db.query(SecretSighting.secret_fp)
                              .filter(SecretSighting.tenant_id == tenant_id,
                                      SecretSighting.finding_id == finding_id).distinct())]
    return [travel(db, tenant_id, fp, now=now) for fp in fps]


def mark_rotated(db: Session, tenant_id: int, fp: str, by: str, note: str = "",
                 now: datetime | None = None) -> SecretRotation:
    now = now or _now()
    rot = (db.query(SecretRotation)
             .filter(SecretRotation.tenant_id == tenant_id, SecretRotation.secret_fp == fp).one_or_none())
    label = (db.query(SecretSighting.label)
               .filter(SecretSighting.tenant_id == tenant_id, SecretSighting.secret_fp == fp)
               .order_by(SecretSighting.seen_at.desc()).first())
    if rot is None:
        rot = SecretRotation(tenant_id=tenant_id, secret_fp=fp, label=(label[0] if label else ""))
        db.add(rot)
    rot.rotated_at, rot.rotated_by, rot.note, rot.verified_at = now, (by or "")[:320], (note or "")[:500], None
    db.commit()
    db.refresh(rot)
    return rot


def rotations(db: Session, tenant_id: int, now: datetime | None = None) -> list[dict]:
    """Every rotation on record, with its current status, newest first."""
    now = now or _now()
    out = []
    for rot in (db.query(SecretRotation).filter(SecretRotation.tenant_id == tenant_id)
                  .order_by(SecretRotation.rotated_at.desc()).limit(200).all()):
        last = (db.query(func.max(SecretSighting.seen_at))
                  .filter(SecretSighting.tenant_id == tenant_id,
                          SecretSighting.secret_fp == rot.secret_fp).scalar())
        status = rotation_status(rot, last, now)
        if status["status"] == "verified" and rot.verified_at is None:
            rot.verified_at = now
            db.commit()
        out.append({"secret": rot.secret_fp, "label": rot.label or "", **status,
                    "last_seen": last.isoformat() if last else None})
    return out
