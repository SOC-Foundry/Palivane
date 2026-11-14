"""The canary: a secret that is only ever a self-test.

Every install ends with the same question: is anything actually reaching the console? The
answer used to be "paste a fake key into Claude and look". This makes it one command.
Each org has a canary value, derived from the app secret and the tenant id (no table, no
rotation to manage), that the detection engine recognises as a secret format of its own.
`palivane-hook selftest` fetches it with the device's capture key, sends it through the real
ingest path exactly as a typed prompt would go, and prints the verdict. A browser or proxy
install is tested the same way by pasting the value into any AI site: it is a secret as far
as every sensor is concerned.

A canary finding is a real finding, recorded with the device, the tool and the time, so the
console can say when the first one arrived and how long after the first capture key was
minted: time to first finding, measured, not promised. It is reviewed on arrival as
dismissed/expected by "self-test canary", so it never sits in the queue, never opens an
exposure and never counts against precision as a false positive: the detector was right.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import ApiKey, Finding

PREFIX = "pvcanary_"
RE = re.compile(r"pvcanary_[0-9a-f]{24}")
BY = "self-test canary"


def value(tenant_id: int) -> str:
    from .security import _secret
    key = hmac.new(_secret(), b"palivane-canary", hashlib.sha256).digest()
    return PREFIX + hmac.new(key, str(tenant_id).encode(), hashlib.sha256).hexdigest()[:24]


def contains(tenant_id: int | None, text: str | None) -> bool:
    if tenant_id is None or not text or PREFIX not in text:
        return False
    return value(tenant_id) in text


def review(finding: Finding) -> None:
    """Dismissed, expected, by the canary itself: the detection was right and the org asked
    for it. Recorded, not dropped, so Fleet, the self-test status and precision all see it."""
    from . import review as review_mod
    finding.status = "dismissed"
    review_mod.record_review(finding, "dismissed", BY, "bulk", "expected")


def status(db: Session, tenant_id: int) -> dict:
    """What the self-test has shown so far: the canary findings, first and last, and how
    long the first one took after the org's first capture key existed."""
    q = (db.query(Finding).filter(Finding.tenant_id == tenant_id, Finding.reviewed_by == BY)
           .order_by(Finding.created_at.asc()))
    rows = q.limit(500).all()
    first_key = (db.query(ApiKey.created_at).filter(ApiKey.tenant_id == tenant_id)
                   .order_by(ApiKey.created_at.asc()).first())
    first_key_at = first_key[0] if first_key else None

    def one(f: Finding) -> dict:
        return {"finding_id": f.id, "at": f.created_at.isoformat() if f.created_at else None,
                "sender": f.sender or "", "channel": f.channel or "", "surface": f.surface or "",
                "severity": f.severity, "action": f.recommended_action or ""}
    first = rows[0] if rows else None
    minutes = None
    if first is not None and first.created_at and first_key_at:
        minutes = max(0.0, round((first.created_at - first_key_at).total_seconds() / 60, 1))
    return {
        "count": len(rows),
        "first": one(first) if first else None,
        "last": one(rows[-1]) if rows else None,
        "first_key_at": first_key_at.isoformat() if first_key_at else None,
        "minutes_to_first_finding": minutes,
        "checked_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
    }
