"""Who reviewed a finding, how, and why: the record the precision readout is built on.

`status` alone cannot say. `dismissed` is a false positive, or behavior the org expects, or a queue
somebody cleared; `triaged` is an analyst confirming a finding, or the person it belongs to having
answered it. A precision number computed from `status` would be wrong in both directions, so every
review writes four more fields, and a reopen clears them:

  reviewed_at / reviewed_by   when, and which person
  review_via                  manual  one person, one finding
                              analyst a person applying the AI analyst's recommendation
                              bulk    one action on many findings: not a judgement of each
  review_reason               dismissed only: false_positive | expected | accepted_risk | duplicate

Deliberately free of imports from the rest of the app, so the places that change a status
(the console endpoints, the recurrence reopen in service.py) can all use it.
"""
from __future__ import annotations

from datetime import datetime, timezone

# Why a finding was dismissed. Only `false_positive` says the DETECTOR was wrong: `expected` and
# `accepted_risk` are real detections of something the org is fine with (an allowlist entry or a
# policy change, not a detector fix), and `duplicate` is neither.
REASONS = ("false_positive", "expected", "accepted_risk", "duplicate")
VIAS = ("manual", "analyst", "bulk")

_COLUMNS = ("reviewed_at", "reviewed_by", "review_via", "review_reason")


def review_values(status: str, by: str = "", via: str = "manual", reason: str = "",
                  now: datetime | None = None) -> dict:
    """The review fields to write for a status change: a record of the review for `triaged` and
    `dismissed`, and a clean slate for `open` (a reopened finding has not been reviewed)."""
    if status in ("triaged", "dismissed"):
        return {"reviewed_at": now or datetime.now(timezone.utc).replace(tzinfo=None),
                "reviewed_by": (by or "")[:320],
                "review_via": via if via in VIAS else "manual",
                "review_reason": reason if status == "dismissed" and reason in REASONS else ""}
    return {"reviewed_at": None, "reviewed_by": "", "review_via": "", "review_reason": ""}


def record_review(row, status: str, by: str = "", via: str = "manual", reason: str = "") -> None:
    """Set the review fields on a Finding row."""
    for key, value in review_values(status, by, via, reason).items():
        setattr(row, key, value)


def review_update(model, status: str, by: str = "", via: str = "manual", reason: str = "") -> dict:
    """The same, as a `{Column: value}` mapping for `query.update(...)`, plus the status itself."""
    values = {getattr(model, "status"): status}
    for key, value in review_values(status, by, via, reason).items():
        values[getattr(model, key)] = value
    return values
