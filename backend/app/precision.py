"""Detection precision: when a check fires, is it right, according to the people who reviewed it?

The honest version of "how often are you wrong" needs more than `status`. A dismissed finding is
a false positive, or behavior the org expects, or part of a queue somebody cleared; a triaged one is
an analyst confirming it, or its owner having answered. So this reads the review record
(app/review.py) and says only what it supports:

  needed action    a person triaged it                              the detection was right
  expected         dismissed as expected / accepted risk            right, and the org is fine with it:
                                                                    an allowlist entry or a policy change
  false positive   dismissed as a false positive                    the detector was wrong
  no reason        dismissed with no reason given                   could be either: reported as a range
  duplicate        dismissed as a duplicate                         not counted either way

Only reviews made by one person on one finding count (`manual`, and `analyst` where a person applied
the AI analyst's recommendation). Findings closed in bulk, and ones reviewed before the record
existed or answered only by their owner, are counted and shown, and kept out of every rate: a
"clear the queue" is not a judgement of each finding, and dividing by it would make every check look
like noise.

Read it by finding (one row is one distinct event class) with the events behind it alongside: a
false positive that fired 300 times is one finding and 300 events.
"""

from __future__ import annotations

import csv
import io
import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import require_admin
from .database import get_db
from .models import Finding, User
from .review import REASONS

router = APIRouter(prefix="/api", tags=["precision"])

MAX_ROWS = 20_000          # per query, like the other analytics: a bound, and the response says so
MIN_JUDGED = 5             # reviews before a check's rate is worth reading
OK_RATE = 0.6              # at least this share needing action reads as healthy
EXPECTED_SHARE = 0.4       # this much "expected" means the fix is an allowlist, not a detector
FALSE_POSITIVE_SHARE = 0.25
NO_REASON_SHARE = 0.4
NOISY_ROWS = 10

BUCKETS = ("actionable", "expected", "false_positive", "unspecified", "duplicate")

HINTS = {
    "ok": "",
    "low_sample": "Not enough reviews yet to judge.",
    "expected": ("Mostly dismissed as expected. Allow the commands or paths your team uses on "
                 "purpose, or turn the check off for the people it does not apply to."),
    "false_positives": ("Often wrong. Tell Palivane which findings were false positives so the "
                        "check can be fixed, and tune it for your org meanwhile."),
    "no_reason": ("Mostly dismissed without a reason, so it cannot be said why. Pick one when you "
                  "dismiss."),
    "mixed": "Fewer than 6 in 10 needed action.",
}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --- the arithmetic (pure) --------------------------------------------------------------------------

def bucket(status: str, reason: str) -> str:
    """Which of the five a review is. `triaged` needed action; a dismissal is what its reason says,
    and a dismissal with no (or an unknown) reason is `unspecified`."""
    if status == "triaged":
        return "actionable"
    if reason in ("expected", "accepted_risk"):
        return "expected"
    if reason == "false_positive":
        return "false_positive"
    if reason == "duplicate":
        return "duplicate"
    return "unspecified"


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    """The 95% Wilson interval for `k` of `n`: how far a rate from a handful of reviews can be
    trusted. None when there is nothing to estimate."""
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def primary(signals) -> tuple[str, str, str]:
    """The (check, title, evidence) of the signal that drove a finding: the one with the highest
    weight times confidence, which is the one the console leads with. A review judges the finding
    as a whole, so it is credited to one check rather than split across all of them."""
    best = None
    for s in signals or []:
        if not isinstance(s, dict):
            continue
        key = s.get("check") or s.get("category") or ""
        if not key:
            continue
        try:
            conf = s.get("confidence")
            score = float(s.get("weight") or 0) * float(1 if conf is None else conf)
        except (TypeError, ValueError):
            score = 0.0
        if best is None or score > best[0]:
            best = (score, key, (s.get("title") or "").strip(), (s.get("evidence") or "").strip())
    return (best[1], best[2], best[3]) if best else ("unknown", "", "")


def _tally() -> dict:
    return {"findings": 0, "events": 0, **{b: 0 for b in BUCKETS}, **{f"{b}_events": 0 for b in BUCKETS}}


def _rates(t: dict) -> dict:
    """The numbers a tally supports. Duplicates are left out of `judged`: a duplicate says nothing
    about whether the check was right."""
    judged = t["actionable"] + t["expected"] + t["false_positive"] + t["unspecified"]
    out = dict(t)
    out["judged"] = judged
    if judged:
        out["actionable_rate"] = round(t["actionable"] / judged, 3)
        out["actionable_ci"] = wilson(t["actionable"], judged)
        # What "no reason" could be: if every one was a false positive the detector was right this
        # often (low); if none was, this often (high). They meet when every dismissal has a reason.
        out["correct_low"] = round((t["actionable"] + t["expected"]) / judged, 3)
        out["correct_high"] = round((t["actionable"] + t["expected"] + t["unspecified"]) / judged, 3)
        noise_events = t["expected_events"] + t["false_positive_events"] + t["unspecified_events"]
        total_events = noise_events + t["actionable_events"]
        out["noise_event_share"] = round(noise_events / total_events, 3) if total_events else None
    else:
        out.update(actionable_rate=None, actionable_ci=None, correct_low=None, correct_high=None,
                   noise_event_share=None)
    out["verdict"], out["hint"] = verdict(out)
    return out


def verdict(t: dict) -> tuple[str, str]:
    """A one-word reading of a check and what to do about it."""
    j = t["judged"]
    if j < MIN_JUDGED:
        return "low_sample", HINTS["low_sample"]
    if t["actionable_rate"] >= OK_RATE:
        return "ok", HINTS["ok"]
    if t["expected"] / j >= EXPECTED_SHARE:
        return "expected", HINTS["expected"]
    if t["false_positive"] / j >= FALSE_POSITIVE_SHARE:
        return "false_positives", HINTS["false_positives"]
    if t["unspecified"] / j >= NO_REASON_SHARE:
        return "no_reason", HINTS["no_reason"]
    return "mixed", HINTS["mixed"]


def _week(ts: datetime) -> str:
    return (ts - timedelta(days=ts.weekday())).date().isoformat()


def compute(reviews: list[dict], legacy: list[dict], backlog: dict, now: datetime, days: int,
            truncated: bool = False) -> dict:
    """The readout from plain rows. `reviews` are the findings reviewed in the window
    (`status, reason, via, reviewed_at, events, signals, channel, sender, id`), `legacy` the
    triaged/dismissed ones with no review record (`status, answered`), `backlog` what is still open."""
    since = now - timedelta(days=days)
    overall, bulk = _tally(), {"findings": 0, "events": 0}
    by_check: dict[str, dict] = {}
    titles: dict[str, str] = {}
    by_tool: dict[str, dict] = {}
    weeks: dict[str, dict] = {}
    noisy: list[dict] = []
    via_analyst = 0

    # every week in the window, so an empty one is a gap the chart shows rather than hides
    w = since - timedelta(days=since.weekday())
    while w <= now:
        weeks[w.date().isoformat()] = _tally()
        w += timedelta(days=7)

    for r in reviews:
        events = max(int(r.get("events") or 1), 1)
        if r.get("via") == "bulk":
            bulk["findings"] += 1
            bulk["events"] += events
            continue
        b = bucket(r["status"], r.get("reason") or "")
        check, title, evidence = primary(r.get("signals"))
        titles.setdefault(check, title)
        via_analyst += r.get("via") == "analyst"
        targets = [overall,
                   by_check.setdefault(check, _tally()),
                   by_tool.setdefault(r.get("channel") or "(none)", _tally())]
        wk = r.get("reviewed_at")
        if wk is not None:
            targets.append(weeks.setdefault(_week(wk), _tally()))
        for t in targets:
            t["findings"] += 1
            t["events"] += events
            t[b] += 1
            t[f"{b}_events"] += events
        if r["status"] == "dismissed" and b != "duplicate" and events >= 2:
            noisy.append({"id": r.get("id"), "check": check, "title": title, "evidence": evidence,
                          "channel": r.get("channel") or "", "sender": r.get("sender") or "",
                          "events": events, "reason": r.get("reason") or "",
                          "reviewed_at": wk.isoformat() if wk else None})

    checks = []
    for key, t in by_check.items():
        row = _rates(t)
        row.update(check=key, title=titles.get(key, ""))
        checks.append(row)
    # the checks that most need attention first: the least often right, among those with a sample
    checks.sort(key=lambda c: (c["verdict"] == "low_sample",
                               c["actionable_rate"] if c["actionable_rate"] is not None else 2.0,
                               -c["judged"]))
    tools = []
    for key, t in by_tool.items():
        row = _rates(t)
        row["tool"] = key
        tools.append(row)
    tools.sort(key=lambda c: -c["judged"])
    noisy.sort(key=lambda n: -n["events"])

    owner = sum(1 for r in legacy if r.get("answered") and r.get("status") == "triaged")
    return {
        "days": days, "since": since.isoformat(), "generated_at": now.isoformat(),
        "truncated": truncated,
        "reviewed": {**_rates(overall), "via_analyst": via_analyst},
        "bulk": bulk,
        "not_counted": {"answered_by_owner": owner, "before_tracking": len(legacy) - owner},
        "backlog": backlog,
        "checks": checks,
        "tools": tools[:10],
        "trend": [{"week": k, **_rates(v)} for k, v in sorted(weeks.items())],
        "recurring_noise": noisy[:NOISY_ROWS],
        "limits": {"min_judged": MIN_JUDGED, "reasons": list(REASONS)},
    }


# --- the endpoint ------------------------------------------------------------------------------------

def readout(db: Session, tenant_id: int, days: int, now: datetime | None = None) -> dict:
    now = now or _now()
    days = max(1, min(int(days), 365))
    since = now - timedelta(days=days)
    cols = (Finding.id, Finding.status, Finding.review_reason, Finding.review_via,
            Finding.reviewed_at, Finding.seen_count, Finding.signals, Finding.channel, Finding.sender)
    rows = (db.query(*cols)
              .filter(Finding.tenant_id == tenant_id, Finding.reviewed_at >= since,
                      Finding.status.in_(("triaged", "dismissed")))
              .order_by(Finding.reviewed_at.desc()).limit(MAX_ROWS + 1).all())
    truncated = len(rows) > MAX_ROWS
    reviews = [{"id": r[0], "status": r[1], "reason": r[2] or "", "via": r[3] or "",
                "reviewed_at": r[4], "events": r[5] or 1, "signals": r[6], "channel": r[7],
                "sender": r[8]} for r in rows[:MAX_ROWS]]
    old = (db.query(Finding.status, Finding.owner_response)
             .filter(Finding.tenant_id == tenant_id, Finding.reviewed_at.is_(None),
                     Finding.status.in_(("triaged", "dismissed")))
             .limit(MAX_ROWS).all())
    legacy = [{"status": s, "answered": bool(o)} for s, o in old]
    open_q = db.query(Finding).filter(Finding.tenant_id == tenant_id, Finding.status == "open")
    oldest = (db.query(func.min(Finding.created_at))
                .filter(Finding.tenant_id == tenant_id, Finding.status == "open",
                        Finding.severity.in_(("suspicious", "high", "critical"))).scalar())
    backlog = {"open": open_q.count(),
               "open_high": open_q.filter(Finding.severity.in_(("high", "critical"))).count(),
               "oldest_open_days": (now - oldest).days if oldest else None}
    return compute(reviews, legacy, backlog, now, days, truncated)


def _pct(v) -> str:
    return "" if v is None else f"{v * 100:.1f}"


def to_csv(r: dict) -> str:
    """The per-check table as CSV, with the overall row first: what goes into a pilot readout."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["scope", "check", "findings", "events", "needed_action", "expected", "false_positive",
                "no_reason", "duplicate", "judged", "needed_action_pct", "correct_low_pct",
                "correct_high_pct", "reading", f"window_days={r['days']}"])
    for scope, row in [("overall", r["reviewed"])] + [("check", c) for c in r["checks"]]:
        w.writerow([scope, row.get("check", ""), row["findings"], row["events"], row["actionable"],
                    row["expected"], row["false_positive"], row["unspecified"], row["duplicate"],
                    row["judged"], _pct(row["actionable_rate"]), _pct(row["correct_low"]),
                    _pct(row["correct_high"]), row["verdict"], ""])
    return buf.getvalue()


@router.get("/precision")
def precision(days: int = 30, format: Literal["json", "csv"] = "json",
              current: User = Depends(require_admin), db: Session = Depends(get_db)):
    """How often the findings your team reviewed were right, per check, over the last `days`
    (1 to 365). Admin only. See the module docstring for exactly what is and is not counted."""
    r = readout(db, current.tenant_id, days)
    if format == "csv":
        return Response(to_csv(r), media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="palivane-precision.csv"'})
    return r
