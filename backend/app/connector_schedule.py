"""Scheduled connector scans: a platform that sets `schedule_secs` in saas_connectors.PLATFORMS
(GitHub secret scanning) syncs on its own, so "scanning constantly" does not depend on an admin
clicking Scan now.

Every instance runs the loop and any of them may find a connector due, so a scan is CLAIMED with a
conditional update of sync_claimed_at (the same pattern the alert digests use): only the instance whose
update matches goes on to scan, the others see it already claimed. last_sync_at is when the last scan
finished; it is written by the scan that holds the claim, when it finishes, and by no one else. A scan that ran out of budget
(`truncated`) is due again in a few minutes, so a big first pass catches up without waiting an hour;
a clean one waits its interval. A failed one is recorded by sync_connector and tried again at the
next interval, so a revoked token does not hammer the API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from . import github_secrets
from .config import settings

log = logging.getLogger("palivane.connector_schedule")

CATCH_UP_SECS = 300      # a scan that stopped at its budget resumes this soon
MAX_PER_TICK = 3         # connectors scanned per loop tick, so one tick stays short
# One scheduled scan stops here (an admin's Scan now gets far less: it is a request). This is
# longer than the shortest interval (5 minutes), which is safe because an interval is counted
# from when the last scan FINISHED, and a scan holds a claim (sync_claimed_at, kept for
# saas_connectors.SYNC_CLAIM_SECS, longer than this) that no other instance can take while it
# runs. Before #298 the claim and the finish time were the same column, so a second instance
# could claim a connector mid-scan and the slower commit wrote an older time and cursor back.
SCAN_MAX_SECS = 480.0


def _interval(db, row, spec: dict) -> int:
    """How often this connector scans: the platform's default, or what the connector itself asks for."""
    default = int(spec["schedule_secs"])
    pick = spec.get("interval_for")
    if not pick:
        return default
    try:
        from .saas_connectors import read_credentials
        return int(pick(read_credentials(row, db), default))
    except Exception:                                 # noqa: BLE001  an unreadable credential keeps the default
        return default


def _claim(db, connector_id: int, now: datetime, cutoff: datetime) -> bool:
    """True for exactly one caller: the one whose conditional update of the claim matches, and only
    while the connector is due (it last finished at or before `cutoff`)."""
    from .saas_connectors import claim_sync
    return claim_sync(db, connector_id, now, due_before=cutoff)


def _resume_at(summary: dict) -> datetime | None:
    """When the platform said the scan may go on (a rate limit's reset), if the scan recorded it."""
    raw = str(summary.get("resume_after") or "")
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ") if raw else None
    except ValueError:
        return None


def _stamp_for(interval: int):
    """The last_sync_at to record for a finished scan. A clean one records when it finished and
    waits its interval. One that stopped at its budget is recorded as if it had finished earlier,
    so it comes due again CATCH_UP_SECS after it finished (not an interval later), or, when it
    stopped at a rate limit whose reset GitHub named, at that reset: scanning before it would only
    be refused again. Never later than an ordinary interval."""
    def stamp(summary: dict, finished: datetime) -> datetime:
        if not summary.get("truncated"):
            return finished
        due = finished + timedelta(seconds=CATCH_UP_SECS)
        resume = _resume_at(summary)
        if resume is not None:
            due = min(max(due, resume), finished + timedelta(seconds=interval))
        return due - timedelta(seconds=interval)
    return stamp


def run_scheduled_scans(db, now: datetime | None = None, limit: int = MAX_PER_TICK) -> int:
    """Scan the connectors that are due. Returns how many were scanned."""
    if not settings.connector_schedule:
        return 0
    from .database import bind_tenant, clear_tenant
    from .models import SaasConnector
    from .saas_connectors import PLATFORMS, ConnectorError, sync_connector
    now = now or datetime.utcnow()
    scheduled = {k: v for k, v in PLATFORMS.items() if v.get("schedule_secs")}
    if not scheduled:
        return 0
    rows = (db.query(SaasConnector)
            .filter(SaasConnector.active.is_(True), SaasConnector.platform.in_(list(scheduled)))
            .order_by(SaasConnector.last_sync_at.is_(None).desc(), SaasConnector.last_sync_at).all())
    ran = 0
    for row in rows:
        if ran >= limit:
            break
        interval = _interval(db, row, scheduled[row.platform])
        cutoff = now - timedelta(seconds=interval)
        if row.last_sync_at is not None and row.last_sync_at > cutoff:
            continue
        cid, tenant_id = row.id, row.tenant_id
        if not _claim(db, cid, now, cutoff):
            continue                                  # another instance has it, or it just finished
        ran += 1
        limit_token = github_secrets.max_seconds.set(SCAN_MAX_SECS)
        try:
            bind_tenant(db, tenant_id)                # the same isolation an admin-triggered sync has
            db.expire_all()
            fresh = db.get(SaasConnector, cid)
            # sync_connector writes last_sync_at, the status and the cursor when the scan finishes,
            # and only while this claim is still the connector's (saas_connectors._finish_sync).
            sync_connector(db, fresh, claimed_at=now, stamp=_stamp_for(interval))
        except ConnectorError:
            pass                                      # sync_connector recorded the error on the row
        except Exception:                             # noqa: BLE001  one connector must not stop the rest
            db.rollback()
            log.warning("scheduled scan of connector %s failed", cid, exc_info=True)
        finally:
            github_secrets.max_seconds.reset(limit_token)
            clear_tenant()
    return ran
