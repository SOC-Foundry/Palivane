"""Scheduled connector scans: a platform that sets `schedule_secs` in saas_connectors.PLATFORMS
(GitHub secret scanning) syncs on its own, so "scanning constantly" does not depend on an admin
clicking Scan now.

Every instance runs the loop and any of them may find a connector due, so a scan is CLAIMED with a
conditional update of last_sync_at (the same pattern the alert digests use): only the instance whose
update matches goes on to scan, the others see it already claimed. A scan that ran out of budget
(`truncated`) is due again in a few minutes, so a big first pass catches up without waiting an hour;
a clean one waits its interval. A failed one is recorded by sync_connector and tried again at the
next interval, so a revoked token does not hammer the API.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import or_

from . import github_secrets
from .config import settings

log = logging.getLogger("palivane.connector_schedule")

CATCH_UP_SECS = 300      # a scan that stopped at its budget resumes this soon
MAX_PER_TICK = 3         # connectors scanned per loop tick, so one tick stays short
SCAN_MAX_SECS = 480.0    # one scheduled scan stops here (an admin's Scan now gets far less: it is a request)


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
    """True for exactly one caller: the one whose conditional update of last_sync_at matches."""
    from .models import SaasConnector
    n = (db.query(SaasConnector)
         .filter(SaasConnector.id == connector_id, SaasConnector.active.is_(True),
                 or_(SaasConnector.last_sync_at.is_(None), SaasConnector.last_sync_at <= cutoff))
         .update({SaasConnector.last_sync_at: now}, synchronize_session=False))
    db.commit()
    return n == 1


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
            continue                                  # another instance took it
        ran += 1
        limit_token = github_secrets.max_seconds.set(SCAN_MAX_SECS)
        try:
            bind_tenant(db, tenant_id)                # the same isolation an admin-triggered sync has
            db.expire_all()
            fresh = db.get(SaasConnector, cid)
            summary = sync_connector(db, fresh)
            if summary.get("truncated"):
                # more to read: due again soon, not an interval from now
                fresh.last_sync_at = now - timedelta(seconds=max(0, interval - CATCH_UP_SECS))
                db.commit()
        except ConnectorError:
            pass                                      # sync_connector recorded the error on the row
        except Exception:                             # noqa: BLE001  one connector must not stop the rest
            db.rollback()
            log.warning("scheduled scan of connector %s failed", cid, exc_info=True)
        finally:
            github_secrets.max_seconds.reset(limit_token)
            clear_tenant()
    return ran
