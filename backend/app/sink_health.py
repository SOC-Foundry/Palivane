"""Per-tenant delivery health for the out-of-band sinks (SIEM HTTP push, S3 findings,
S3 event archive).

The sinks are fire-and-forget by design — they must never block or break capture — but
"best-effort" must not mean "invisible": a tenant whose HEC token expired should see
that in Settings, not discover a month of silent data loss. Every delivery attempt is
recorded here (and counted in Prometheus); the console reads the snapshot via
GET /api/siem/status.

In-memory and per-instance, like archive_s3's daily byte counter — an observability
aid, not an exact ledger. Under horizontal scale each instance reports the deliveries
it attempted; the last-error detail is what matters and any instance seeing failures
will show them.
"""

from __future__ import annotations

import threading
import time

from . import metrics

# Sinks we track. Keys are stable API strings (the console keys on them).
SINKS = ("siem_http", "siem_s3", "archive_s3")

_lock = threading.Lock()
# (tenant_id, sink) -> {"ok": int, "failed": int, "last_ok_ts": float|None,
#                       "last_error_ts": float|None, "last_error": str}
_health: dict[tuple[int, str], dict] = {}
_MAX_ENTRIES = 4096  # tenants * sinks; on overflow just reset (rebuilds on traffic)


def record(tenant_id: int, sink: str, ok: bool, detail: str = "") -> None:
    """Count one delivery attempt. Never raises (called from delivery threads)."""
    try:
        metrics.SINK_DELIVERY.labels(sink, "ok" if ok else "error").inc()
        with _lock:
            if len(_health) >= _MAX_ENTRIES and (tenant_id, sink) not in _health:
                _health.clear()
            s = _health.setdefault((tenant_id, sink), {
                "ok": 0, "failed": 0, "last_ok_ts": None,
                "last_error_ts": None, "last_error": ""})
            if ok:
                s["ok"] += 1
                s["last_ok_ts"] = time.time()
            else:
                s["failed"] += 1
                s["last_error_ts"] = time.time()
                s["last_error"] = (detail or "delivery failed")[:300]
    except Exception:
        pass


def _iso(ts: float | None) -> str | None:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else None


def snapshot(tenant_id: int) -> dict:
    """This tenant's delivery health per sink, for the console/status endpoint."""
    out = {}
    with _lock:
        for sink in SINKS:
            s = _health.get((tenant_id, sink))
            if s is None:
                out[sink] = {"attempted": False, "ok": 0, "failed": 0,
                             "last_ok": None, "last_error_at": None, "last_error": ""}
            else:
                out[sink] = {"attempted": True, "ok": s["ok"], "failed": s["failed"],
                             "last_ok": _iso(s["last_ok_ts"]),
                             "last_error_at": _iso(s["last_error_ts"]),
                             "last_error": s["last_error"]}
    return out


def reset() -> None:
    """Test hook."""
    with _lock:
        _health.clear()
