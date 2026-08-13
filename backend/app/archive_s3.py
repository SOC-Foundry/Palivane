"""Raw event archival to S3 — the audit-trail complement to the findings feed in siem_s3.py.

Where siem_s3 delivers severity-gated FINDINGS one object at a time, this sink archives
EVERY analyzed event (benign included) so a tenant's data lake holds the complete capture
record. Volume is orders of magnitude higher than findings, so events are buffered per
tenant and flushed as NDJSON micro-batches (size- or age-triggered) under
<prefix>/<naming>/events/YYYY/MM/DD/HH/<ts>-<rand>.ndjson — hour-partitioned for
Athena/Panther/Snowflake external tables.

Content policy: prompt prose ships REDACTED (same redact_text as stored findings) unless
the org explicitly opts into raw (archive_s3_raw_content). Signals/evidence are already
redacted upstream — they go through unchanged, same as the SIEM sinks.

Delivery is best-effort and must never block or break the capture path: puts run on the
shared bounded dispatch pool, a saturated pool drops the batch, and a per-tenant daily
byte budget (cost guard — these puts are GCP→AWS internet egress) drops the overflow.
Unlike the findings sinks, failures are LOGGED (an archive silently losing data defeats
its purpose) and counted in stats(). The in-memory buffer means an abrupt instance kill
can lose up to one flush window; the lifespan hook flushes synchronously on clean
shutdown (Cloud Run sends SIGTERM with a grace period).
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid

from .config import settings
from .siem_s3 import _client

log = logging.getLogger("uvicorn.error")

_lock = threading.Lock()
# tenant_id -> {"cfg": (bucket, prefix, region, key_id, secret, naming),
#               "lines": [bytes], "bytes": int, "first": monotonic}
_buffers: dict[int, dict] = {}
# (tenant_id, "YYYY-MM-DD") -> bytes archived today (per-instance, so approximate under
# horizontal scale — a cost guard, not an exact meter).
_daily: dict[tuple[int, str], int] = {}
_stats = {"events": 0, "batches": 0, "dropped_cap": 0, "dropped_overflow": 0, "put_failures": 0}
_flusher_started = False


def stats() -> dict:
    return dict(_stats)


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _event_key(prefix: str, naming: str) -> str:
    p = (prefix or "").strip().strip("/")
    hour = time.strftime("%Y/%m/%d/%H", time.gmtime())
    uid = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
    base = f"{naming}/events/{hour}/{uid}.ndjson"
    return f"{p}/{base}" if p else base


def _put_batch(cfg: tuple, body: bytes, count: int, tid: int = 0) -> None:
    from . import sink_health
    bucket, prefix, region, key_id, secret, naming = cfg
    try:
        s3 = _client(region, key_id, secret)
        s3.put_object(Bucket=bucket, Key=_event_key(prefix, naming), Body=body,
                      ContentType="application/x-ndjson")
        _stats["batches"] += 1
        sink_health.record(tid, "archive_s3", True)
    except Exception as e:
        _stats["put_failures"] += 1
        sink_health.record(tid, "archive_s3", False, str(e)[:300])
        log.warning("event archive: S3 put of %d event(s) to %s failed: %s",
                    count, bucket, str(e)[:200])


def _pop_locked(tid: int) -> tuple[tuple, bytes, int, int] | None:
    """Detach a tenant's pending batch (caller holds _lock)."""
    buf = _buffers.pop(tid, None)
    if not buf or not buf["lines"]:
        return None
    return buf["cfg"], b"\n".join(buf["lines"]) + b"\n", len(buf["lines"]), tid


def _flusher() -> None:
    """Age out buffers that haven't hit the size threshold (daemon; ticks every second)."""
    while True:
        time.sleep(1)
        try:
            due = []
            with _lock:
                for tid, buf in list(_buffers.items()):
                    if time.monotonic() - buf["first"] >= max(1, settings.archive_flush_secs):
                        batch = _pop_locked(tid)
                        if batch:
                            due.append(batch)
            for cfg, body, count, tid in due:
                _submit(cfg, body, count, tid)
        except Exception as e:                      # the flusher must never die
            log.warning("event archive flusher: %s", e)


def _submit(cfg: tuple, body: bytes, count: int, tid: int = 0) -> None:
    from .dispatch import submit
    submit(_put_batch, cfg, body, count, tid)


def _ensure_flusher() -> None:
    global _flusher_started
    if not _flusher_started:
        with _lock:
            if not _flusher_started:
                threading.Thread(target=_flusher, name="palivane-archive-flush",
                                 daemon=True).start()
                _flusher_started = True


def _over_daily_cap(tenant, tid: int, nbytes: int) -> bool:
    """Track today's bytes for this tenant (per instance); True once the budget is spent.
    0 on the tenant column = the global default; the counter resets at UTC midnight."""
    cap_mb = getattr(tenant, "archive_s3_daily_mb", 0) or settings.archive_daily_mb
    if cap_mb <= 0:                                  # 0/negative global = uncapped
        return False
    today = time.strftime("%Y-%m-%d", time.gmtime())
    for k in [k for k in _daily if k[1] != today]:   # new day: drop stale counters
        _daily.pop(k, None)
    spent = _daily.get((tid, today), 0)
    if spent + nbytes > cap_mb * 1024 * 1024:
        return True
    _daily[(tid, today)] = spent + nbytes
    return False


def archive(tenant, item, result: dict, agent: str = "") -> None:
    """Buffer one analyzed event for the tenant's S3 archive. No-op unless the tenant has
    the archive enabled AND the shared S3 sink fully configured. Never raises."""
    try:
        if tenant is None or not getattr(tenant, "archive_s3_enabled", False):
            return
        from .crypto import unseal
        bucket = (tenant.siem_s3_bucket or "").strip()
        key_id = (tenant.siem_s3_key_id or "").strip()
        secret = unseal((tenant.siem_s3_secret or "").strip())
        if not (bucket and key_id and secret):
            return
        raw = bool(getattr(tenant, "archive_s3_raw_content", False))
        content = item.content or ""
        if content and not raw:
            from .redaction import redact_text
            content = redact_text(content)
        line = json.dumps({
            "schema": 1,
            "ts": _iso_now(),
            "event": "capture",
            "org": tenant.slug or "",
            "surface": item.surface.value,
            "channel": item.channel,
            "actor": item.sender or "",
            "agent": agent or "",
            "subject": item.subject or "",
            "severity": result.get("severity", ""),
            "risk_score": result.get("risk_score", 0),
            "signals": result.get("signals", []),
            "content": content,
            "content_redacted": not raw,
        }, separators=(",", ":")).encode()
        if _over_daily_cap(tenant, tenant.id, len(line) + 1):
            _stats["dropped_cap"] += 1
            return
        cfg = (bucket, tenant.siem_s3_prefix or "", tenant.siem_s3_region or "",
               key_id, secret, tenant.siem_naming or "warden")
        flush_bytes = max(1, settings.archive_flush_kb) * 1024
        ready = None
        with _lock:
            buf = _buffers.get(tenant.id)
            if buf is None:
                buf = _buffers[tenant.id] = {"cfg": cfg, "lines": [], "bytes": 0,
                                             "first": time.monotonic()}
            buf["cfg"] = cfg                         # latest settings win for the batch
            buf["lines"].append(line)
            buf["bytes"] += len(line) + 1
            _stats["events"] += 1
            if buf["bytes"] >= flush_bytes:
                ready = _pop_locked(tenant.id)
        if ready:
            _submit(*ready)
        _ensure_flusher()
    except Exception as e:                           # archival is additive — never sink analysis
        log.warning("event archive: %s", e)


def flush_all() -> None:
    """Synchronously drain every pending buffer — the clean-shutdown path (lifespan), so
    a scale-to-zero instance ships its tail within the SIGTERM grace period."""
    with _lock:
        batches = [b for b in (_pop_locked(tid) for tid in list(_buffers)) if b]
    for cfg, body, count, tid in batches:
        _put_batch(cfg, body, count, tid)


def test(bucket: str, prefix: str, region: str, key_id: str, secret: str,
         naming: str = "warden") -> tuple[bool, str]:
    """Synchronously write one sample events object so the console can validate the path
    (and the customer can point an Athena/Panther table at it)."""
    if not (bucket and key_id and secret):
        return False, "bucket + AWS key id + secret are required"
    line = json.dumps({"schema": 1, "ts": _iso_now(), "event": "test", "org": "",
                       "surface": "test", "channel": "test", "actor": "palivane",
                       "agent": "", "subject": "Palivane event-archive test", "severity": "low",
                       "risk_score": 0, "signals": [], "content": "", "content_redacted": True},
                      separators=(",", ":")).encode()
    try:
        s3 = _client(region, key_id, secret)
        s3.put_object(Bucket=bucket, Key=_event_key(prefix, naming), Body=line + b"\n",
                      ContentType="application/x-ndjson")
        return True, ""
    except Exception as e:
        return False, str(e)[:300]
