"""Shared bounded background dispatcher for fire-and-forget delivery (alerts, SIEM).

Previously each finding spawned a raw daemon thread per sink — a finding storm (e.g. a
10k-item scan with a slow/dead webhook) could create tens of thousands of threads and
exhaust the worker. This routes those sends through one small, bounded thread pool with a
capped queue: when saturated, extra jobs are dropped rather than piling up. Delivery is
best-effort telemetry, so dropping under overload is the right trade — it must never add
latency to, or take down, the capture path.
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("uvicorn.error")

_MAX_WORKERS = max(1, int(os.getenv("WARDEN_DISPATCH_WORKERS", "8")))
_MAX_PENDING = max(1, int(os.getenv("WARDEN_DISPATCH_QUEUE", "256")))
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="warden-dispatch")
# ThreadPoolExecutor's internal work queue is unbounded, so the real cap is this
# semaphore: running + queued jobs may never exceed workers + _MAX_PENDING.
_slots = threading.BoundedSemaphore(_MAX_WORKERS + _MAX_PENDING)


def submit(fn, *args, **kwargs) -> None:
    """Run fn(*args) on the shared pool; drop (with a debug log) if the pool is saturated.
    Never raises — a delivery backlog can't break the request path."""
    if not _slots.acquire(blocking=False):
        log.debug("dispatch dropped a background job: %d jobs already pending",
                  _MAX_WORKERS + _MAX_PENDING)
        return

    def _run():
        try:
            fn(*args, **kwargs)
        finally:
            _slots.release()

    try:
        _executor.submit(_run)
    except Exception as e:              # interpreter shutting down, or anything else —
        _slots.release()                # never let delivery scheduling break capture
        log.debug("dispatch dropped a background job: %s", e)
