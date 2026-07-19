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
    # Bind the pair NOW: a job must always release the same semaphore it acquired.
    # Resolving the globals again inside _run's finally means a job outliving a swap of
    # these (tests monkeypatch them; a future reconfig could too) would release the NEW
    # semaphore — leaking a permit there while deadlocking a slot here.
    slots, executor = _slots, _executor
    if not slots.acquire(blocking=False):
        log.debug("dispatch dropped a background job: %d jobs already pending",
                  _MAX_WORKERS + _MAX_PENDING)
        return

    def _run():
        try:
            fn(*args, **kwargs)
        finally:
            slots.release()

    try:
        executor.submit(_run)
    except Exception as e:              # interpreter shutting down, or anything else —
        slots.release()                 # never let delivery scheduling break capture
        log.debug("dispatch dropped a background job: %s", e)
