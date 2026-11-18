"""Shared bounded background dispatcher for fire-and-forget work that is allowed to drop.

SIEM pushes and real-time alerts do not come through here anymore: capture writes an
outbox row (app/outbox.py) and a lifespan loop delivers it with retries. This pool is
what is left for work that is still best-effort (email sends, the S3 event archive
flush). When it is saturated, extra jobs are dropped rather than piling up, and that
drop is counted. It must never add latency to, or take down, the request path.
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from .config import _env

log = logging.getLogger("uvicorn.error")

_MAX_WORKERS = max(1, int(_env("PALIVANE_DISPATCH_WORKERS", "8")))
_MAX_PENDING = max(1, int(_env("PALIVANE_DISPATCH_QUEUE", "256")))
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="palivane-dispatch")
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
        _count_drop()
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
        _count_drop()
        log.debug("dispatch dropped a background job: %s", e)


def _count_drop() -> None:
    """Make shedding observable (palivane_dispatch_dropped_total) — dropping under
    overload is the designed trade, but it must show up on a dashboard, not vanish."""
    try:
        from . import metrics
        metrics.DISPATCH_DROPPED.inc()
    except Exception:
        pass
