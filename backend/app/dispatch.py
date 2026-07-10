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
from concurrent.futures import ThreadPoolExecutor
from queue import Full

log = logging.getLogger("uvicorn.error")

_MAX_WORKERS = max(1, int(os.getenv("WARDEN_DISPATCH_WORKERS", "8")))
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="warden-dispatch")


def submit(fn, *args, **kwargs) -> None:
    """Run fn(*args) on the shared pool; drop (with a debug log) if the pool is saturated.
    Never raises — a delivery backlog can't break the request path."""
    try:
        _executor.submit(fn, *args, **kwargs)
    except (Full, RuntimeError) as e:   # queue full / interpreter shutting down
        log.debug("dispatch dropped a background job: %s", e)
    except Exception as e:              # never let delivery scheduling break capture
        log.debug("dispatch error: %s", e)
