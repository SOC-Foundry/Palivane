"""Prometheus metrics: HTTP request counts + latency, recorded by route template.

Labelling by the matched route path (e.g. /api/findings/{id}, not the concrete id) keeps
cardinality bounded. Wired as middleware in main.py; exposed at /metrics.
"""
from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

REQUESTS = Counter(
    "palivane_http_requests_total", "HTTP requests", ["method", "path", "status"],
)
LATENCY = Histogram(
    "palivane_http_request_duration_seconds", "HTTP request latency (s)", ["method", "path"],
)
# Out-of-band delivery outcomes (SIEM HTTP push / S3 findings / S3 event archive) — the
# ops-side view of what sink_health.py tracks per tenant. Labels stay low-cardinality:
# sink name + ok/error, never per-tenant.
SINK_DELIVERY = Counter(
    "palivane_sink_delivery_total", "Sink delivery attempts", ["sink", "outcome"],
)
# Background jobs dropped by the bounded dispatch pool (saturation): nonzero here means
# alert/SIEM deliveries are being shed under load.
DISPATCH_DROPPED = Counter(
    "palivane_dispatch_dropped_total", "Background delivery jobs dropped (pool saturated)",
)


def route_template(request) -> str:
    """The matched route's path template, or 'unmatched' (avoids high-cardinality labels)."""
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


def observe(method: str, path: str, status: int, duration: float) -> None:
    REQUESTS.labels(method, path, str(status)).inc()
    LATENCY.labels(method, path).observe(duration)


def exposition() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
