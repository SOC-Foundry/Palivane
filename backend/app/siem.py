"""SIEM forwarding — push findings to a collector in a format the SIEM parses natively.

Vendor-neutral: one generic HTTP forwarder with three output shapes covers Splunk (HEC),
Microsoft Sentinel / Elastic / Sumo / Datadog (generic JSON over HTTP), and anything that
ingests CEF. The SIEM specifics (endpoint URL, token, index) are the customer's config, not
per-vendor code here. Complements the pull-based JSONL export (/api/export/findings).

Fire-and-forget on the request path (daemon thread, short timeout, SSRF-guarded) so a slow
or down collector never adds latency or breaks capture.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request

log = logging.getLogger("uvicorn.error")

_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}
# CEF severity is 0-10; map Palivane's bands onto it.
_CEF_SEV = {"benign": 0, "low": 3, "suspicious": 5, "high": 7, "critical": 9}
FORMATS = ("json", "splunk_hec", "cef")


def _fields(verdict: dict, subject: str, actor: str, surface: str, org: str) -> dict:
    from .signal_summary import top_signals
    cats = [s.get("category", "") for s in verdict.get("signals", []) if s.get("category")]
    return {
        "vendor": "Palivane", "product": "Palivane",
        "event": "finding", "severity": verdict.get("severity"),
        "risk_score": verdict.get("risk_score"), "categories": cats,
        # The concrete cause (strongest signals, redacted evidence) for programmatic consumers.
        "top_signals": top_signals(verdict.get("signals"), 3),
        "surface": surface, "subject": subject, "actor": actor,
        "finding_id": verdict.get("finding_id"), "org": org,
        # A recurrence of a finding somebody had closed. Carried so a SIEM rule can treat
        # "closed and came back" differently from a first sighting — it is a different fact.
        "reopened": bool(verdict.get("reopened")),
        "recurrence": verdict.get("recurrence") or None,
        # Content-origin lineage: the source document the leaked content came from, when
        # matched, so a SIEM correlation rule can pivot on the leaking file/owner.
        "origin": verdict.get("origin") or None,
        "ts": int(time.time()),
    }


def _cef(f: dict) -> str:
    """A CEF line: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions."""
    def esc(v):   # CEF extension value: escape \ = and newlines
        return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")
    def hesc(v):  # CEF header field: escape \ | and newlines (pipe would forge a new field)
        return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
    sig = hesc(",".join(f["categories"]) or "finding")
    name = hesc((f.get("subject") or "Palivane finding")[:120])
    header = f"CEF:0|Palivane|Palivane|1.0|{sig}|{name}|{_CEF_SEV.get(f['severity'], 5)}"
    tops = f.get("top_signals") or []
    match = "; ".join(t["title"] + (f": {t['evidence']}" if t.get("evidence") else "")
                       for t in tops[:3])
    ext = {
        "cs1Label": "surface", "cs1": f.get("surface", ""),
        "cs2Label": "categories", "cs2": ",".join(f["categories"]),
        "suser": f.get("actor") or "", "cn1Label": "risk", "cn1": f.get("risk_score", 0),
        "externalId": f.get("finding_id") or "", "cs3Label": "org", "cs3": f.get("org", ""),
        "cs4Label": "match", "cs4": match,   # what actually matched (redacted evidence)
    }
    return header + "|" + " ".join(f"{k}={esc(v)}" for k, v in ext.items())


BRAND = "palivane"   # brand key in the SIEM sourcetype and S3 object paths


def _request(url: str, token: str, fmt: str, f: dict) -> urllib.request.Request:
    """Build the HTTP request for the chosen format (body + headers)."""
    headers = {}
    if fmt == "cef":
        body = _cef(f).encode()
        headers["content-type"] = "text/plain"
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif fmt == "splunk_hec":
        # Tenant-selected brand key: existing tenants' Splunk dashboards key on the
        # pre-rebrand "palivane:finding" sourcetype; new tenants use "palivane:finding".
        body = json.dumps({"event": f, "sourcetype": f"{BRAND}:finding", "source": BRAND}).encode()
        headers["content-type"] = "application/json"
        if token:
            headers["Authorization"] = f"Splunk {token}"   # HEC scheme
    else:  # json (default)
        body = json.dumps(f).encode()
        headers["content-type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, method="POST", data=body, headers=headers)


def send_detail(url: str, token: str, fmt: str, fields: dict, timeout: float = 8.0,
                ) -> tuple[bool, str]:
    """Deliver one event; returns (ok, detail) so callers can surface WHY a send failed
    (expired token vs unreachable host) instead of a bare boolean."""
    from .netguard import is_safe_url, safe_urlopen
    if not url:
        return False, "no SIEM URL configured"
    if not is_safe_url(url):                # SSRF guard: no internal/metadata targets
        return False, "URL blocked (internal/loopback/metadata host)"
    try:
        # Pinned to the validated IP so the connection can't be rebound to an internal host.
        safe_urlopen(_request(url, token, fmt if fmt in FORMATS else "json", fields), timeout)
        return True, ""
    except Exception as e:
        return False, str(e)[:300]


def send_sync(url: str, token: str, fmt: str, fields: dict, timeout: float = 8.0,
              ) -> bool:
    ok, _detail = send_detail(url, token, fmt, fields, timeout=timeout)
    return ok


def _deliver(url: str, token: str, fmt: str, fields: dict,
             tenant_id: int) -> None:
    """Pool job: send + record the outcome (a silently-lost finding defeats the sink)."""
    ok, detail = send_detail(url, token, fmt, fields)
    from . import sink_health
    sink_health.record(tenant_id, "siem_http", ok, detail)
    if not ok:
        log.warning("SIEM push failed (tenant %s): %s", tenant_id, detail)


def forward(url: str, token: str, min_severity: str, fmt: str, verdict: dict,
            subject: str = "", actor: str = "", surface: str = "", org: str = "",
            tenant_id: int = 0) -> None:
    """Push a finding to the tenant's SIEM if configured and severity >= min_severity. Non-blocking."""
    if not url:
        return
    if _RANK.get(verdict.get("severity"), 0) < _RANK.get(min_severity or "high", 3):
        return
    fields = _fields(verdict, subject, actor, surface, org)
    from .dispatch import submit
    submit(_deliver, url, token, fmt or "json", fields, tenant_id)  # bounded shared pool
