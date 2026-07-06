"""OSV.dev advisory lookup for pinned dependencies (agentless CVE scanning).

Given (ecosystem, name, version) pins, query the OSV batch API for known vulnerabilities.
Used by /api/scan/deps when DEP_OSV_ENABLED is set. Fails open (returns {}) on any error
so a feed outage never blocks a scan — the heuristic checks still run regardless.
"""

from __future__ import annotations

import json
import urllib.request

from .config import settings


def query(pins: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
    """Return {(ecosystem, name, version): [advisory_id, ...]} for pins that have vulns."""
    if not pins:
        return {}
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in pins]
    try:
        req = urllib.request.Request(
            settings.dep_osv_url, method="POST",
            data=json.dumps({"queries": queries}).encode(),
            headers={"content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
    except Exception:
        return {}  # fail open — feed unreachable
    out: dict[tuple[str, str, str], list[str]] = {}
    for pin, res in zip(pins, data.get("results", []) or []):
        ids = [v.get("id") for v in (res or {}).get("vulns", []) or [] if v.get("id")]
        if ids:
            out[pin] = ids
    return out
