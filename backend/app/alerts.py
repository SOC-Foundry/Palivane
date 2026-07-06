"""Outbound alerts — POST high/critical findings to a tenant's webhook (Slack-compatible).

Fire-and-forget on the request path (a daemon thread with a short timeout) so a slow or
down webhook never adds latency or breaks capture. `send_sync` is the same POST but
blocking, for the "test webhook" button.
"""

from __future__ import annotations

import json
import threading
import urllib.request

_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}


def _payload(verdict: dict, subject: str, actor: str, surface: str) -> dict:
    cats = ", ".join(s.get("category", "") for s in verdict.get("signals", [])[:5]) or "—"
    text = (f":shield: *Warden {verdict.get('severity', '?').upper()}* — "
            f"{subject or 'finding'} ({actor or 'unknown'})\n"
            f"{cats} · risk {verdict.get('risk_score', '?')} · surface {surface}")
    return {"text": text, "warden": {
        "severity": verdict.get("severity"), "risk_score": verdict.get("risk_score"),
        "categories": cats, "actor": actor, "surface": surface,
        "finding_id": verdict.get("finding_id"),
    }}


def send_sync(webhook: str, payload: dict, timeout: float = 8.0) -> bool:
    try:
        req = urllib.request.Request(
            webhook, method="POST", data=json.dumps(payload).encode(),
            headers={"content-type": "application/json"})
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        return False


def notify(webhook: str, min_severity: str, verdict: dict,
           subject: str = "", actor: str = "", surface: str = "") -> None:
    """Fire an alert if the webhook is set and severity >= min_severity. Non-blocking."""
    if not webhook:
        return
    if _RANK.get(verdict.get("severity"), 0) < _RANK.get(min_severity or "high", 3):
        return
    payload = _payload(verdict, subject, actor, surface)
    threading.Thread(target=send_sync, args=(webhook, payload), daemon=True).start()
