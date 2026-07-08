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
    from .netguard import is_safe_url
    if not is_safe_url(webhook):   # SSRF guard: no internal/metadata targets
        return False
    try:
        req = urllib.request.Request(
            webhook, method="POST", data=json.dumps(payload).encode(),
            headers={"content-type": "application/json"})
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        return False


def notify(webhook: str, min_severity: str, verdict: dict,
           subject: str = "", actor: str = "", surface: str = "", digest: str = "off") -> None:
    """Fire a real-time alert if the webhook is set and severity >= min_severity.

    In digest mode ("hourly"/"daily") only *critical* findings fire in real time — everything
    else is rolled up by run_digests() so the channel isn't flooded per finding. Non-blocking."""
    if not webhook or not _realtime_ok(verdict.get("severity"), min_severity, digest):
        return
    payload = _payload(verdict, subject, actor, surface)
    threading.Thread(target=send_sync, args=(webhook, payload), daemon=True).start()


def _realtime_ok(severity: str, min_severity: str, digest: str) -> bool:
    """Should this finding fire a real-time alert? It must clear the severity threshold, and
    in digest mode only criticals go out immediately (the rest are batched)."""
    if _RANK.get(severity, 0) < _RANK.get(min_severity or "high", 3):
        return False
    if digest in ("hourly", "daily") and severity != "critical":
        return False
    return True


_DIGEST_INTERVAL = {"hourly": 3600, "daily": 86400}


def _digest_payload(tenant, findings: list, since, now) -> dict:
    from collections import Counter
    c = Counter(f.severity for f in findings)
    by_sev = " · ".join(f"{c[s]} {s}" for s in ("critical", "high", "suspicious", "low") if c.get(s))
    top = sorted(findings, key=lambda f: _RANK.get(f.severity, 0), reverse=True)[:10]
    lines = "\n".join(
        f"• *{f.severity}* · {f.surface} · {(f.subject or 'finding')[:70]} ({f.sender or '—'})"
        for f in top)
    more = f"\n…and {len(findings) - len(top)} more" if len(findings) > len(top) else ""
    text = (f":shield: *Warden {tenant.alert_digest} digest* — {len(findings)} finding(s) "
            f"since {since:%Y-%m-%d %H:%M} UTC\n{by_sev}\n{lines}{more}")
    return {"text": text, "warden": {"digest": tenant.alert_digest, "count": len(findings),
                                     "by_severity": dict(c), "org": tenant.slug}}


def run_digests(db, now=None) -> int:
    """Send due per-tenant digests. For each tenant on hourly/daily with a webhook: if the
    window has elapsed, atomically claim it (a conditional timestamp update — safe across
    workers), roll up alertable findings since the last window, and POST. Returns #sent."""
    from datetime import datetime, timedelta
    from .models import Tenant, Finding
    now = now or datetime.utcnow()
    tenants = (db.query(Tenant)
               .filter(Tenant.alert_digest.in_(("hourly", "daily")),
                       Tenant.alert_webhook != "").all())
    sent = 0
    for t in tenants:
        interval = timedelta(seconds=_DIGEST_INTERVAL[t.alert_digest])
        last = t.alert_digest_last
        if last and (now - last) < interval:
            continue
        since = last or (now - interval)
        # Claim the window: only one worker's conditional update matches -> no duplicate sends.
        cond = (Tenant.alert_digest_last == last) if last else Tenant.alert_digest_last.is_(None)
        claimed = (db.query(Tenant).filter(Tenant.id == t.id, cond)
                   .update({Tenant.alert_digest_last: now}, synchronize_session=False))
        db.commit()
        if not claimed:
            continue
        min_rank = _RANK.get(t.alert_min_severity or "high", 3)
        findings = [f for f in db.query(Finding)
                    .filter(Finding.tenant_id == t.id, Finding.created_at > since).all()
                    if _RANK.get(f.severity, 0) >= min_rank]
        if not findings:
            continue
        if send_sync(t.alert_webhook.strip(), _digest_payload(t, findings, since, now)):
            sent += 1
    return sent
