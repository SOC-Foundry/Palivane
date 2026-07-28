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
    from .signal_summary import top_signals
    cats = ", ".join(s.get("category", "") for s in verdict.get("signals", [])[:5]) or "—"
    # The concrete cause — the strongest signals with their (already-redacted) evidence — so
    # the alert says WHAT matched, not just which category buckets tripped.
    tops = top_signals(verdict.get("signals"), 3)
    lines = "".join(f"\n  • {t['title']}" + (f" — `{t['evidence']}`" if t["evidence"] else "")
                    for t in tops)
    text = (f":shield: *Warden {verdict.get('severity', '?').upper()}* — "
            f"{subject or 'finding'} ({actor or 'unknown'})\n"
            f"{cats} · risk {verdict.get('risk_score', '?')} · surface {surface}{lines}")
    return {"text": text, "warden": {
        "severity": verdict.get("severity"), "risk_score": verdict.get("risk_score"),
        "categories": cats, "actor": actor, "surface": surface,
        "finding_id": verdict.get("finding_id"), "top_signals": tops,
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
    from .dispatch import submit
    submit(send_sync, webhook, payload)   # bounded shared pool (no thread-per-finding)


def notify_judge_down(webhook: str, health: dict) -> bool:
    """Page the operator that the LLM judge is failing — all configured providers erroring
    (e.g. exhausted API credits), so Warden is running offline detectors only. Best-effort;
    returns True if a webhook was configured and the POST was attempted."""
    text = (":rotating_light: *Warden: LLM judge is DOWN* — all configured providers are "
            f"failing ({health.get('consecutive_failures', '?')} consecutive calls). "
            f"Last error: {health.get('last_error') or 'unknown'}.\n"
            "Warden is running offline detectors only. Restore a judge provider "
            "(top up API credits, or set a fallback provider key for failover).")
    if not webhook:
        return False
    return send_sync(webhook, {"text": text, "warden": {"event": "judge_down", **health}})


def notify_judge_recovered(webhook: str, health: dict) -> bool:
    """Tell the operator the LLM judge is back (a provider is answering again)."""
    if not webhook:
        return False
    return send_sync(webhook, {"text": ":white_check_mark: *Warden: LLM judge recovered* — a "
                              "provider is answering again; full detection restored.",
                              "warden": {"event": "judge_recovered", **health}})


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
    from .signal_summary import top_signals
    top = sorted(findings, key=lambda f: _RANK.get(f.severity, 0), reverse=True)[:10]

    def _what(f):   # the single strongest signal, so a digest line still names the cause
        t = top_signals(f.signals, 1)
        if not t:
            return ""
        return f" — {t[0]['title']}" + (f" `{t[0]['evidence']}`" if t[0]["evidence"] else "")

    lines = "\n".join(
        f"• *{f.severity}* · {f.surface} · {(f.subject or 'finding')[:70]} ({f.sender or '—'}){_what(f)}"
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
