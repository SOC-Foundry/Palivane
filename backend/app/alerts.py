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


def _envelope(env: dict) -> dict:
    """Structured payload under the product's brand key."""
    return {"palivane": env}


def _payload(verdict: dict, subject: str, actor: str, surface: str) -> dict:
    from .signal_summary import top_signals
    cats = ", ".join(s.get("category", "") for s in verdict.get("signals", [])[:5]) or "—"
    # The concrete cause — the strongest signals with their (already-redacted) evidence — so
    # the alert says WHAT matched, not just which category buckets tripped.
    tops = top_signals(verdict.get("signals"), 3)
    lines = "".join(f"\n  • {t['title']}" + (f" — `{t['evidence']}`" if t["evidence"] else "")
                    for t in tops)
    # Content origin: name the source document the leaked content came from, when known —
    # the "restrict it here" pointer, and flag when that source is itself sensitive.
    origin = verdict.get("origin") or None
    origin_line = ""
    if origin:
        src = origin.get("title") or origin.get("ref") or "a scanned document"
        origin_line = (f"\n  ↳ from {src} ({origin.get('source', 'at-rest')}, "
                       f"{int(origin.get('containment', 0) * 100)}% match"
                       + (", sensitive source" if origin.get("sensitive") else "") + ")")
    text = (f":shield: *Palivane {verdict.get('severity', '?').upper()}* — "
            f"{subject or 'finding'} ({actor or 'unknown'})\n"
            f"{cats} · risk {verdict.get('risk_score', '?')} · surface {surface}{lines}{origin_line}")
    return {"text": text, **_envelope({
        "severity": verdict.get("severity"), "risk_score": verdict.get("risk_score"),
        "categories": cats, "actor": actor, "surface": surface,
        "finding_id": verdict.get("finding_id"), "top_signals": tops,
        "origin": origin,
    })}


def send_sync(webhook: str, payload: dict, timeout: float = 8.0) -> bool:
    from .netguard import is_safe_url, safe_urlopen
    if not is_safe_url(webhook):   # SSRF guard: no internal/metadata targets
        return False
    try:
        req = urllib.request.Request(
            webhook, method="POST", data=json.dumps(payload).encode(),
            headers={"content-type": "application/json"})
        safe_urlopen(req, timeout)   # pinned to the validated IP (closes the DNS-rebind window)
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
    (e.g. exhausted API credits), so Palivane is running offline detectors only. Best-effort;
    returns True if a webhook was configured and the POST was attempted."""
    text = (":rotating_light: *Palivane: LLM judge is DOWN* — all configured providers are "
            f"failing ({health.get('consecutive_failures', '?')} consecutive calls). "
            f"Last error: {health.get('last_error') or 'unknown'}.\n"
            "Palivane is running offline detectors only. Restore a judge provider "
            "(top up API credits, or set a fallback provider key for failover).")
    if not webhook:
        return False
    return send_sync(webhook, {"text": text, **_envelope({"event": "judge_down", **health})})


def notify_judge_recovered(webhook: str, health: dict) -> bool:
    """Tell the operator the LLM judge is back (a provider is answering again)."""
    if not webhook:
        return False
    return send_sync(webhook, {"text": ":white_check_mark: *Palivane: LLM judge recovered* — a "
                              "provider is answering again; full detection restored.",
                              **_envelope({"event": "judge_recovered", **health})})


def notify_upgrade_request(webhook: str, org: str, plan: str, seats: int,
                           contact: str, note: str) -> bool:
    """Page the operator that an org hit "Request upgrade" in the console — a buying
    signal that should never wait for someone to check /admin. Best-effort."""
    if not webhook:
        return False
    text = (f":moneybag: *Palivane: upgrade request* — \"{org}\" wants the *{plan}* plan"
            + (f" ({seats} seats)" if seats else "")
            + f". Contact: {contact or 'unknown'}."
            + (f"\n> {note}" if note else "")
            + "\nWork the queue in the operator console (/admin).")
    return send_sync(webhook, {"text": text, **_envelope({
        "event": "upgrade_request", "org": org, "plan": plan, "seats": seats})})


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
    text = (f":shield: *Palivane {tenant.alert_digest} digest* — {len(findings)} finding(s) "
            f"since {since:%Y-%m-%d %H:%M} UTC\n{by_sev}\n{lines}{more}")
    return {"text": text, **_envelope({"digest": tenant.alert_digest, "count": len(findings),
                                       "by_severity": dict(c), "org": tenant.slug})}


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


_DARK_AFTER_HOURS = 72   # matches the fleet view's "dark" bucket


def run_fleet_alerts(db, now=None) -> int:
    """Page a tenant's webhook when a sensor goes dark (>72h silent — MDM removed the
    hook, device wiped, key rotated but never re-enrolled) or a device keeps presenting
    a revoked/expired key. Edge-triggered via per-row alerted-at markers (the heartbeat
    upsert re-arms a sensor when it resumes), claimed with conditional updates so
    multiple workers can't double-send, and batched per tenant per sweep so a returned-
    from-vacation Monday is one message, not thirty. Returns #webhooks sent."""
    from datetime import datetime, timedelta

    from .models import ApiKey, SensorHeartbeat, Tenant
    now = now or datetime.utcnow()
    cutoff = now - timedelta(hours=_DARK_AFTER_HOURS)
    sent = 0
    for t in db.query(Tenant).filter(Tenant.alert_webhook != "").all():
        dark = (db.query(SensorHeartbeat)
                .filter(SensorHeartbeat.tenant_id == t.id,
                        SensorHeartbeat.last_seen < cutoff,
                        SensorHeartbeat.dark_alerted_at.is_(None))
                .order_by(SensorHeartbeat.last_seen).limit(50).all())
        dead = (db.query(ApiKey)
                .filter(ApiKey.tenant_id == t.id, ApiKey.active.is_(False),
                        ApiKey.last_failed_at.isnot(None),
                        ApiKey.dead_alerted_at.is_(None))
                .order_by(ApiKey.last_failed_at.desc()).limit(50).all())
        if not dark and not dead:
            continue
        # Claim each row before sending (conditional update, like digest windows) so a
        # second worker's sweep matches zero rows and stays quiet.
        claimed_dark = [r for r in dark if db.query(SensorHeartbeat)
                        .filter(SensorHeartbeat.id == r.id,
                                SensorHeartbeat.dark_alerted_at.is_(None))
                        .update({SensorHeartbeat.dark_alerted_at: now},
                                synchronize_session=False)]
        claimed_dead = [k for k in dead if db.query(ApiKey)
                        .filter(ApiKey.id == k.id, ApiKey.dead_alerted_at.is_(None))
                        .update({ApiKey.dead_alerted_at: now}, synchronize_session=False)]
        db.commit()
        if not claimed_dark and not claimed_dead:
            continue
        lines = [f"• gone dark: *{r.actor or 'unknown'}* ({r.plane}"
                 f"{'/' + r.tool if r.tool else ''}) — last seen "
                 f"{r.last_seen:%Y-%m-%d %H:%M} UTC" for r in claimed_dark]
        lines += [f"• revoked key still in use: *{k.label or k.prefix}*"
                  f"{' (' + k.actor + ')' if k.actor else ''} — last attempt "
                  f"{k.last_failed_at:%Y-%m-%d %H:%M} UTC" for k in claimed_dead]
        text = (f":shield: *Palivane fleet alert* — {len(claimed_dark)} sensor(s) dark"
                + (f", {len(claimed_dead)} dead key(s) in use" if claimed_dead else "")
                + " (a fail-open control that stops reporting is indistinguishable from "
                  "a healthy quiet one — check the Fleet view)\n" + "\n".join(lines))
        if send_sync(t.alert_webhook.strip(), {"text": text, **_envelope({
                "event": "fleet_health",
                "dark": [{"actor": r.actor, "plane": r.plane, "tool": r.tool}
                         for r in claimed_dark],
                "dead_keys": [{"label": k.label, "actor": k.actor} for k in claimed_dead],
                "org": t.slug})}):
            sent += 1
    return sent
