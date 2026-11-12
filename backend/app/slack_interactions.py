"""The buttons on the security team's Slack alert (app/slack_remediation.alert_blocks).

Slack posts each click to /api/slack/interactions. Trust comes from three checks, all of
which must pass before anything happens to a message:

  1. the request signature (the app's signing secret, as for events);
  2. the button's own signature: it names the finding, the connector and the exact message,
     signed by us when the alert was posted, so a forged or edited value is refused;
  3. the person who clicked is a Palivane ADMIN of the org that owns that connector, matched
     by their Slack email (users:read.email). Anyone else in the channel gets a private
     "only a Palivane admin can do this" and nothing changes.

The click is acknowledged at once (Slack wants an answer within 3 seconds) and run on the
events worker pool; the alert is then rewritten through Slack's response_url to say who did
what, and the button that was used is removed. Every outcome is audit-logged under the
admin's own address.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request

from fastapi import APIRouter, HTTPException, Request, Response

from .config import settings

log = logging.getLogger("palivane.slack_interactions")
router = APIRouter(prefix="/api", tags=["slack"])

_DONE = {"redact": "Redacted", "delete": "Deleted", "notify": "Sender notified",
         "contain": "Sender contained for 24 hours", "dismiss": "Dismissed as a false positive"}


def _respond(url: str, payload: dict) -> None:
    """POST to Slack's response_url (no token needed; valid for 30 minutes, 5 uses)."""
    if not url.startswith("https://hooks.slack.com/"):
        return
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:                                             # noqa: BLE001
        log.warning("slack response_url post failed", exc_info=True)


def _private(url: str, text: str) -> None:
    _respond(url, {"response_type": "ephemeral", "replace_original": False, "text": text})


def _clicker_email(bot: str, user_id: str) -> str:
    from .saas_connectors import _SLACK_API_BASE, ConnectorError, _http_json
    try:
        data = _http_json(f"{_SLACK_API_BASE}/users.info?" + urllib.parse.urlencode({"user": user_id}),
                          headers={"Authorization": f"Bearer {bot}"})
    except ConnectorError:
        return ""
    email = (((data.get("user") or {}).get("profile") or {}).get("email") or "") if data.get("ok") else ""
    return email.strip().lower() if "@" in email else ""


def _message_text(bot: str, channel: str, ts: str) -> str:
    """The flagged message as it is now, read back from Slack at click time (never stored)."""
    from .saas_connectors import _SLACK_API_BASE, ConnectorError, _http_json
    try:
        data = _http_json(f"{_SLACK_API_BASE}/conversations.history?" + urllib.parse.urlencode(
            {"channel": channel, "latest": ts, "oldest": ts, "inclusive": "true", "limit": "1"}),
            headers={"Authorization": f"Bearer {bot}"})
    except ConnectorError:
        return ""
    msgs = data.get("messages") or [] if data.get("ok") else []
    return (msgs[0].get("text") or "") if msgs and msgs[0].get("ts") == ts else ""


def _updated_blocks(blocks: list[dict], action: str, line: str) -> list[dict]:
    """The alert with the used button removed (both Redact and Delete once the message is
    gone) and a line saying who did it."""
    gone = {"redact", "delete"} if action in ("redact", "delete") else {action}
    out = []
    for b in blocks or []:
        if b.get("type") == "actions":
            keep = [e for e in b.get("elements", [])
                    if (e.get("action_id") or "").split(":", 1)[-1] not in gone]
            if action == "dismiss":
                keep = []
            if keep:
                out.append({**b, "elements": keep})
            continue
        out.append(b)
    out.append({"type": "context", "elements": [{"type": "mrkdwn", "text": line}]})
    return out


def handle_click(payload: dict, db_factory=None) -> None:
    """One button click, start to finish. Never raises. `db_factory` defaults to SessionLocal."""
    from . import audit_log, review
    from . import saas_connectors as sc
    from . import slack_remediation as sr
    from .database import SessionLocal
    from .models import Finding, User
    from .slack_events import _connector_for_team

    response_url = payload.get("response_url", "")
    act = (payload.get("actions") or [{}])[0]
    fields = sr.unsign_action(act.get("value", ""))
    if not fields or (act.get("action_id") or "").split(":", 1)[0] != sr.ALERT_ACTION_ID:
        _private(response_url, "That button could not be verified, so nothing was changed.")
        return
    action = fields.get("a", "")
    team = payload.get("team") or {}
    db = (db_factory or SessionLocal)()
    try:
        connector = _connector_for_team(db, team.get("id", ""), team.get("enterprise_id") or "",
                                        payload.get("api_app_id", ""))
        if connector is None or connector.id != fields.get("k"):
            _private(response_url, "This alert belongs to a workspace Palivane no longer scans.")
            return
        creds = sc.read_credentials(connector, db)
        bot = (creds.get("bot_token") or "").strip()
        clicker = (payload.get("user") or {}).get("id", "")
        email = _clicker_email(bot, clicker) if bot and clicker else ""
        admin = (db.query(User).filter(User.tenant_id == connector.tenant_id,
                                       User.email.ilike(email), User.active.is_(True)).first()
                 if email else None)
        if admin is None or admin.role != "admin":
            _private(response_url, "Only a Palivane admin of this organization can do this. "
                                   "Open the finding in the Palivane console instead.")
            return
        finding = db.query(Finding).filter(Finding.id == fields.get("f"),
                                           Finding.tenant_id == connector.tenant_id).first()
        if finding is None:
            _private(response_url, "That finding no longer exists in Palivane.")
            return
        channel, ts, where = fields.get("c", ""), fields.get("t", ""), fields.get("w", "")
        target = f"{where}:{ts}"
        base = {"finding_id": finding.id, "severity": finding.severity, "channel": where,
                "connector": connector.label or connector.id, "via": "slack_alert"}
        ok, why = False, ""
        if action in ("redact", "delete"):
            if action == "redact":
                ok, why, _ = sr.do_redact(sr.discovery_token(db, connector), channel, ts,
                                          _message_text(bot, channel, ts), finding.signals or [],
                                          (connector.state or {}).get("team_id", ""))
            else:
                token = sr.admin_token(db, connector, {**creds, "remediate": True})
                ok, why = (sr.do_delete(token, channel, ts) if token else
                           (False, "no workspace-admin token on this connector, or the plan has "
                                   "no remediation"))
            names = {"redact": ("slack.message_redacted", "slack.message_redact_failed"),
                     "delete": ("slack.message_deleted", "slack.message_delete_failed")}[action]
            audit_log.record(db, connector.tenant_id, admin.email, names[0] if ok else names[1],
                             target, {**base, **({} if ok else {"error": why})})
        elif action == "notify":
            ok, why = sr.do_notify(bot, fields.get("u", ""), where,
                                   sr.labels_of({"signals": finding.signals or []}), "")
            audit_log.record(db, connector.tenant_id, admin.email,
                             "slack.sender_notified" if ok else "slack.sender_notify_failed",
                             target, {**base, **({} if ok else {"error": why})})
        elif action == "contain":
            from . import containment
            try:
                row = containment.create(db, connector.tenant_id, "user", fields.get("e", ""),
                                         f"Slack alert on finding #{finding.id} ({where})", None,
                                         admin.email)
                ok, why = True, ""
                base["containment_id"] = row.id
            except containment.ContainmentError as e:
                ok, why = False, str(e)
            if not ok:
                audit_log.record(db, connector.tenant_id, admin.email, "containment.failed",
                                 fields.get("e", ""), {**base, "error": why})
        elif action == "dismiss":
            finding.status = "dismissed"
            review.record_review(finding, "dismissed", admin.email, "manual", "false_positive")
            db.commit()
            ok = True
            audit_log.record(db, connector.tenant_id, admin.email, "finding.status", str(finding.id),
                             {"status": "dismissed", "reason": "false_positive", "via": "slack_alert"})
        else:
            _private(response_url, "Unknown action; nothing was changed.")
            return
        if ok:
            line = f":white_check_mark: {_DONE[action]} by {admin.email}"
            _respond(response_url, {"replace_original": True,
                                    "text": (payload.get("message") or {}).get("text", ""),
                                    "blocks": _updated_blocks((payload.get("message") or {}).get("blocks"),
                                                              action, line)})
        else:
            _private(response_url, f"{_DONE[action].split(' ')[0]} failed: {why}")
    except Exception:                                             # noqa: BLE001
        log.exception("slack alert action failed")
        db.rollback()
        _private(response_url, "Something went wrong; nothing was changed. Try the console.")
    finally:
        db.close()


@router.post("/slack/interactions")
async def slack_interactions(request: Request):
    """Slack interactivity receiver (button clicks on Palivane's alerts). Configure the Slack
    app's Interactivity Request URL to this path. Public; trust comes from the signature."""
    from .slack_events import _EXECUTOR, _verify
    if not settings.slack_signing_secret:
        raise HTTPException(status_code=400, detail="slack interactivity not configured")
    body = await request.body()
    if not _verify(body, request.headers.get("X-Slack-Request-Timestamp", ""),
                   request.headers.get("X-Slack-Signature", "")):
        raise HTTPException(status_code=401, detail="bad signature")
    form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
    try:
        payload = json.loads((form.get("payload") or ["{}"])[0])
    except ValueError:
        raise HTTPException(status_code=400, detail="bad payload")
    if payload.get("type") == "block_actions":
        _EXECUTOR.submit(handle_click, payload)
    return Response(status_code=200)
