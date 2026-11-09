"""What Palivane does in Slack after it flags a message: redact the values, delete the
message, and tell the person who posted it. One place for both paths that flag Slack
messages (the scheduled scan in saas_connectors and real-time events in slack_events), so
the gates cannot drift apart.

Each action is a per-workspace switch, off by default, and runs only on a message this scan
just flagged at the confirmed-leak tier (high or critical):

  redact          replace the flagged values in the message with «redacted:<label>», keeping
                  the rest. Slack lets one person edit another's message only on Enterprise
                  Grid, and only with an org admin's user token; anywhere else Slack refuses
                  (cant_update_message) and that is recorded, not hidden. Enterprise plan.
  remediate       delete the message (the existing switch). A workspace admin's user token;
                  a bot can delete only its own posts. Enterprise plan. When redaction is on
                  too, deletion is the fallback for a message that could not be redacted.
  notify_sender   a private message to the person who posted it, saying what was found
                  (never the value) and what happened to their message. The bot token, with
                  chat:write and im:write. Any plan: it removes nothing.

Every action is written to the audit log BEFORE it is reported, success or failure: a message
changed with no record of what it was or why is worse than the leak it was fixing.
"""
from __future__ import annotations

import logging
import re
import urllib.parse

from . import audit_log, redact_spans

log = logging.getLogger("palivane.slack_remediation")

CONFIRMED_MIN_RANK = 3            # high | critical — the confirmed-leak tier
SEV_RANK = {"benign": 0, "low": 1, "suspicious": 2, "high": 3, "critical": 4}
_DATA_CATEGORIES = ("secret_leak", "pii_exposure", "phi_exposure", "confidential_data")
_WORDS = re.compile(r"^[A-Za-z][A-Za-z ()/&,.'-]{1,60}$")
# What Slack says when the caller may not edit another person's message (every plan but Grid).
_NOT_EDITABLE = {"cant_update_message", "edit_window_closed", "not_authorized", "missing_scope",
                 "message_not_found"}


def _api(method: str, token: str, params: dict) -> tuple[bool, str, dict]:
    from .saas_connectors import _SLACK_API_BASE, ConnectorError, _http_json
    try:
        r = _http_json(f"{_SLACK_API_BASE}/{method}",
                       headers={"Authorization": f"Bearer {token}",
                                "Content-Type": "application/x-www-form-urlencoded"},
                       data=urllib.parse.urlencode(params).encode())
    except ConnectorError as e:
        return False, str(e), {}
    return (True, "", r) if r.get("ok") else (False, r.get("error", "unknown"), r)


def admin_token(db, connector, creds: dict) -> str:
    """The admin user token that may redact or delete, or "" when neither may run: neither
    switch on, no admin user token, or a plan without the remediation feature."""
    if not (creds.get("remediate") or creds.get("redact")):
        return ""
    token = (creds.get("admin_token") or "").strip()
    if not token.startswith("xoxp-"):
        return ""                 # a bot token cannot change anyone else's message
    from .models import Tenant
    from .plans import has_feature
    tenant = db.get(Tenant, connector.tenant_id)
    return token if (tenant is not None and has_feature(tenant, "remediation")) else ""


def labels_of(result: dict) -> list[str]:
    """What was found, as rule names fit for the person who posted it. Never a value."""
    out: list[str] = []
    for s in result.get("signals") or []:
        if (s.get("check") or s.get("category")) not in _DATA_CATEGORIES:
            continue
        for part in re.split(r",\s*", s.get("evidence") or ""):
            part = part.strip()
            if _WORDS.match(part) and part not in out:
                out.append(part)
        if not out and s.get("title"):
            out.append(s["title"])
    return out[:4] or ["sensitive data"]


def _notice(where: str, labels: list[str], outcome: str) -> str:
    what = labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]
    head = {
        "redacted": f"Palivane removed {what} from your message in {where}. The rest of the "
                    f"message is unchanged.",
        "deleted": f"Palivane deleted your message in {where} because it contained {what}.",
    }.get(outcome, f"Your message in {where} contains {what}. Please delete it.")
    tail = (" If it was a real credential, rotate it now: it was visible to the channel "
            "until it was removed." if any("key" in l.lower() or "token" in l.lower()
                                           or "secret" in l.lower() or "credential" in l.lower()
                                           or "password" in l.lower() for l in labels) else "")
    return head + tail + " Questions: ask your security team."


# --- the three actions, one Slack call each ---------------------------------------------
# Used by remediate() below (the automatic path) and by the buttons on the security team's
# alert (app/slack_interactions.py), so a click does exactly what the switch would have done.

def do_redact(token: str, channel: str, ts: str, text: str, signals: list[dict]) -> tuple[bool, str, int]:
    """Replace the flagged values in one message. Returns (ok, error, values replaced)."""
    spans = (redact_spans.find_spans(text, signals) if text and redact_spans.precheck(signals) else [])
    if not spans:
        # The value is visible only after folding or decoding, so there is no exact stretch
        # of the message to replace: redacting would leave it in place.
        return False, "no_exact_span", 0
    ok, why, _ = _api("chat.update", token,
                      {"channel": channel, "ts": ts, "text": redact_spans.apply(text, spans)})
    if not ok and why in _NOT_EDITABLE:
        why = f"{why} (Slack lets an admin edit another person's message only on Enterprise Grid)"
    return ok, why, len(spans)


def do_delete(token: str, channel: str, ts: str) -> tuple[bool, str]:
    ok, why, _ = _api("chat.delete", token, {"channel": channel, "ts": ts})
    return ok, why


def do_notify(bot: str, user_id: str, where: str, labels: list[str], outcome: str) -> tuple[bool, str]:
    """A private message from the bot to the person who posted it."""
    ok, why, r = _api("conversations.open", bot, {"users": user_id})
    dm = ((r.get("channel") or {}).get("id") or "") if ok else ""
    if not dm:
        return False, why or "no_dm_channel"
    ok, why, _ = _api("chat.postMessage", bot, {"channel": dm, "text": _notice(where, labels, outcome)})
    return ok, why


def remediate(db, connector, creds: dict, *, channel: str, where: str, ts: str, user_id: str,
              actor: str, text: str, result: dict, realtime: bool = False) -> dict:
    """Run the enabled actions on one flagged message, then post the security team's alert
    when an alert channel is set. Returns {redacted, deleted, notified, alerted, failed:
    [action, ...]}. Never raises into the scan that called it."""
    out = {"redacted": False, "deleted": False, "notified": False, "alerted": False, "failed": []}
    try:
        if not ts or SEV_RANK.get(result.get("severity", ""), 0) < CONFIRMED_MIN_RANK:
            return out
        base = {"finding_id": result.get("finding_id"), "severity": result.get("severity"),
                "channel": where, "connector": connector.label or connector.id,
                **({"realtime": True} if realtime else {})}
        target = f"{where}:{ts}"
        token = admin_token(db, connector, creds)
        signals = result.get("signals") or []
        outcome = ""

        if token and creds.get("redact") and text:
            ok, why, n = do_redact(token, channel, ts, text, signals)
            audit_log.record(db, connector.tenant_id, actor,
                             "slack.message_redacted" if ok else "slack.message_redact_failed",
                             target, {**base, "values": n, **({} if ok else {"error": why})})
            outcome = "redacted" if ok else outcome
            out["redacted"] = ok
            if not ok:
                out["failed"].append("redact")

        if token and creds.get("remediate") and not outcome:
            ok, why = do_delete(token, channel, ts)
            audit_log.record(db, connector.tenant_id, actor,
                             "slack.message_deleted" if ok else "slack.message_delete_failed",
                             target, {**base, **({} if ok else {"error": why})})
            outcome = "deleted" if ok else outcome
            out["deleted"] = ok
            if not ok:
                out["failed"].append("delete")

        bot = (creds.get("bot_token") or "").strip()
        if creds.get("notify_sender") and bot and user_id:
            ok, why = do_notify(bot, user_id, where, labels_of(result), outcome)
            audit_log.record(db, connector.tenant_id, actor,
                             "slack.sender_notified" if ok else "slack.sender_notify_failed",
                             target, {**base, "outcome": outcome or "asked_to_delete",
                                      **({} if ok else {"error": why})})
            out["notified"] = ok
            if not ok:
                out["failed"].append("notify")

        if (creds.get("alert_channel") or "").strip() and bot:
            ok, why = post_alert(connector, creds, channel=channel, where=where, ts=ts,
                                 user_id=user_id, actor=actor, result=result, done=out,
                                 can_change=bool(token))
            audit_log.record(db, connector.tenant_id, actor,
                             "slack.alert_posted" if ok else "slack.alert_post_failed",
                             target, {**base, "alert_channel": creds.get("alert_channel"),
                                      **({} if ok else {"error": why})})
            out["alerted"] = ok
            if not ok:
                out["failed"].append("alert")
    except Exception:                                             # noqa: BLE001
        log.exception("slack remediation failed (connector %s)", getattr(connector, "id", "?"))
        db.rollback()
    return out


# --- the security team's alert, with buttons ---------------------------------------------
# Posted by the bot to the workspace's alert channel for every confirmed leak, with a button
# per action not already taken. A click comes back to /api/slack/interactions, which checks
# the signature, that the clicker is a Palivane admin, and runs the same do_* function the
# switch would have. The button carries where the message is (signed, so it cannot be
# pointed at another message); the message text is re-read from Slack at click time, never
# stored.

ALERT_ACTION_ID = "palivane_remediate"
_SEV_ICON = {"critical": ":rotating_light:", "high": ":warning:"}


def sign_action(fields: dict) -> str:
    import base64
    import hashlib
    import hmac as _hmac
    import json
    body = base64.urlsafe_b64encode(json.dumps(fields, separators=(",", ":")).encode()).decode().rstrip("=")
    mac = _hmac.new(_action_key(), body.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{body}.{mac}"


def unsign_action(value: str) -> dict | None:
    import base64
    import hashlib
    import hmac as _hmac
    import json
    body, _, mac = (value or "").rpartition(".")
    if not body or not _hmac.compare_digest(
            mac, _hmac.new(_action_key(), body.encode(), hashlib.sha256).hexdigest()[:32]):
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError:
        return None


def _action_key() -> bytes:
    import hashlib
    import hmac as _hmac
    from .security import _secret
    return _hmac.new(_secret(), b"palivane-slack-alert-action", hashlib.sha256).digest()


def _button(label: str, action: str, fields: dict, style: str = "", confirm: str = "") -> dict:
    b = {"type": "button", "text": {"type": "plain_text", "text": label},
         "action_id": f"{ALERT_ACTION_ID}:{action}", "value": sign_action({**fields, "a": action})}
    if style:
        b["style"] = style
    if confirm:
        b["confirm"] = {"title": {"type": "plain_text", "text": label + "?"},
                        "text": {"type": "plain_text", "text": confirm},
                        "confirm": {"type": "plain_text", "text": label},
                        "deny": {"type": "plain_text", "text": "Cancel"}}
    return b


def alert_blocks(connector, *, channel: str, where: str, ts: str, user_id: str, actor: str,
                 result: dict, done: dict, can_change: bool) -> list[dict]:
    from .config import settings
    sev = result.get("severity", "high")
    what = ", ".join(labels_of(result))
    fid = result.get("finding_id")
    link = (f"{settings.public_base_url.rstrip('/')}/app/findings/{fid}"
            if settings.public_base_url and fid else "")
    taken = [w for w, k in (("redacted", "redacted"), ("deleted", "deleted"),
                            ("sender notified", "notified")) if done.get(k)]
    head = (f"{_SEV_ICON.get(sev, ':warning:')} *{sev.capitalize()}*: {what} in {where}"
            + (f", posted by {actor}" if actor else ""))
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": head}},
              {"type": "context", "elements": [{"type": "mrkdwn", "text":
                  ("Already done: " + ", ".join(taken) if taken else "No action taken yet.")
                  + (f"  <{link}|Open in Palivane>" if link else "")}]}]
    fields = {"f": fid, "k": connector.id, "c": channel, "t": ts, "u": user_id, "w": where}
    buttons = []
    gone = done.get("deleted") or done.get("redacted")
    if can_change and not gone:
        buttons.append(_button("Redact", "redact", fields, confirm=(
            "Replace the flagged values in the message. Slack allows this only on Enterprise Grid.")))
        buttons.append(_button("Delete", "delete", fields, style="danger",
                               confirm="Delete the message from Slack. This cannot be undone."))
    if user_id and not done.get("notified"):
        buttons.append(_button("Notify sender", "notify", fields))
    buttons.append(_button("Dismiss as false positive", "dismiss", fields))
    blocks.append({"type": "actions", "block_id": "palivane_actions", "elements": buttons})
    return blocks


def post_alert(connector, creds: dict, **kw) -> tuple[bool, str]:
    import json
    blocks = alert_blocks(connector, **kw)
    fallback = blocks[0]["text"]["text"]
    bot, where = (creds.get("bot_token") or "").strip(), creds["alert_channel"].strip()
    msg = {"channel": where, "text": fallback, "blocks": json.dumps(blocks)}
    ok, why, _ = _api("chat.postMessage", bot, msg)
    if not ok and why == "not_in_channel":
        # A public alert channel the bot was never invited to: it may join (channels:join).
        # A private one has to invite it; that error is what the audit log then shows.
        joined, _, r = _api("conversations.join", bot, {"channel": where})
        if joined:
            msg["channel"] = (r.get("channel") or {}).get("id") or where
            ok, why, _ = _api("chat.postMessage", bot, msg)
    return ok, why
