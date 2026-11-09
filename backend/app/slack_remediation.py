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


def remediate(db, connector, creds: dict, *, channel: str, where: str, ts: str, user_id: str,
              actor: str, text: str, result: dict, realtime: bool = False) -> dict:
    """Run the enabled actions on one flagged message. Returns {redacted, deleted, notified,
    failed: [action, ...]}. Never raises into the scan that called it."""
    out = {"redacted": False, "deleted": False, "notified": False, "failed": []}
    try:
        if not ts or SEV_RANK.get(result.get("severity", ""), 0) < CONFIRMED_MIN_RANK:
            return out
        base = {"finding_id": result.get("finding_id"), "severity": result.get("severity"),
                "channel": where, "connector": connector.label or connector.id,
                **({"realtime": True} if realtime else {})}
        target = f"{where}:{ts}"
        token = admin_token(db, connector, creds)
        outcome = ""

        if token and creds.get("redact") and text:
            spans = (redact_spans.find_spans(text, result.get("signals") or [])
                     if redact_spans.precheck(result.get("signals") or []) else [])
            if spans:
                ok, why, _ = _api("chat.update", token,
                                  {"channel": channel, "ts": ts, "text": redact_spans.apply(text, spans)})
            else:
                # The value is visible only after folding or decoding, so there is no exact
                # stretch of the message to replace: redacting would leave it in place.
                ok, why = False, "no_exact_span"
            if ok:
                outcome = "redacted"
            elif why in _NOT_EDITABLE:
                why = f"{why} (Slack lets an admin edit another person's message only on Enterprise Grid)"
            audit_log.record(db, connector.tenant_id, actor,
                             "slack.message_redacted" if ok else "slack.message_redact_failed",
                             target, {**base, "values": len(spans),
                                      **({} if ok else {"error": why})})
            if not ok:
                out["failed"].append("redact")
            out["redacted"] = ok

        if token and creds.get("remediate") and not outcome:
            ok, why, _ = _api("chat.delete", token, {"channel": channel, "ts": ts})
            audit_log.record(db, connector.tenant_id, actor,
                             "slack.message_deleted" if ok else "slack.message_delete_failed",
                             target, {**base, **({} if ok else {"error": why})})
            if ok:
                outcome = "deleted"
            else:
                out["failed"].append("delete")
            out["deleted"] = ok

        bot = (creds.get("bot_token") or "").strip()
        if creds.get("notify_sender") and bot and user_id:
            ok, why, r = _api("conversations.open", bot, {"users": user_id})
            dm = ((r.get("channel") or {}).get("id") or "") if ok else ""
            if dm:
                ok, why, _ = _api("chat.postMessage", bot,
                                  {"channel": dm, "text": _notice(where, labels_of(result), outcome)})
            audit_log.record(db, connector.tenant_id, actor,
                             "slack.sender_notified" if ok and dm else "slack.sender_notify_failed",
                             target, {**base, "outcome": outcome or "asked_to_delete",
                                      **({} if ok and dm else {"error": why or "no_dm_channel"})})
            out["notified"] = bool(ok and dm)
            if not out["notified"]:
                out["failed"].append("notify")
    except Exception:                                             # noqa: BLE001
        log.exception("slack remediation failed (connector %s)", getattr(connector, "id", "?"))
        db.rollback()
    return out
