"""Real-time Slack scanning — the Events API push path beside the pull-based sync.

The slack_messages connector's cron sync sees a leak minutes-to-hours after it lands;
Slack's Events API delivers the message the moment it is sent. Same detection, same
findings, same remediation gates — only the transport differs. The two paths coexist:
events never advance the sync cursors, so a synced channel simply rescans event-scanned
messages and the recurrences fold.

Trust model mirrors the Stripe webhook: the endpoint is public (Slack posts to it), so
trust comes entirely from the request signature — HMAC-SHA256 of "v0:{ts}:{body}" with
the app's signing secret (PALIVANE_SLACK_SIGNING_SECRET), constant-time compare, 5-minute
replay window. Tenancy comes from the event's team_id, matched to the slack_messages
connector whose bot token belongs to that workspace (resolved once via auth.test and
cached in connector state).

Slack requires an ack within 3 seconds and redelivers on timeout, so events are ack'd
immediately and processed on a small worker pool; redeliveries are folded by event_id.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

from fastapi import APIRouter, HTTPException, Request

from .config import settings

_log = logging.getLogger("palivane.slack_events")
router = APIRouter(prefix="/api", tags=["slack"])

_SLACK_API = "https://slack.com/api"
_REPLAY_WINDOW = 300

# Bounded pool: a message storm must queue, not spawn a thread per event.
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="slack-event")
_submit = _EXECUTOR.submit          # tests monkeypatch this to run inline

# Redelivery fold: Slack retries any event not ack'd fast enough; event_id is stable
# across retries. Small in-memory TTL set — a duplicate finding on multi-replica
# deployments still folds as a recurrence downstream, so this is latency, not correctness.
_SEEN: dict[str, float] = {}
_SEEN_LOCK = threading.Lock()
_SEEN_TTL = 900
_SEEN_MAX = 20_000


def _already_seen(event_id: str) -> bool:
    if not event_id:
        return False
    now = time.time()
    with _SEEN_LOCK:
        if len(_SEEN) > _SEEN_MAX:
            for k in [k for k, exp in _SEEN.items() if exp < now]:
                _SEEN.pop(k, None)
        if _SEEN.get(event_id, 0) > now:
            return True
        _SEEN[event_id] = now + _SEEN_TTL
        return False


def _verify(body: bytes, ts: str, sig: str) -> bool:
    """Slack request signing: X-Slack-Signature = v0=HMAC_SHA256("v0:{ts}:{body}")."""
    try:
        if abs(time.time() - int(ts or "0")) > _REPLAY_WINDOW:
            return False
    except ValueError:
        return False
    expected = "v0=" + hmac.new(settings.slack_signing_secret.encode(),
                                f"v0:{ts}:".encode() + body, sha256).hexdigest()
    return hmac.compare_digest(expected, sig or "")


def _connector_for_team(db, team_id: str):
    """The active slack_messages connector whose workspace is team_id. Matched from
    connector state; connectors not yet mapped get one auth.test call to learn (and
    cache) their workspace, so the first event after an install does the wiring."""
    from .models import SaasConnector
    from .saas_connectors import ConnectorError, _http_json, read_credentials
    rows = (db.query(SaasConnector)
              .filter(SaasConnector.platform == "slack_messages",
                      SaasConnector.active.is_(True)).all())
    for row in rows:
        if row.state.get("team_id") == team_id:
            return row
    for row in rows:
        if row.state.get("team_id"):
            continue
        try:
            token = (read_credentials(row, db).get("bot_token") or "").strip()
            if not token:
                continue
            info = _http_json(f"{_SLACK_API}/auth.test",
                              headers={"Authorization": f"Bearer {token}"}, data=b"")
        except (ConnectorError, Exception):                       # noqa: BLE001
            continue
        tid = (info.get("team_id") or "") if info.get("ok") else ""
        if tid:
            row.state = {**row.state, "team_id": tid}
            db.commit()
        if tid == team_id:
            return row
    return None


def _process_event(team_id: str, event: dict) -> None:
    """One message event through the engine — its own DB session (the request's session
    is gone by the time the pool runs this). Mirrors scan_slack_messages: same skips,
    same surface, same fingerprinting, same remediation gates. Never raises."""
    from .database import SessionLocal
    from . import saas_connectors as sc

    db = SessionLocal()
    try:
        connector = _connector_for_team(db, team_id)
        if connector is None:
            return                       # workspace not enrolled — ack'd and dropped
        # Same content filter as the pull scan: user messages with text; file_share
        # keeps its text and its attachments are scanned below.
        if (event.get("subtype") not in (None, "file_share") or event.get("bot_id")
                or not event.get("user") or not (event.get("text") or "").strip()):
            if not (event.get("subtype") == "file_share" and event.get("files")):
                return
        creds = sc.read_credentials(connector, db)
        token = (creds.get("bot_token") or "").strip()
        if not token:
            return
        hdrs = {"Authorization": f"Bearer {token}"}
        custom_pii = sc._tenant_custom_pii(db, connector)

        cid = event.get("channel", "")
        cname = ""
        try:
            info = sc._http_json(f"{_SLACK_API}/conversations.info?channel={cid}",
                                 headers=hdrs)
            cname = ((info.get("channel") or {}).get("name") or "") if info.get("ok") else ""
        except sc.ConnectorError:
            pass
        where = f"#{cname}" if cname else cid
        actor = sc._slack_actor({}, event["user"], hdrs) if event.get("user") else ""

        from .detectors import AnalysisInput, Surface
        from .service import run_analysis
        from . import content_origin

        findings: list[tuple[str, dict]] = []   # (ts to remediate, result)
        text = (event.get("text") or "").strip()
        if text:
            result = run_analysis(
                AnalysisInput(content=text, sender=actor, channel="slack", subject=where,
                              surface=Surface.COLLAB,
                              metadata={"custom_pii": custom_pii, "realtime": "events"}),
                persist=True, db=db, tenant_id=connector.tenant_id,
                persist_benign=False, use_judge=False)
            content_origin.store_fingerprint(
                db, connector.tenant_id, "slack", f"{cid}:{event.get('ts', '')}",
                where, actor, text, sensitive=result.get("finding_id") is not None)
            if result.get("finding_id") is not None:
                findings.append((event.get("ts", ""), result))
        for fo in (event.get("files") or []):
            if not sc._slack_readable_file(fo) or int(fo.get("size") or 0) > sc._MAX_FILE_BYTES:
                continue
            body, how = sc._slack_file_text(fo, hdrs)
            if not body.strip():
                continue
            fname = sc._slack_file_name(fo)
            result = run_analysis(
                AnalysisInput(content=body, sender=actor, channel="slack",
                              subject=f"{where}: {fname}", surface=Surface.COLLAB,
                              metadata={"custom_pii": custom_pii, "slack_file": fname,
                                        "extracted_via": how, "realtime": "events"}),
                persist=True, db=db, tenant_id=connector.tenant_id,
                persist_benign=False, use_judge=False)
            if result.get("finding_id") is not None:
                findings.append((event.get("ts", ""), result))

        # Remediation: identical gates to the pull scan (opt-in, admin user token,
        # Enterprise feature, confirmed-leak tier), audit-logged BEFORE it is counted.
        admin_token = sc._remediation_enabled(db, connector, creds)
        if admin_token:
            for ts, result in findings:
                if (not ts or sc._SEV_RANK.get(result.get("severity", ""), 0)
                        < sc._REMEDIATE_MIN_RANK):
                    continue
                ok, why = sc._slack_delete(cid, ts, admin_token)
                from . import audit_log
                audit_log.record(
                    db, connector.tenant_id, actor,
                    "slack.message_deleted" if ok else "slack.message_delete_failed",
                    f"{where}:{ts}",
                    {"finding_id": result.get("finding_id"),
                     "severity": result.get("severity"), "channel": where,
                     "connector": connector.label or connector.id, "realtime": True,
                     **({} if ok else {"error": why})})
                break                    # one message, one delete
    except Exception:                                             # noqa: BLE001
        _log.exception("slack event processing failed (team %s)", team_id)
    finally:
        db.close()


@router.post("/slack/events")
async def slack_events(request: Request):
    """Slack Events API receiver. Public endpoint; trust comes from the signature.
    Acks immediately (Slack redelivers anything slower than 3s) and processes on the
    worker pool. Configure the Slack app with this URL under Event Subscriptions and
    subscribe to message.channels + message.groups (the bot's existing read scopes
    already cover the payloads)."""
    if not settings.slack_signing_secret:
        raise HTTPException(status_code=400, detail="slack events not configured")
    body = await request.body()
    if not _verify(body, request.headers.get("X-Slack-Request-Timestamp", ""),
                   request.headers.get("X-Slack-Signature", "")):
        raise HTTPException(status_code=401, detail="bad signature")
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="not json")

    kind = payload.get("type", "")
    if kind == "url_verification":       # Slack's one-time endpoint handshake
        return {"challenge": payload.get("challenge", "")}
    if kind != "event_callback":
        return {"ok": True}
    if _already_seen(payload.get("event_id", "")):
        return {"ok": True}
    event = payload.get("event") or {}
    if event.get("type") != "message":
        return {"ok": True}
    team_id = payload.get("team_id") or payload.get("enterprise_id") or ""
    if team_id:
        _submit(_process_event, team_id, event)
    return {"ok": True}
