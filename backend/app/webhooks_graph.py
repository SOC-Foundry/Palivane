"""Change-notification receivers — the on-write paths for SharePoint/OneDrive (Microsoft
Graph subscriptions) and Google Drive (changes.watch channels).

The cron pull sees a leaked document minutes-to-hours after it lands; Graph subscriptions
(created and renewed by the sharepoint_files sync) tell us the moment a drive changes.
A notification carries no content — only "this resource changed" — so the handler's whole
job is to run the EXISTING per-drive delta scan for that drive right now. Same scanner,
same findings, same watermark discipline; only the trigger differs, and the cron sync
remains the safety net for anything a notification misses.

Trust model: the endpoint is public (Graph posts to it), so trust comes from clientState —
a signed token minted at subscription time binding the connector id. Anything that doesn't
verify is dropped (and still 202'd: Graph retries on non-2xx, and retrying garbage is
just more garbage). Graph's endpoint-validation handshake (POST ?validationToken=…) is
answered with the token in plain text, as the contract requires.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

_log = logging.getLogger("palivane.graph_webhook")
router = APIRouter(prefix="/api", tags=["webhooks"])

_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="graph-notify")
_submit = _EXECUTOR.submit          # tests monkeypatch this to run inline

# Graph sends bursts (one notification per change, often many per save). Debounce per
# (connector, drive): one scan pass per window covers every change in it, because the
# delta query reads everything since the watermark anyway.
_RECENT: dict[tuple[int, str], float] = {}
_RECENT_LOCK = threading.Lock()
_DEBOUNCE_SECS = 20


def _debounced(connector_id: int, drive_id: str) -> bool:
    now = time.time()
    key = (connector_id, drive_id)
    with _RECENT_LOCK:
        if len(_RECENT) > 4096:
            for k in [k for k, t in _RECENT.items() if t < now]:
                _RECENT.pop(k, None)
        if _RECENT.get(key, 0) > now:
            return True
        _RECENT[key] = now + _DEBOUNCE_SECS
        return False


def _scan_notified_drive(connector_id: int, sub_id: str) -> None:
    """Run the per-drive delta scan a notification pointed at — its own session, never
    raises (a failed on-write scan is caught up by the next cron sync)."""
    from .database import SessionLocal, bind_tenant
    from . import saas_connectors as sc

    db = SessionLocal()
    try:
        from .models import SaasConnector
        row = db.get(SaasConnector, connector_id)
        if row is None or not row.active or row.platform != "sharepoint_files":
            return
        bind_tenant(db, row.tenant_id)
        meta = (row.state.get("graph_subs") or {}).get(sub_id) or {}
        did = meta.get("drive", "")
        if not did or _debounced(connector_id, did):
            return
        creds = sc.read_credentials(row, db)
        token = sc._microsoft_access_token(creds)
        hdrs = {"Authorization": f"Bearer {token}"}
        deltas = dict(row.state.get("deltas") or {})
        scanned, findings, skipped, _ = sc._scan_drive(
            db, row, hdrs, sc._tenant_custom_pii(db, row), did,
            meta.get("name", "library"), deltas)
        row.state = {**row.state, "deltas": deltas}
        db.commit()
        if findings:
            _log.info("graph notify: drive %s scanned %d files, %d findings",
                      did[:24], scanned, findings)
    except Exception:                                             # noqa: BLE001
        _log.exception("graph notification scan failed (connector %s)", connector_id)
    finally:
        db.close()


def _sync_notified_connector(connector_id: int) -> None:
    """Google Drive notifications are opaque ("something changed"), and the gdrive scan
    is already watermark-incremental — so the on-write path is simply: run that
    connector's normal sync now. Own session; never raises (cron is the safety net)."""
    from .database import SessionLocal, bind_tenant
    from . import saas_connectors as sc

    db = SessionLocal()
    try:
        from .models import SaasConnector
        row = db.get(SaasConnector, connector_id)
        if row is None or not row.active or row.platform != "gdrive_files":
            return
        if _debounced(connector_id, "gdrive"):
            return
        bind_tenant(db, row.tenant_id)
        sc.sync_connector(db, row)
    except Exception:                                             # noqa: BLE001
        _log.exception("gdrive notification sync failed (connector %s)", connector_id)
    finally:
        db.close()


@router.post("/webhooks/gdrive")
async def gdrive_notifications(request: Request):
    """Google Drive changes.watch receiver. Drive sends headers, not a body: the channel
    token (our signed connector binding) authenticates; resource-state 'sync' is the
    channel handshake and is just acked. Always 200 fast — Drive retries non-2xx."""
    from .security import TokenError, decode_token
    state = request.headers.get("X-Goog-Resource-State", "")
    try:
        claims = decode_token(request.headers.get("X-Goog-Channel-Token", ""))
    except TokenError:
        return JSONResponse(status_code=200, content={"ok": True})   # unauthenticated noise
    if claims.get("typ") == "gdrive_watch" and state and state != "sync":
        connector_id = int(claims.get("connector_id") or 0)
        if connector_id:
            _submit(_sync_notified_connector, connector_id)
    return JSONResponse(status_code=200, content={"ok": True})


@router.post("/webhooks/graph")
async def graph_notifications(request: Request):
    """Graph change notifications + the endpoint-validation handshake. Always answers
    fast (Graph gives ~10s before it marks the endpoint dead and retries)."""
    token = request.query_params.get("validationToken")
    if token is not None:
        return PlainTextResponse(content=token)   # handshake: echo, text/plain, 200

    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse(status_code=202, content={"ok": True})
    from .security import TokenError, decode_token
    for note in (payload.get("value") or [])[:50]:
        try:
            claims = decode_token(str(note.get("clientState") or ""))
        except TokenError:
            continue                     # unauthenticated noise — drop, don't 4xx
        if claims.get("typ") != "graph_sub":
            continue
        connector_id = int(claims.get("connector_id") or 0)
        sub_id = str(note.get("subscriptionId") or "")
        if connector_id and sub_id:
            _submit(_scan_notified_drive, connector_id, sub_id)
    return JSONResponse(status_code=202, content={"ok": True})
