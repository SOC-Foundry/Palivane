"""GitHub push webhooks: the on-push path for the GitHub secret-scanning connector.

The scheduled scan sees a commit within its interval; a push event tells us the moment it lands. The
event only NAMES what changed, so the handler's whole job is to read those commits the way a scheduled
scan reads them (github_secrets.scan_push). The scheduled scan stays as the safety net.

Trust model: the endpoint is public (GitHub posts to it), so trust comes from the signature. Each
connector has its own webhook secret, generated here and shown to the admin once; GitHub signs the raw
body with it (X-Hub-Signature-256, HMAC-SHA256) and nothing is parsed before that verifies. Every
failure, including an unknown connector or one with no secret set, answers the same 401. Repeated
failures from one address are cut off. A delivery GitHub retries is processed once.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .auth import _client_ip, require_admin
from .config import settings
from .database import get_db
from .models import SaasConnector, User

_log = logging.getLogger("palivane.github_webhook")
router = APIRouter(prefix="/api", tags=["webhooks"])

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="github-push")
_submit = _EXECUTOR.submit          # tests monkeypatch this to run inline
_MAX_BODY = 5_000_000               # GitHub caps a payload at 25 MB; a push event is far smaller
_SCAN_SECS = 60.0                   # a push scan stops here

_SEEN: dict[str, float] = {}        # X-GitHub-Delivery -> expiry; GitHub retries a delivery it thinks failed
_SEEN_LOCK = threading.Lock()
_SEEN_TTL = 3600
_FAILS: dict[str, list[float]] = {}  # ip -> recent bad-signature times
_FAIL_LIMIT, _FAIL_WINDOW = 30, 60


def sign(secret: str, body: bytes) -> str:
    """GitHub's signature header value for `body`."""
    return "sha256=" + hmac.new(secret.encode(), body, sha256).hexdigest()


def _already_seen(delivery: str) -> bool:
    if not delivery:
        return False
    now = time.time()
    with _SEEN_LOCK:
        if len(_SEEN) > 4096:
            for k in [k for k, exp in _SEEN.items() if exp < now]:
                _SEEN.pop(k, None)
        if _SEEN.get(delivery, 0) > now:
            return True
        _SEEN[delivery] = now + _SEEN_TTL
        return False


def _too_many_failures(ip: str) -> bool:
    now = time.time()
    with _SEEN_LOCK:
        recent = [t for t in _FAILS.get(ip, []) if t > now - _FAIL_WINDOW]
        _FAILS[ip] = recent
        if len(_FAILS) > 4096:
            for k in [k for k, v in _FAILS.items() if not v or v[-1] < now - _FAIL_WINDOW]:
                _FAILS.pop(k, None)
        return len(recent) >= _FAIL_LIMIT


def _note_failure(ip: str) -> None:
    with _SEEN_LOCK:
        _FAILS.setdefault(ip, []).append(time.time())


def _secret_for(connector_id: int) -> str:
    """The connector's webhook secret ("" for anything that should not accept pushes). Own session:
    the endpoint has no signed-in user, and the credential is sealed under the tenant's key."""
    from . import saas_connectors as sc
    from .database import SessionLocal
    db = SessionLocal()
    try:
        row = db.get(SaasConnector, connector_id)
        if row is None or not row.active or row.platform != "github_secrets":
            return ""
        return str(sc.read_credentials(row, db).get("webhook_secret") or "")
    except Exception:                                             # noqa: BLE001
        return ""
    finally:
        db.close()


def _process_push(connector_id: int, payload: dict) -> None:
    """Scan a push in its own session. Never raises: a failed push scan is caught up by the next
    scheduled one."""
    from . import github_secrets, saas_connectors as sc
    from .database import SessionLocal, bind_tenant, clear_tenant
    db = SessionLocal()
    token = github_secrets.max_seconds.set(_SCAN_SECS)
    try:
        row = db.get(SaasConnector, connector_id)
        if row is None or not row.active or row.platform != "github_secrets":
            return
        bind_tenant(db, row.tenant_id)
        result = github_secrets.scan_push(db, row, sc.read_credentials(row, db), payload)
        if result.get("findings"):
            _log.info("github push: %s", result)
    except Exception:                                             # noqa: BLE001
        _log.exception("github push scan failed (connector %s)", connector_id)
    finally:
        github_secrets.max_seconds.reset(token)
        clear_tenant()
        db.close()


@router.post("/webhooks/github/{connector_id}")
async def github_push(connector_id: int, request: Request):
    """GitHub webhook receiver (subscribe to the `push` event, content type application/json)."""
    ip = _client_ip(request)
    if _too_many_failures(ip):
        raise HTTPException(status_code=429, detail="too many bad requests")
    body = await request.body()
    if len(body) > _MAX_BODY:
        raise HTTPException(status_code=413, detail="payload too large")
    secret = await asyncio.to_thread(_secret_for, connector_id)
    # an unknown connector does the same work and fails the same way as a wrong signature
    expected = sign(secret or "-", body)
    if not secret or not hmac.compare_digest(expected, request.headers.get("X-Hub-Signature-256", "")):
        _note_failure(ip)
        raise HTTPException(status_code=401, detail="bad signature")
    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return {"ok": True, "pong": True}
    if event != "push":
        return {"ok": True, "ignored": event}
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="not json")
    if _already_seen(request.headers.get("X-GitHub-Delivery", "")):
        return {"ok": True, "duplicate": True}
    _submit(_process_push, connector_id, payload)
    return {"ok": True}


# --- admin: turn it on, rotate it, turn it off --------------------------------------------------

def _github_connector(db: Session, current: User, connector_id: int) -> SaasConnector:
    row = db.get(SaasConnector, connector_id)
    if row is None or row.tenant_id != current.tenant_id or row.platform != "github_secrets":
        raise HTTPException(status_code=404, detail="connector not found")
    return row


@router.post("/discovery/connectors/{connector_id}/github-webhook")
def enable_github_webhook(connector_id: int, request: Request, current: User = Depends(require_admin),
                          db: Session = Depends(get_db)):
    """Generate (or rotate) this connector's webhook secret and return what GitHub needs. The secret is
    shown here once; it is not readable again, so a lost one is replaced, not recovered."""
    from . import audit_log
    from .saas_connectors import merge_options
    row = _github_connector(db, current, connector_id)
    secret = secrets.token_urlsafe(32)
    merge_options(row, {"webhook_secret": secret}, db)
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "connector.github_webhook_enabled",
                     target=row.label or str(row.id))
    base = settings.public_base_url or str(request.base_url).rstrip("/")
    return {"url": f"{base}/api/webhooks/github/{row.id}", "secret": secret,
            "content_type": "application/json", "events": ["push"]}


@router.delete("/discovery/connectors/{connector_id}/github-webhook")
def disable_github_webhook(connector_id: int, current: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    from . import audit_log
    from .saas_connectors import merge_options
    row = _github_connector(db, current, connector_id)
    merge_options(row, {"webhook_secret": ""}, db)
    db.commit()
    audit_log.record(db, current.tenant_id, current.email, "connector.github_webhook_disabled",
                     target=row.label or str(row.id))
    return {"ok": True}
