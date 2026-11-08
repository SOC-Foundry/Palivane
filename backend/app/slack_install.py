""""Add to Slack" — OAuth v2 install flow for the published Palivane Slack app.

The operator registers ONE Slack app (PALIVANE_SLACK_CLIENT_ID/SECRET); a tenant admin
clicks "Add to Slack" in Settings, approves the read scopes in their own workspace, and
the OAuth callback stores that workspace's bot token as a `slack_messages` connector —
no hand-built per-tenant Slack app, no pasted token.

Tenancy across the redirect rides a signed state token (typ=slack_install, 10-min TTL),
the same pattern as the OIDC login state: the callback is necessarily unauthenticated
(Slack redirects the admin's browser to it), so the state — minted by an authenticated
admin — is what binds the install to an org. A signed state alone can be handed to anyone:
an org's install link, approved by an admin at another company, would attach THEIR
workspace to the link's org. So, as for SSO, the state also carries the hash of a nonce
set as a cookie in the browser that asked for the link, and the callback requires it.

One workspace belongs to one org: an install is refused when the workspace is already
installed for another org, and the connector records the workspace and app ids that
slack_events routes on. The bot token is encrypted at rest via the connector's normal
credential storage and never returned by the API.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import urllib.parse

from .config import settings
from .security import create_token, decode_token, TokenError

BIND_COOKIE = "palivane_slack_bind"
BIND_TTL = 600
BIND_PATH = "/api/slack"

_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
_ACCESS_URL = "https://slack.com/api/oauth.v2.access"
# Scan scopes — must match the published app's manifest. Nothing that posts, edits, or
# deletes in the workspace. files:read lets the scan open attachments; channels:join backs
# the per-org "Scan every public channel" setting (off by default), as for a pasted token.
_SCOPES = ("channels:read,groups:read,channels:history,groups:history,"
           "users:read,users:read.email,files:read,channels:join")


class InstallError(Exception):
    """The install could not be completed (bad state, Slack refusal) — user-safe text."""


def configured() -> bool:
    return bool(settings.slack_client_id and settings.slack_client_secret)


def _bind_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()


def install_url(tenant_id: int, redirect_uri: str) -> tuple[str, str]:
    """(the slack.com authorize URL for this org, the bind nonce to set as BIND_COOKIE in
    the requesting browser). The state carries the tenant and the nonce's hash."""
    nonce = secrets.token_urlsafe(24)
    state = create_token({"typ": "slack_install", "tenant_id": tenant_id,
                          "bind": _bind_hash(nonce)}, ttl=BIND_TTL)
    return _AUTHORIZE_URL + "?" + urllib.parse.urlencode({
        "client_id": settings.slack_client_id,
        "scope": _SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
    }), nonce


def workspace_ids(state: dict) -> tuple[str, str]:
    """(team_id, enterprise_id) a connector's state records for its workspace."""
    return str(state.get("team_id") or ""), str(state.get("enterprise_id") or "")


def _installed_elsewhere(db, tenant_id: int, team_id: str, enterprise_id: str) -> bool:
    """Whether another org holds an active app install of this workspace (or Grid org)."""
    from .models import SaasConnector
    rows = (db.query(SaasConnector)
              .filter(SaasConnector.platform == "slack_messages",
                      SaasConnector.active.is_(True),
                      SaasConnector.tenant_id != tenant_id).all())
    for row in rows:
        st = row.state or {}
        if not st.get("app_installed"):
            continue
        t, e = workspace_ids(st)
        if (team_id and t == team_id) or (enterprise_id and e == enterprise_id):
            return True
    return False


def complete_install(db, code: str, state: str, redirect_uri: str, bind_nonce: str = ""):
    """Validate the state (and that this browser asked for it), exchange the code for a
    bot token, and upsert the tenant's slack_messages connector. Returns the connector
    row. Raises InstallError on any failure (the callback turns it into a redirect, never
    a stack trace)."""
    try:
        payload = decode_token(state)
    except TokenError:
        raise InstallError("invalid or expired install state")
    if payload.get("typ") != "slack_install":
        raise InstallError("not a Slack install state")
    want = str(payload.get("bind") or "")
    if not bind_nonce or not want or not hmac.compare_digest(_bind_hash(bind_nonce), want):
        raise InstallError("the install was not started from this browser")
    tenant_id = int(payload.get("tenant_id", 0))
    if not tenant_id:
        raise InstallError("install state carries no org")
    if not code:
        raise InstallError("Slack returned no authorization code")

    from .saas_connectors import _http_json, ConnectorError, store_credentials
    body = urllib.parse.urlencode({
        "code": code,
        "client_id": settings.slack_client_id,
        "client_secret": settings.slack_client_secret,
        "redirect_uri": redirect_uri,
    }).encode()
    try:
        data = _http_json(_ACCESS_URL, data=body,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
    except ConnectorError as e:
        raise InstallError(str(e))
    if not data.get("ok"):
        raise InstallError(f"Slack refused the code exchange: {data.get('error', 'unknown')}")
    token = (data.get("access_token") or "").strip()   # xoxb-… bot token
    if not token:
        raise InstallError("Slack returned no bot token")
    # Workspace installs carry `team`; Enterprise Grid org-wide installs carry
    # `enterprise` instead (team is null) — the app is org-deploy-enabled, so both arrive.
    team = data.get("team") or data.get("enterprise") or {}
    label = (team.get("name") or team.get("id") or "workspace").strip()
    team_id = str((data.get("team") or {}).get("id") or "")
    enterprise_id = str((data.get("enterprise") or {}).get("id") or "")
    if not (team_id or enterprise_id):
        raise InstallError("Slack returned no workspace id")
    if _installed_elsewhere(db, tenant_id, team_id, enterprise_id):
        raise InstallError("this Slack workspace is already connected to another org")

    from .models import SaasConnector
    row = (db.query(SaasConnector)
             .filter(SaasConnector.tenant_id == tenant_id,
                     SaasConnector.platform == "slack_messages",
                     SaasConnector.label == label).first())
    if not row:
        row = SaasConnector(tenant_id=tenant_id, platform="slack_messages", label=label)
        db.add(row)
    store_credentials(row, {"bot_token": token}, db)
    # What slack_events routes on: only an app install receives the published app's events.
    row.state = {**(row.state or {}), "team_id": team_id, "enterprise_id": enterprise_id,
                 "app_installed": True, "api_app_id": str(data.get("app_id") or "")}
    row.active = True
    db.commit()
    db.refresh(row)

    from . import audit_log
    audit_log.record(db, tenant_id, "slack-oauth", "connector.slack_install",
                     detail={"team": label, "team_id": team_id or enterprise_id,
                             "connector_id": row.id})
    return row
