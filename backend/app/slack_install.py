""""Add to Slack" — OAuth v2 install flow for the published Palivane Slack app.

The operator registers ONE Slack app (PALIVANE_SLACK_CLIENT_ID/SECRET); a tenant admin
clicks "Add to Slack" in Settings, approves the read scopes in their own workspace, and
the OAuth callback stores that workspace's bot token as a `slack_messages` connector —
no hand-built per-tenant Slack app, no pasted token.

Tenancy across the redirect rides a signed state token (typ=slack_install, 10-min TTL),
the same pattern as the OIDC login state: the callback is necessarily unauthenticated
(Slack redirects the admin's browser to it), so the state — minted by an authenticated
admin — is what binds the install to an org. The bot token is encrypted at rest via the
connector's normal credential storage and never returned by the API.
"""

from __future__ import annotations

import urllib.parse

from .config import settings
from .security import create_token, decode_token, TokenError

_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
_ACCESS_URL = "https://slack.com/api/oauth.v2.access"
# Read-only scan scopes — must match the published app's manifest. No write scopes:
# Phase 1 never posts, edits, or deletes anything in the workspace.
_SCOPES = ("channels:read,groups:read,channels:history,groups:history,"
           "users:read,users:read.email")


class InstallError(Exception):
    """The install could not be completed (bad state, Slack refusal) — user-safe text."""


def configured() -> bool:
    return bool(settings.slack_client_id and settings.slack_client_secret)


def install_url(tenant_id: int, redirect_uri: str) -> str:
    """The slack.com authorize URL for this org, with the tenant bound into the state."""
    state = create_token({"typ": "slack_install", "tenant_id": tenant_id}, ttl=600)
    return _AUTHORIZE_URL + "?" + urllib.parse.urlencode({
        "client_id": settings.slack_client_id,
        "scope": _SCOPES,
        "redirect_uri": redirect_uri,
        "state": state,
    })


def complete_install(db, code: str, state: str, redirect_uri: str):
    """Validate the state, exchange the code for a bot token, and upsert the tenant's
    slack_messages connector. Returns the connector row. Raises InstallError on any
    failure (the callback turns it into a redirect, never a stack trace)."""
    try:
        payload = decode_token(state)
    except TokenError:
        raise InstallError("invalid or expired install state")
    if payload.get("typ") != "slack_install":
        raise InstallError("not a Slack install state")
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
    team = data.get("team") or {}
    label = (team.get("name") or team.get("id") or "workspace").strip()

    from .models import SaasConnector
    row = (db.query(SaasConnector)
             .filter(SaasConnector.tenant_id == tenant_id,
                     SaasConnector.platform == "slack_messages",
                     SaasConnector.label == label).first())
    if not row:
        row = SaasConnector(tenant_id=tenant_id, platform="slack_messages", label=label)
        db.add(row)
    store_credentials(row, {"bot_token": token})
    row.active = True
    db.commit()
    db.refresh(row)

    from . import audit_log
    audit_log.record(db, tenant_id, "slack-oauth", "connector.slack_install",
                     detail={"team": label, "team_id": team.get("id", ""),
                             "connector_id": row.id})
    return row
