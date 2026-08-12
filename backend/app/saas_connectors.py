"""Live OAuth-grant pulls from SaaS admin APIs — the recurring version of the one-shot
POST /api/discovery/oauth-grants ingest.

Where AI tools plug into SaaS via OAuth they leave no traffic a proxy or extension can see;
the grant inventory lives in each platform's admin API. A SaasConnector row stores a
platform credential (encrypted at rest); sync_connector() pulls the current grants and runs
them through the same ingest_oauth_grants() path as a manual export, so live pulls and
one-shot uploads land identically in discovery.

Platform registry: PLATFORMS maps a key to its fetch function + the credential fields the
UI should collect. Each fetcher is fetch(creds) -> [{app_name, app_id, user, provider,
scopes}]; the ingest classifies every app against the catalog, so fetchers pull the whole
grant inventory and do not pre-filter for AI. Live fetchers: Google Workspace (service
account with domain-wide delegation), Microsoft 365 / Entra ID (Graph client credentials),
Slack (org-admin token), Salesforce (connected-app client credentials). Notion is
registered manual-only — its public API has no grant-enumeration surface (see fetch_notion).
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from authlib.jose import jwt

from .crypto import decrypt, encrypt
from .discovery import ingest_oauth_grants
from .schemas import OAuthGrant

_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_ADMIN_BASE = "https://admin.googleapis.com/admin/directory/v1"
_GOOGLE_SCOPES = ("https://www.googleapis.com/auth/admin.directory.user.readonly "
                  "https://www.googleapis.com/auth/admin.directory.user.security")
_MAX_USERS_PER_SYNC = 2000   # bounds sync runtime on huge tenants; truncation is reported


class ConnectorError(Exception):
    """A sync failed in a way the admin needs to see (bad credential, API denial)."""


def _http_json(url: str, *, headers: dict | None = None, data: bytes | None = None,
               timeout: int = 20) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:200]
        raise ConnectorError(f"HTTP {e.code} from {urllib.parse.urlparse(url).netloc}: {detail}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ConnectorError(f"request failed: {e}")


# --- Google Workspace ------------------------------------------------------------------

def _google_access_token(creds: dict) -> str:
    """Service-account JWT grant (RFC 7523), impersonating the admin via `sub` — the
    domain-wide-delegation flow Google requires for Admin SDK reads."""
    sa = creds.get("service_account_json") or {}
    if isinstance(sa, str):                      # UI may store the key file as a string
        try:
            sa = json.loads(sa)
        except ValueError:
            raise ConnectorError("service_account_json is not valid JSON")
    admin = (creds.get("admin_email") or "").strip()
    if not sa.get("client_email") or not sa.get("private_key") or not admin:
        raise ConnectorError("google_workspace needs service_account_json (client_email, "
                             "private_key) and admin_email")
    now = int(time.time())
    assertion = jwt.encode(
        {"alg": "RS256"},
        {"iss": sa["client_email"], "sub": admin, "scope": _GOOGLE_SCOPES,
         "aud": _GOOGLE_TOKEN_URL, "iat": now, "exp": now + 3600},
        sa["private_key"])
    body = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion.decode() if isinstance(assertion, bytes) else assertion,
    }).encode()
    tok = _http_json(_GOOGLE_TOKEN_URL, data=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    if not tok.get("access_token"):
        raise ConnectorError(f"token exchange returned no access_token: {tok}")
    return tok["access_token"]


def fetch_google_workspace(creds: dict) -> list[dict]:
    """Pull every user's third-party OAuth tokens from the Admin SDK. Returns normalized
    grant dicts; raises ConnectorError on auth/API failure."""
    token = _google_access_token(creds)
    hdrs = {"Authorization": f"Bearer {token}"}

    users: list[str] = []
    page = ""
    while len(users) < _MAX_USERS_PER_SYNC:
        q = {"customer": "my_customer", "maxResults": "500",
             "projection": "basic", "viewType": "admin_view"}
        if page:
            q["pageToken"] = page
        data = _http_json(f"{_GOOGLE_ADMIN_BASE}/users?{urllib.parse.urlencode(q)}", headers=hdrs)
        users += [u.get("primaryEmail", "") for u in data.get("users", []) if u.get("primaryEmail")]
        page = data.get("nextPageToken", "")
        if not page:
            break
    truncated = bool(page)

    grants: list[dict] = []
    for email in users[:_MAX_USERS_PER_SYNC]:
        data = _http_json(f"{_GOOGLE_ADMIN_BASE}/users/{urllib.parse.quote(email)}/tokens",
                          headers=hdrs)
        for t in data.get("items", []):
            grants.append({"app_name": t.get("displayText", ""),
                           "app_id": t.get("clientId", ""),
                           "user": email, "provider": "google",
                           "scopes": t.get("scopes", []) or []})
    if truncated:
        grants.append({"app_name": f"__truncated_at_{_MAX_USERS_PER_SYNC}_users__",
                       "app_id": "", "user": "", "provider": "google", "scopes": []})
    return grants


# --- Microsoft 365 / Entra ID -----------------------------------------------------------

_MS_LOGIN_BASE = "https://login.microsoftonline.com"
_MS_GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _microsoft_access_token(creds: dict) -> str:
    """Client-credentials grant against the tenant's v2.0 token endpoint. Needs an app
    registration with *application* Graph permissions Application.Read.All +
    Directory.Read.All (admin-consented)."""
    tenant = (creds.get("tenant_id") or "").strip()
    client_id = (creds.get("client_id") or "").strip()
    secret = creds.get("client_secret") or ""
    if not tenant or not client_id or not secret:
        raise ConnectorError("microsoft_365 needs tenant_id, client_id and client_secret")
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": client_id,
        "client_secret": secret, "scope": "https://graph.microsoft.com/.default",
    }).encode()
    tok = _http_json(f"{_MS_LOGIN_BASE}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token",
                     data=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    if not tok.get("access_token"):
        raise ConnectorError(f"token exchange returned no access_token: {tok}")
    return tok["access_token"]


def fetch_microsoft_365(creds: dict) -> list[dict]:
    """Enumerate the tenant's OAuth footprint from Microsoft Graph: servicePrincipals for
    app identity, oauth2PermissionGrants for delegated (user-consented) grants, and each
    service principal's appRoleAssignments for application (app-only) grants. Note: the
    ingest grant shape carries no timestamp, so grant times (where Graph has them) are not
    propagated."""
    token = _microsoft_access_token(creds)
    hdrs = {"Authorization": f"Bearer {token}"}

    # Service principals: object id -> {appId, displayName, appRoles}. appRoles lets us
    # resolve application-grant role GUIDs to names (e.g. Mail.Read) when the resource SP
    # is in the page we saw.
    sps: dict[str, dict] = {}
    url = (f"{_MS_GRAPH_BASE}/servicePrincipals?"
           + urllib.parse.urlencode({"$select": "id,appId,displayName,appRoles",
                                     "$top": "999"}))
    while url and len(sps) < _MAX_USERS_PER_SYNC:
        data = _http_json(url, headers=hdrs)
        for sp in data.get("value", []):
            if sp.get("id"):
                sps[sp["id"]] = sp
        url = data.get("@odata.nextLink", "")
    truncated = bool(url)
    role_names = {sp_id: {r.get("id"): r.get("value") for r in (sp.get("appRoles") or [])}
                  for sp_id, sp in sps.items()}

    users: dict[str, str] = {}   # principal object id -> UPN (cached; falls back to the id)

    def _upn(pid: str) -> str:
        if not pid:
            return ""
        if pid not in users:
            try:
                u = _http_json(f"{_MS_GRAPH_BASE}/users/{urllib.parse.quote(pid)}"
                               "?$select=userPrincipalName", headers=hdrs)
                users[pid] = u.get("userPrincipalName") or pid
            except ConnectorError:      # deleted user / non-user principal
                users[pid] = pid
        return users[pid]

    grants: list[dict] = []

    # Delegated grants: one row per (client app, consenting principal).
    url = f"{_MS_GRAPH_BASE}/oauth2PermissionGrants?%24top=999"
    while url:
        data = _http_json(url, headers=hdrs)
        for g in data.get("value", []):
            sp = sps.get(g.get("clientId") or "", {})
            who = _upn(g.get("principalId") or "") if g.get("consentType") == "Principal" else ""
            grants.append({"app_name": sp.get("displayName", "") or "",
                           "app_id": sp.get("appId", "") or "",
                           "user": who, "provider": "microsoft",
                           "scopes": (g.get("scope") or "").split()})
        url = data.get("@odata.nextLink", "")

    # Application grants: app roles assigned *to* each client SP, one row per client app
    # with its resolved role names combined (falls back to the role GUID).
    for sp_id, sp in sps.items():
        roles: list[str] = []
        url = (f"{_MS_GRAPH_BASE}/servicePrincipals/{urllib.parse.quote(sp_id)}"
               "/appRoleAssignments?%24top=999")
        while url:
            data = _http_json(url, headers=hdrs)
            for a in data.get("value", []):
                r = (role_names.get(a.get("resourceId") or "", {}).get(a.get("appRoleId"))
                     or a.get("appRoleId") or "")
                if r and r not in roles:
                    roles.append(r)
            url = data.get("@odata.nextLink", "")
        if roles:
            grants.append({"app_name": sp.get("displayName", "") or "",
                           "app_id": sp.get("appId", "") or "",
                           "user": "", "provider": "microsoft", "scopes": roles})

    if truncated:
        grants.append({"app_name": f"__truncated_at_{_MAX_USERS_PER_SYNC}_service_principals__",
                       "app_id": "", "user": "", "provider": "microsoft", "scopes": []})
    return grants


# --- Slack -------------------------------------------------------------------------------

_SLACK_API_BASE = "https://slack.com/api"

# Slack signals failure with HTTP 200 + ok:false; map the usual errors to actions.
_SLACK_ERROR_HINTS = {
    "invalid_auth": "token is invalid or revoked — reissue the org-admin user token",
    "not_authed": "no token was accepted — check admin_token",
    "token_revoked": "token was revoked — reissue the org-admin user token",
    "missing_scope": "token lacks admin.apps:read — reinstall the admin app with that scope",
    "not_an_admin": "token's user is not an org admin",
    "feature_not_enabled": "admin.apps.* needs an Enterprise Grid org",
    "team_not_found": "team_id does not match a workspace in this org",
}


def fetch_slack(creds: dict) -> list[dict]:
    """Enumerate org-approved Slack apps and their scopes via admin.apps.approved.list
    (org-admin user token with admin.apps:read; Enterprise Grid). Slack's admin API lists
    apps at org/workspace approval level, not per-granting-user, so `user` is empty."""
    token = (creds.get("admin_token") or "").strip()
    if not token:
        raise ConnectorError("slack needs admin_token (org-admin user token with the "
                             "admin.apps:read scope)")
    team = (creds.get("team_id") or "").strip()
    hdrs = {"Authorization": f"Bearer {token}"}

    grants: list[dict] = []
    cursor = ""
    while True:
        q = {"limit": "100"}
        if team:
            q["team_id"] = team
        if cursor:
            q["cursor"] = cursor
        data = _http_json(f"{_SLACK_API_BASE}/admin.apps.approved.list?"
                          + urllib.parse.urlencode(q), headers=hdrs)
        if not data.get("ok"):
            err = data.get("error", "unknown_error")
            hint = _SLACK_ERROR_HINTS.get(err, "see https://docs.slack.dev/reference/methods/admin.apps.approved.list")
            raise ConnectorError(f"Slack API error {err}: {hint}")
        for entry in data.get("approved_apps", []):
            app = entry.get("app") or {}
            grants.append({"app_name": app.get("name", "") or "",
                           "app_id": app.get("id", "") or "",
                           "user": "", "provider": "slack",
                           "scopes": [s.get("name", "") for s in (entry.get("scopes") or [])
                                      if s.get("name")]})
        cursor = (data.get("response_metadata") or {}).get("next_cursor", "")
        if not cursor:
            break
    return grants


# --- Salesforce --------------------------------------------------------------------------

_SF_API_VERSION = "v60.0"


def _salesforce_access(creds: dict) -> tuple[str, str]:
    """Connected-app client-credentials grant against the org's My Domain token endpoint.
    Returns (instance_url, access_token)."""
    instance = (creds.get("instance_url") or "").strip().rstrip("/")
    client_id = (creds.get("client_id") or "").strip()
    secret = creds.get("client_secret") or ""
    if not instance or not client_id or not secret:
        raise ConnectorError("salesforce needs instance_url (https://<mydomain>.my.salesforce.com), "
                             "client_id and client_secret of a connected app with the "
                             "client-credentials flow enabled")
    if not instance.startswith("http"):
        instance = f"https://{instance}"
    body = urllib.parse.urlencode({"grant_type": "client_credentials",
                                   "client_id": client_id,
                                   "client_secret": secret}).encode()
    tok = _http_json(f"{instance}/services/oauth2/token", data=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    if not tok.get("access_token"):
        raise ConnectorError(f"token exchange returned no access_token: {tok}")
    return (tok.get("instance_url") or instance).rstrip("/"), tok["access_token"]


def fetch_salesforce(creds: dict) -> list[dict]:
    """Query the OauthToken sObject for third-party app grants: one row per (connected app,
    user) token. Salesforce does not expose per-token OAuth scopes on OauthToken, so
    `scopes` is empty and broad-scope flagging never triggers for this platform. The
    connected app's run-as user needs API Enabled + Manage Users (to read OauthToken)."""
    instance, token = _salesforce_access(creds)
    hdrs = {"Authorization": f"Bearer {token}"}
    soql = "SELECT AppName, AppMenuItemId, User.Username FROM OauthToken"
    url = (f"{instance}/services/data/{_SF_API_VERSION}/query?"
           + urllib.parse.urlencode({"q": soql}))
    grants: list[dict] = []
    while url:
        data = _http_json(url, headers=hdrs)
        for rec in data.get("records", []):
            grants.append({"app_name": rec.get("AppName", "") or "",
                           "app_id": rec.get("AppMenuItemId", "") or "",
                           "user": ((rec.get("User") or {}).get("Username") or ""),
                           "provider": "salesforce", "scopes": []})
        nxt = data.get("nextRecordsUrl", "")
        url = f"{instance}{nxt}" if (nxt and not data.get("done", True)) else ""
    return grants


# --- Notion (manual export only) ---------------------------------------------------------

def fetch_notion(creds: dict) -> list[dict]:
    """Notion has no admin API for enumerating a workspace's installed third-party
    integrations or their OAuth grants: the public API is scoped to a single integration's
    own token, the SCIM API covers users/groups only, and the Enterprise audit log is a
    UI/SIEM export, not a grant inventory (verified Aug 2026). Registered so the platform
    is visible in the UI, but a sync can only point at the manual path."""
    raise ConnectorError(
        "Notion's public API has no endpoint that lists a workspace's installed "
        "integrations or OAuth grants — live pulls are not possible. Export the list from "
        "Settings & members -> Connections and upload it via POST /api/discovery/oauth-grants.")


PLATFORMS: dict[str, dict] = {
    "google_workspace": {
        "label": "Google Workspace",
        "fetch": fetch_google_workspace,
        "credential_fields": ["service_account_json", "admin_email"],
        "setup": "Service account with domain-wide delegation; grant it the "
                 "admin.directory.user.readonly and admin.directory.user.security scopes "
                 "in Admin Console, and set admin_email to the admin it impersonates.",
    },
    "microsoft_365": {
        "label": "Microsoft 365 / Entra ID",
        "fetch": fetch_microsoft_365,
        "credential_fields": ["tenant_id", "client_id", "client_secret"],
        "setup": "Entra ID app registration with a client secret and admin-consented "
                 "*application* Graph permissions Application.Read.All and "
                 "Directory.Read.All. Reads servicePrincipals, oauth2PermissionGrants "
                 "(delegated consents) and appRoleAssignments (app-only grants).",
    },
    "slack": {
        "label": "Slack",
        "fetch": fetch_slack,
        "credential_fields": ["admin_token", "team_id"],
        "setup": "Org-admin user token with the admin.apps:read scope (Enterprise Grid). "
                 "team_id is optional — set it to limit the pull to one workspace. Lists "
                 "org-approved apps and their scopes via admin.apps.approved.list.",
    },
    "salesforce": {
        "label": "Salesforce",
        "fetch": fetch_salesforce,
        "credential_fields": ["instance_url", "client_id", "client_secret"],
        "setup": "Connected app with the client-credentials flow enabled; instance_url is "
                 "the org's My Domain (https://<mydomain>.my.salesforce.com). The run-as "
                 "user needs API Enabled + Manage Users to read the OauthToken sObject. "
                 "Salesforce does not expose per-token scopes, so scope-based risk "
                 "flagging is unavailable here.",
    },
    "notion": {
        "label": "Notion (manual export only)",
        "fetch": fetch_notion,
        "credential_fields": [],
        "manual_only": True,
        "setup": "Notion's public API cannot enumerate a workspace's installed "
                 "integrations or OAuth grants — there is no live pull. Export "
                 "Settings & members -> Connections and upload it via "
                 "POST /api/discovery/oauth-grants instead.",
    },
}


# --- sync -------------------------------------------------------------------------------

def store_credentials(connector, credentials: dict) -> None:
    connector.credentials_enc = encrypt(json.dumps(credentials))


def sync_connector(db, connector) -> dict:
    """Pull grants for one connector and run them through the standard ingest. Updates the
    connector's last_sync_* fields (committed by the caller alongside the ingest)."""
    connector.last_sync_at = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        creds = json.loads(decrypt(connector.credentials_enc) or "{}")
        fetched = PLATFORMS[connector.platform]["fetch"](creds)
        # the sentinel row reports truncation without polluting discovery
        truncated = any(g["app_name"].startswith("__truncated_") for g in fetched)
        grants = [OAuthGrant(**g) for g in fetched if not g["app_name"].startswith("__truncated_")]
        summary = ingest_oauth_grants(db, connector.tenant_id, grants)
        if truncated:
            summary["truncated"] = True
        connector.last_sync_status = "ok"
        connector.last_sync_detail = json.dumps(summary)[:512]
        db.commit()
        return summary
    except ConnectorError as e:
        connector.last_sync_status = "error"
        connector.last_sync_detail = str(e)[:512]
        db.commit()
        raise
