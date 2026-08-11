"""Live OAuth-grant pulls from SaaS admin APIs — the recurring version of the one-shot
POST /api/discovery/oauth-grants ingest.

Where AI tools plug into SaaS via OAuth they leave no traffic a proxy or extension can see;
the grant inventory lives in each platform's admin API. A SaasConnector row stores a
platform credential (encrypted at rest); sync_connector() pulls the current grants and runs
them through the same ingest_oauth_grants() path as a manual export, so live pulls and
one-shot uploads land identically in discovery.

Platform registry: PLATFORMS maps a key to its fetch function + the credential fields the
UI should collect. First connector is Google Workspace (service account with domain-wide
delegation, impersonating an admin). The registry is the extension point for M365 / Slack /
Salesforce — each is fetch(creds) -> [{app_name, app_id, user, provider, scopes}].
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


PLATFORMS: dict[str, dict] = {
    "google_workspace": {
        "label": "Google Workspace",
        "fetch": fetch_google_workspace,
        "credential_fields": ["service_account_json", "admin_email"],
        "setup": "Service account with domain-wide delegation; grant it the "
                 "admin.directory.user.readonly and admin.directory.user.security scopes "
                 "in Admin Console, and set admin_email to the admin it impersonates.",
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
