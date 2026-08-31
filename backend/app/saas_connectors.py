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

def _google_access_token(creds: dict, scopes: str = _GOOGLE_SCOPES) -> str:
    """Service-account JWT grant (RFC 7523), impersonating the admin via `sub` — the
    domain-wide-delegation flow Google requires for Admin SDK / Drive reads."""
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
        {"iss": sa["client_email"], "sub": admin, "scope": scopes,
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


# --- Slack message scanning (collab-surface DLP) ------------------------------------------
#
# Where fetch_slack inventories which AI apps are INSTALLED, this scans what the AI can
# READ: message content in the channels the scan bot is invited to, run through the same
# PII/PHI/secret engine as every other plane (Surface.COLLAB — Slack AI, bots, and MCP
# Slack servers all read this content). Cursor-incremental: connector.sync_state keeps a
# per-channel last-message-ts high-water mark, so each sync pulls only new messages.
# Rules-only (use_judge=False): a 2000-message backfill must not fan out 2000 LLM calls.

_MAX_MESSAGES_PER_SYNC = 2000     # bounds one sync; the cursor resumes where it stopped
_SCAN_LOOKBACK_SECS = 7 * 86400   # first sync reaches back a week, then cursor-incremental

# --- shared files ---------------------------------------------------------------------
# A regulated record is as likely to be a pasted CSV as a typed message, and the message
# scan alone never saw it. Only formats whose bytes ARE their text are read: a PDF or a
# .docx is a container needing a parser, and an image needs OCR — both are real gaps and
# neither is quietly approximated here. Slack reports the type, so an unreadable
# attachment is counted and reported rather than skipped in silence.
_FILE_TEXT_MIMES = ("text/", "application/json", "application/xml", "application/x-ndjson",
                    "application/x-sh", "application/javascript", "application/sql")
_FILE_TEXT_TYPES = frozenset({
    "text", "post", "snippet", "csv", "tsv", "json", "yaml", "yml", "xml", "markdown",
    "md", "html", "css", "javascript", "typescript", "python", "ruby", "go", "rust",
    "java", "php", "shell", "sql", "ini", "toml", "log", "diff", "patch", "env",
})
_MAX_FILE_BYTES = 1_000_000       # per file; larger ones are counted as skipped
_MAX_FILE_BYTES_PER_SYNC = 25_000_000


def _slack_pages(url_base: str, params: dict, hdrs: dict, list_key: str):
    """Iterate a cursor-paginated Slack list method, yielding items. Raises ConnectorError
    on Slack's in-band (HTTP 200 + ok:false) errors."""
    cursor = ""
    while True:
        q = dict(params)
        if cursor:
            q["cursor"] = cursor
        data = _http_json(f"{url_base}?{urllib.parse.urlencode(q)}", headers=hdrs)
        if not data.get("ok"):
            err = data.get("error", "unknown_error")
            raise ConnectorError(f"Slack API error {err} from {url_base.rsplit('/', 1)[-1]}")
        yield from data.get(list_key, [])
        cursor = (data.get("response_metadata") or {}).get("next_cursor", "")
        if not cursor:
            break


def _slack_actor(cache: dict, user_id: str, hdrs: dict) -> str:
    """Slack user id -> email (users:read.email), falling back to real name / the id.
    Cached per sync — a channel's messages share a handful of authors."""
    if user_id in cache:
        return cache[user_id]
    try:
        data = _http_json(f"{_SLACK_API_BASE}/users.info?"
                          + urllib.parse.urlencode({"user": user_id}), headers=hdrs)
        prof = (data.get("user") or {}).get("profile") or {} if data.get("ok") else {}
        actor = prof.get("email") or (data.get("user") or {}).get("real_name") or user_id
    except ConnectorError:
        actor = user_id
    cache[user_id] = actor
    return actor


def _slack_readable_file(f: dict) -> bool:
    """Whether this attachment's bytes can be read as text without a parser."""
    mime = (f.get("mimetype") or "").lower()
    return (f.get("filetype") or "").lower() in _FILE_TEXT_TYPES or mime.startswith(_FILE_TEXT_MIMES)


def _slack_file_text(f: dict, hdrs: dict) -> str:
    """An attachment's text, or "" if it cannot be read. Best-effort by design: one
    unreadable or expired file must not sink a whole workspace scan."""
    url = f.get("url_private_download") or f.get("url_private") or ""
    if not url:
        return ""
    try:
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read(_MAX_FILE_BYTES).decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return ""


def _slack_channels(hdrs: dict, auto_join: bool) -> tuple[list[dict], int]:
    """The channels to scan, and how many the bot joined to get there.

    Default is what the bot was invited to. With auto_join it also enumerates every
    public channel in the workspace and joins the ones it is not in, which is the closest
    a bot token gets to Enterprise Grid's org-wide view. PRIVATE channels and DMs stay
    invite-only whatever this is set to: no bot scope grants entry to a private
    conversation, only Slack's Discovery API does, and that is Enterprise Grid.
    """
    if not auto_join:
        return list(_slack_pages(f"{_SLACK_API_BASE}/users.conversations",
                                 {"types": "public_channel,private_channel", "limit": "200"},
                                 hdrs, "channels")), 0
    joined = 0
    by_id: dict[str, dict] = {}
    for ch in _slack_pages(f"{_SLACK_API_BASE}/conversations.list",
                           {"types": "public_channel", "exclude_archived": "true",
                            "limit": "200"}, hdrs, "channels"):
        cid = ch.get("id", "")
        if not cid:
            continue
        by_id[cid] = ch
        if not ch.get("is_member"):
            # Joining posts a visible "joined the channel" line, which is why this is
            # opt-in. Best-effort: a channel that refuses (archived mid-scan, admin-only
            # membership) is simply left unscanned rather than failing the sync.
            try:
                r = _http_json(f"{_SLACK_API_BASE}/conversations.join",
                               headers={**hdrs, "Content-Type": "application/x-www-form-urlencoded"},
                               data=urllib.parse.urlencode({"channel": cid}).encode())
                if r.get("ok"):
                    joined += 1
                else:
                    by_id.pop(cid, None)
            except ConnectorError:
                by_id.pop(cid, None)
    # Private channels are only ever the ones somebody invited the bot to.
    for ch in _slack_pages(f"{_SLACK_API_BASE}/users.conversations",
                           {"types": "private_channel", "limit": "200"}, hdrs, "channels"):
        if ch.get("id"):
            by_id.setdefault(ch["id"], ch)
    return list(by_id.values()), joined


def scan_slack_messages(db, connector, creds: dict) -> dict:
    """Scan new Slack messages and their text attachments for PII/PHI/secrets, persisting
    findings on the collab surface.

    Covers the channels the bot is a member of; with creds["auto_join"] it also joins and
    scans every public channel in the workspace. Private channels and DMs remain
    invite-only on any plan below Enterprise Grid.

    Returns {channels, messages, findings, joined?, files?, files_skipped?, truncated?}
    for last_sync_detail."""
    token = (creds.get("bot_token") or "").strip()
    if not token:
        raise ConnectorError("slack_messages needs bot_token (xoxb-… with channels:read, "
                             "groups:read, channels:history, groups:history, users:read, "
                             "users:read.email, files:read; plus channels:join to scan "
                             "public channels it was not invited to)")
    hdrs = {"Authorization": f"Bearer {token}"}
    from .detectors import AnalysisInput, Surface
    from .models import Tenant
    from .service import run_analysis

    tenant = db.get(Tenant, connector.tenant_id)
    custom_pii = (getattr(tenant, "custom_pii_patterns", "") or "") if tenant else ""
    state = connector.state
    marks: dict[str, str] = dict(state.get("channels") or {})
    default_oldest = f"{time.time() - _SCAN_LOOKBACK_SECS:.6f}"

    channels, joined = _slack_channels(hdrs, bool(creds.get("auto_join")))

    users: dict[str, str] = {}
    scanned = findings = 0
    files_scanned = files_skipped = file_bytes = 0
    truncated = False
    for ch in channels:
        cid, cname = ch.get("id", ""), ch.get("name", "")
        if not cid:
            continue
        remaining = _MAX_MESSAGES_PER_SYNC - scanned
        if remaining <= 0:
            truncated = True
            break
        # Slack returns history newest-first, so a partially-scanned window CANNOT
        # advance the watermark — the unfetched messages are the OLDER ones, and moving
        # the cursor past them would skip them forever. Over-budget channels scan what
        # fits and keep their cursor; the rescan next sync folds as recurrences.
        window, over = [], False
        for m in _slack_pages(f"{_SLACK_API_BASE}/conversations.history",
                              {"channel": cid, "limit": "200",
                               "oldest": marks.get(cid, default_oldest)},
                              hdrs, "messages"):
            if m.get("subtype") or not m.get("user") or not (m.get("text") or "").strip():
                continue          # bots, joins, edits-without-text — not user content
            window.append(m)
            if len(window) > remaining:
                over = True
                window.pop()      # keep exactly the budget's worth (the newest ones)
                break
        # Oldest-first so the watermark only ever moves past messages actually scanned.
        for m in sorted(window, key=lambda x: float(x.get("ts", "0"))):
            actor = _slack_actor(users, m["user"], hdrs)
            where = f"#{cname}" if cname else cid
            result = run_analysis(
                AnalysisInput(content=m["text"], sender=actor, channel="slack",
                              subject=where, surface=Surface.COLLAB,
                              metadata={"custom_pii": custom_pii}),
                persist=True, db=db, tenant_id=connector.tenant_id,
                persist_benign=False, use_judge=False)
            # Attachments are scanned as their own findings, so a clean message carrying a
            # customer export is not reported as clean. Subject names the file, so triage
            # points at the thing to delete rather than at the sentence beside it.
            for fo in (m.get("files") or []):
                if file_bytes >= _MAX_FILE_BYTES_PER_SYNC:
                    files_skipped += 1
                    continue
                if not _slack_readable_file(fo) or int(fo.get("size") or 0) > _MAX_FILE_BYTES:
                    files_skipped += 1        # binary/oversize: counted, never guessed at
                    continue
                body = _slack_file_text(fo, hdrs)
                if not body.strip():
                    files_skipped += 1
                    continue
                file_bytes += len(body)
                files_scanned += 1
                fname = fo.get("name") or fo.get("id") or "file"
                if run_analysis(
                        AnalysisInput(content=body, sender=actor, channel="slack",
                                      subject=f"{where}: {fname}", surface=Surface.COLLAB,
                                      metadata={"custom_pii": custom_pii, "slack_file": fname}),
                        persist=True, db=db, tenant_id=connector.tenant_id,
                        persist_benign=False, use_judge=False).get("finding_id") is not None:
                    findings += 1
            # Fingerprint substantial messages so a later leak can be traced to the
            # thread it was lifted from. store_fingerprint no-ops on short text, so
            # one-liners ("lunch?") never create rows — only real content does.
            from . import content_origin
            content_origin.store_fingerprint(
                db, connector.tenant_id, "slack", f"{cid}:{m['ts']}",
                where, actor, m["text"],
                sensitive=result.get("finding_id") is not None)
            scanned += 1
            if not over:
                marks[cid] = m["ts"]
            if result.get("finding_id") is not None:
                findings += 1
        if over:
            truncated = True

    connector.state = {**state, "channels": marks}
    summary = {"channels": len(channels), "messages": scanned, "findings": findings}
    if joined:
        summary["joined"] = joined
    if files_scanned:
        summary["files"] = files_scanned
    if files_skipped:
        # Surfaced, not swallowed: "12 attachments unreadable" is the honest way to say
        # that PDFs, Office documents and images are not covered.
        summary["files_skipped"] = files_skipped
    if truncated:
        summary["truncated"] = True   # budget hit; the cursor resumes next sync
    return summary


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


# --- Salesforce content scanning ---------------------------------------------------------
#
# Distinct from fetch_salesforce (grant inventory): this reads record CONTENT — the free-text
# fields where customer PII and secrets actually accumulate — and runs it through the engine
# on the collab surface, same as Slack/Drive/SharePoint. SOQL is watermark-incremental on
# LastModifiedDate, oldest-first so the cursor only advances past records actually scanned.
# The object set is configurable (creds["objects"]); the defaults are the two objects that
# hold sensitive free text in almost every org.

_MAX_RECORDS_PER_SYNC = 2000
# Each target: which sObject, which text fields to scan, an optional field to title the
# finding, and the relationship path to the actor to attribute it to.
_DEFAULT_SF_OBJECTS = [
    {"sobject": "Case", "fields": ["Subject", "Description"],
     "title": "Subject", "actor": "LastModifiedBy.Username"},
    {"sobject": "FeedItem", "fields": ["Body"],
     "title": None, "actor": "CreatedBy.Username"},
]


def _sf_path(rec: dict, dotted: str) -> str:
    """Walk a SOQL relationship path (e.g. 'LastModifiedBy.Username') through the nested
    record dicts Salesforce returns; '' when any hop is missing."""
    cur = rec
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(part)
    return cur if isinstance(cur, str) else ""


def scan_salesforce_records(db, connector, creds: dict) -> dict:
    """Scan changed Salesforce records (Cases, Chatter posts by default) for PII/PHI/
    secrets, and fingerprint them for content-origin. Watermark-incremental per sObject on
    LastModifiedDate. Text fields only — file/attachment bodies (ContentVersion) are a
    separate scan, not covered here."""
    instance, token = _salesforce_access(creds)
    hdrs = {"Authorization": f"Bearer {token}"}
    custom_pii = _tenant_custom_pii(db, connector)
    state = connector.state
    marks: dict[str, str] = dict(state.get("sf_objects") or {})
    targets = creds.get("objects") or _DEFAULT_SF_OBJECTS
    default_since = datetime.fromtimestamp(
        time.time() - _SCAN_LOOKBACK_SECS, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    scanned = findings = 0
    truncated = False
    for t in targets:
        if scanned >= _MAX_RECORDS_PER_SYNC:
            truncated = True
            break
        sobject = t["sobject"]
        text_fields = t["fields"]
        actor_path = t.get("actor") or ""
        title_field = t.get("title")
        # Deduped SELECT: Id + watermark + actor relationship + content/title fields.
        select = ["Id", "LastModifiedDate"]
        for f in ([actor_path] if actor_path else []) + text_fields + \
                ([title_field] if title_field else []):
            if f and f not in select:
                select.append(f)
        watermark = marks.get(sobject) or default_since
        soql = (f"SELECT {', '.join(select)} FROM {sobject} "
                f"WHERE LastModifiedDate > {watermark} ORDER BY LastModifiedDate ASC")
        url = (f"{instance}/services/data/{_SF_API_VERSION}/query?"
               + urllib.parse.urlencode({"q": soql}))
        mark = watermark
        over = False
        while url and not over:
            data = _http_json(url, headers=hdrs)
            for rec in data.get("records", []):
                if scanned >= _MAX_RECORDS_PER_SYNC:
                    over = True
                    break
                content = "\n".join(str(rec.get(f) or "") for f in text_fields).strip()
                rid = rec.get("Id", "")
                if not content or not rid:
                    mark = rec.get("LastModifiedDate") or mark   # nothing to scan, still advance
                    continue
                actor = _sf_path(rec, actor_path) if actor_path else ""
                title = (title_field and str(rec.get(title_field) or "")) or f"{sobject} {rid}"
                hit = _scan_blob(db, connector, custom_pii, content=content, sender=actor,
                                 subject=f"{sobject}: {title}"[:200], channel="salesforce")
                if hit:
                    findings += 1
                from . import content_origin
                content_origin.store_fingerprint(db, connector.tenant_id, "salesforce",
                                                 f"{sobject}:{rid}", title, actor, content,
                                                 sensitive=hit)
                scanned += 1
                mark = rec.get("LastModifiedDate") or mark
            nxt = data.get("nextRecordsUrl", "")
            url = f"{instance}{nxt}" if (nxt and not data.get("done", True)) else ""
        marks[sobject] = mark
        if over:
            truncated = True

    connector.state = {**state, "sf_objects": marks}
    summary = {"records": scanned, "findings": findings, "objects": len(targets)}
    if truncated:
        summary["truncated"] = True
    return summary


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




# --- Google Drive / SharePoint content scanning -------------------------------------------
#
# Same shape as Slack message scanning: pull what changed since the watermark, run it
# through run_analysis on the collab surface, advance the cursor only past content
# actually scanned. Rules-only (use_judge=False) — a first sync over a big library must
# not fan out thousands of LLM calls. Only text-extractable content is scanned; Office
# binaries (docx/xlsx) and PDFs are skipped in v1 (no extractor dependency).

_MAX_FILES_PER_SYNC = 300          # bounds one sync; the cursor resumes where it stopped
_MAX_CONTENT_BYTES = 256 * 1024    # scan the first 256KB of a file — enough for DLP
_MAX_FILE_BYTES = 8 * 1024 * 1024  # skip anything larger outright

_GDRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
_GDRIVE_BASE = "https://www.googleapis.com/drive/v3"
# Google-native types export to text; everything else must already be text-shaped.
_GDRIVE_EXPORT = {
    "application/vnd.google-apps.document": "text/plain",
    "application/vnd.google-apps.spreadsheet": "text/csv",
    "application/vnd.google-apps.presentation": "text/plain",
}
_TEXTY_EXT = (".txt", ".md", ".csv", ".json", ".yaml", ".yml", ".log", ".env", ".conf",
              ".ini", ".cfg", ".xml", ".html", ".py", ".js", ".ts", ".java", ".go",
              ".rb", ".sql", ".sh", ".ps1", ".tf", ".tfvars", ".pem", ".key")


def _texty(mime: str, name: str) -> bool:
    if mime.startswith("text/") or mime in ("application/json", "application/xml"):
        return True
    return (name or "").lower().endswith(_TEXTY_EXT)


def _http_text(url: str, headers: dict, cap: int = _MAX_CONTENT_BYTES) -> str:
    """GET a (possibly redirecting) content URL, decode best-effort, cap the read."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read(cap).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise ConnectorError(f"HTTP {e.code} fetching content: {str(e)[:120]}")
    except (urllib.error.URLError, OSError) as e:
        raise ConnectorError(f"content fetch failed: {e}")


def _scan_blob(db, connector, custom_pii: str, *, content: str, sender: str,
               subject: str, channel: str) -> bool:
    """One document through the engine on the collab surface. True when it made a finding."""
    from .detectors import AnalysisInput, Surface
    from .service import run_analysis
    result = run_analysis(
        AnalysisInput(content=content, sender=sender, channel=channel, subject=subject,
                      surface=Surface.COLLAB, metadata={"custom_pii": custom_pii}),
        persist=True, db=db, tenant_id=connector.tenant_id,
        persist_benign=False, use_judge=False)
    return result.get("finding_id") is not None


def _tenant_custom_pii(db, connector) -> str:
    from .models import Tenant
    tenant = db.get(Tenant, connector.tenant_id)
    return (getattr(tenant, "custom_pii_patterns", "") or "") if tenant else ""


def scan_gdrive_files(db, connector, creds: dict) -> dict:
    """Scan changed Google Drive files (shared drives + the impersonated user's My Drive)
    for PII/PHI/secrets. Watermark-incremental on modifiedTime; oldest-first so the
    cursor only ever moves past files actually scanned."""
    token = _google_access_token(creds, scopes=_GDRIVE_SCOPE)
    hdrs = {"Authorization": f"Bearer {token}"}
    state = connector.state
    watermark = state.get("modified_after") or datetime.fromtimestamp(
        time.time() - _SCAN_LOOKBACK_SECS, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    custom_pii = _tenant_custom_pii(db, connector)

    scanned = findings = skipped = 0
    truncated = False
    page = ""
    mark = watermark
    while True:
        q = {"q": f"modifiedTime > '{watermark}' and trashed = false",
             "orderBy": "modifiedTime",
             "corpora": "allDrives", "includeItemsFromAllDrives": "true",
             "supportsAllDrives": "true", "pageSize": "100",
             "fields": "nextPageToken,files(id,name,mimeType,modifiedTime,size,"
                       "owners(emailAddress),lastModifyingUser(emailAddress))"}
        if page:
            q["pageToken"] = page
        data = _http_json(f"{_GDRIVE_BASE}/files?{urllib.parse.urlencode(q)}", headers=hdrs)
        for f in data.get("files", []):
            if scanned >= _MAX_FILES_PER_SYNC:
                truncated = True
                break
            fid, name = f.get("id", ""), f.get("name", "")
            mime = f.get("mimeType", "")
            if not fid:
                continue
            export = _GDRIVE_EXPORT.get(mime)
            if not export and (not _texty(mime, name)
                               or int(f.get("size") or 0) > _MAX_FILE_BYTES):
                skipped += 1
                mark = f.get("modifiedTime") or mark   # skipped files still pass the cursor
                continue
            url = (f"{_GDRIVE_BASE}/files/{fid}/export?mimeType={urllib.parse.quote(export)}"
                   if export else f"{_GDRIVE_BASE}/files/{fid}?alt=media&supportsAllDrives=true")
            try:
                text = _http_text(url, hdrs)
            except ConnectorError:
                skipped += 1                            # unexportable/permission-denied file
                mark = f.get("modifiedTime") or mark
                continue
            sender = ((f.get("lastModifyingUser") or {}).get("emailAddress")
                      or ((f.get("owners") or [{}])[0]).get("emailAddress") or "")
            hit = _scan_blob(db, connector, custom_pii, content=text, sender=sender,
                             subject=name, channel="gdrive")
            if hit:
                findings += 1
            # Fingerprint every scanned doc (benign ones are valid origins too) so a later
            # leak of this content can be traced back here; sensitive= flags docs whose own
            # scan tripped a data-loss category, for a stronger match-time severity boost.
            from . import content_origin
            content_origin.store_fingerprint(db, connector.tenant_id, "gdrive", fid,
                                             name, sender, text, sensitive=hit)
            scanned += 1
            mark = f.get("modifiedTime") or mark
        if truncated:
            break
        page = data.get("nextPageToken", "")
        if not page:
            break

    connector.state = {**state, "modified_after": mark}
    summary = {"files": scanned, "skipped": skipped, "findings": findings}
    if truncated:
        summary["truncated"] = True
    return summary


_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_MAX_SITES_PER_SYNC = 50


def scan_sharepoint_files(db, connector, creds: dict) -> dict:
    """Scan changed files in SharePoint document libraries via Graph delta queries.
    Per-drive deltaLinks in connector.state make every sync incremental; a drive whose
    budget runs out keeps its old link (its changes rescan next sync — recurrences fold)."""
    token = _microsoft_access_token(creds)
    hdrs = {"Authorization": f"Bearer {token}"}
    state = connector.state
    deltas: dict[str, str] = dict(state.get("deltas") or {})
    custom_pii = _tenant_custom_pii(db, connector)

    sites, url = [], f"{_GRAPH_BASE}/sites?search=*&$top=50"
    while url and len(sites) < _MAX_SITES_PER_SYNC:
        data = _http_json(url, headers=hdrs)
        sites += data.get("value", [])
        url = data.get("@odata.nextLink", "")

    drives: list[dict] = []
    for site in sites[:_MAX_SITES_PER_SYNC]:
        sid = site.get("id", "")
        if not sid:
            continue
        try:
            dd = _http_json(f"{_GRAPH_BASE}/sites/{sid}/drives", headers=hdrs)
        except ConnectorError:
            continue                              # site without accessible libraries
        drives += dd.get("value", [])

    scanned = findings = skipped = 0
    truncated = False
    for drive in drives:
        did = drive.get("id", "")
        if not did:
            continue
        if scanned >= _MAX_FILES_PER_SYNC:
            truncated = True
            break
        url = deltas.get(did) or f"{_GRAPH_BASE}/drives/{did}/root/delta"
        new_link, over = "", False
        while url:
            data = _http_json(url, headers=hdrs)
            for item in data.get("value", []):
                fobj = item.get("file") or {}
                if not fobj:
                    continue                       # folders / deleted markers
                if scanned >= _MAX_FILES_PER_SYNC:
                    over = True
                    break
                name = item.get("name", "")
                mime = fobj.get("mimeType", "")
                if (not _texty(mime, name)
                        or int(item.get("size") or 0) > _MAX_FILE_BYTES):
                    skipped += 1
                    continue
                try:
                    text = _http_text(f"{_GRAPH_BASE}/drives/{did}/items/"
                                      f"{item.get('id')}/content", hdrs)
                except ConnectorError:
                    skipped += 1
                    continue
                sender = (((item.get("lastModifiedBy") or {}).get("user") or {})
                          .get("email") or "")
                subject = f"{drive.get('name', 'library')}/{name}"
                hit = _scan_blob(db, connector, custom_pii, content=text, sender=sender,
                                 subject=subject, channel="sharepoint")
                if hit:
                    findings += 1
                from . import content_origin
                content_origin.store_fingerprint(db, connector.tenant_id, "sharepoint",
                                                 item.get("id", ""), subject, sender, text,
                                                 sensitive=hit)
                scanned += 1
            if over:
                break
            new_link = data.get("@odata.deltaLink", "")
            url = data.get("@odata.nextLink", "")
        if over:
            truncated = True                       # keep the OLD delta link: rescan, don't skip
        elif new_link:
            deltas[did] = new_link

    connector.state = {**state, "deltas": deltas}
    summary = {"sites": len(sites), "drives": len(drives), "files": scanned,
               "skipped": skipped, "findings": findings}
    if truncated:
        summary["truncated"] = True
    return summary


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
    "slack_messages": {
        "label": "Slack message scanning",
        "scan": scan_slack_messages,
        "credential_fields": ["bot_token"],
        "setup": "Bot token (xoxb-…) with channels:read, groups:read, channels:history, "
                 "groups:history, users:read, users:read.email. Invite the bot to each "
                 "channel to scan. Every sync pulls messages newer than the per-channel "
                 "cursor (first sync looks back 7 days) and runs them through PII/PHI/"
                 "secret detection on the collab surface — findings alert and export "
                 "like any other plane. Detection is rules-only (no LLM judge).",
    },
    "gdrive_files": {
        "label": "Google Drive scanning",
        "scan": scan_gdrive_files,
        "credential_fields": ["service_account_json", "admin_email"],
        "setup": "Service account with domain-wide delegation, granted the "
                 "https://www.googleapis.com/auth/drive.readonly scope in Admin Console; "
                 "admin_email is the user it impersonates (their My Drive + all shared "
                 "drives they can see are scanned). Watermark-incremental on modifiedTime "
                 "(first sync looks back 7 days). Google Docs/Sheets/Slides are exported "
                 "as text; plain-text files are scanned directly; Office binaries and "
                 "PDFs are skipped. Rules-only detection on the collab surface.",
    },
    "sharepoint_files": {
        "label": "SharePoint / OneDrive scanning",
        "scan": scan_sharepoint_files,
        "credential_fields": ["tenant_id", "client_id", "client_secret"],
        "setup": "Entra ID app registration with admin-consented *application* Graph "
                 "permissions Sites.Read.All + Files.Read.All. Scans document libraries "
                 "across SharePoint sites via Graph delta queries (fully incremental "
                 "after the first sync). Text-shaped files are scanned; Office binaries "
                 "and PDFs are skipped. Rules-only detection on the collab surface.",
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
    "salesforce_content": {
        "label": "Salesforce content scanning",
        "scan": scan_salesforce_records,
        "credential_fields": ["instance_url", "client_id", "client_secret"],
        "setup": "Same connected app as the Salesforce grant connector (client-credentials "
                 "flow; instance_url is the org's My Domain). The run-as user needs API "
                 "Enabled plus read access to the scanned objects. Scans record free-text "
                 "for PII/secrets on the collab surface — Cases (Subject, Description) and "
                 "Chatter posts by default; override with an `objects` credential entry "
                 "([{sobject, fields, title, actor}]) to scan custom objects. Watermark-"
                 "incremental on LastModifiedDate (first sync looks back 7 days). Text "
                 "fields only — file/attachment bodies are not scanned. Rules-only.",
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

def store_credentials(connector, credentials: dict, db=None) -> None:
    """Seal connector credentials under the owning tenant's key when a session is given.
    These are the most dangerous secrets the product holds (a Google Workspace entry is a
    domain-wide-delegation service-account key), so they should not share one key across
    tenants. Without a session the global key is still used, and reads handle both."""
    from . import crypto
    dek = crypto.dek_for(db, getattr(connector, "tenant_id", None)) if db is not None else None
    connector.credentials_enc = crypto.seal_secret(dek, json.dumps(credentials))


def read_credentials(connector, db=None) -> dict:
    """The connector's decrypted credential blob (also carries non-secret options)."""
    from . import crypto
    dek = crypto.dek_for(db, getattr(connector, "tenant_id", None)) if db is not None else None
    return json.loads(crypto.unseal_secret(connector.credentials_enc, dek) or "{}")


# Non-secret scan options live inside the (encrypted) credential blob, so they need no
# column — but only these keys may ever be read back out to the API. A bot token must not
# reach the console through this door.
PUBLIC_OPTIONS = ("auto_join",)


def connector_options(connector, db=None) -> dict:
    """The connector's non-secret options. Needs the session: the blob is sealed under the
    tenant's own key, and unsealing without it returns "" rather than raising."""
    try:
        creds = read_credentials(connector, db)
    except Exception:                                             # noqa: BLE001
        return {}
    return {k: bool(creds.get(k)) for k in PUBLIC_OPTIONS}


def merge_options(connector, options: dict, db=None) -> None:
    """Update non-secret settings in place, leaving the secrets alone. Toggling a switch
    must never require the operator to paste their bot token again — that is how a token
    ends up in a browser autofill or a support ticket."""
    creds = read_credentials(connector, db)
    creds.update(options)
    store_credentials(connector, creds, db)


def sync_connector(db, connector) -> dict:
    """Run one connector sync: grant-inventory pull (`fetch` platforms) or content scan
    (`scan` platforms, e.g. Slack message scanning). Updates the connector's
    last_sync_* fields (committed by the caller alongside the ingest)."""
    connector.last_sync_at = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        from . import crypto
        creds = json.loads(
            crypto.unseal_secret(connector.credentials_enc,
                                 crypto.dek_for(db, connector.tenant_id)) or "{}")
        spec = PLATFORMS[connector.platform]
        if "scan" in spec:
            # Content scanner: persists findings itself (and advances its own cursor).
            summary = spec["scan"](db, connector, creds)
        else:
            fetched = spec["fetch"](creds)
            # the sentinel row reports truncation without polluting discovery
            truncated = any(g["app_name"].startswith("__truncated_") for g in fetched)
            grants = [OAuthGrant(**g) for g in fetched
                      if not g["app_name"].startswith("__truncated_")]
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
