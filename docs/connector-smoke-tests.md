# SaaS-connector smoke tests — real-tenant runbook

The live OAuth-grant fetchers in `backend/app/saas_connectors.py` are unit-tested against
mocked HTTP, which proves our parsing, not the vendor's actual API behavior. This runbook
takes an admin from nothing to credentials to a one-command live smoke test per platform,
using `scripts/connector_smoke.py` — the same fetcher code the backend's
`POST /api/discovery/connectors/{id}/sync` executes, run standalone: **no running
backend, no database, nothing stored, read-only API calls**.

Every claimed permission below is cross-checked against what the fetcher actually calls
(the exact endpoints are listed per platform), not copied from generic vendor docs.

## Running the smoke

From the repo root, with the backend's Python environment (it needs the backend's
dependencies — `backend/.venv` if you built one, or any interpreter with
`backend/requirements.txt` installed):

```bash
backend/.venv/bin/python scripts/connector_smoke.py --platform <key>
# or: python scripts/connector_smoke.py --platform <key>
```

Platform keys: `google_workspace`, `microsoft_365`, `slack`, `salesforce` (`notion` is
registered manual-only — running it prints why and exits `SMOKE: SKIP`).

Credentials come from **env vars (preferred — keeps secrets out of shell history)** or
CLI flags; a flag overrides its env var. Env names are
`PALIVANE_SMOKE_<PLATFORM>_<FIELD>` with `PALIVANE_SMOKE_<FIELD>` as a fallback; the
fields are exactly the platform's `credential_fields` in the PLATFORMS registry (also
shown by `--help`, and reported as `MISSING` per field when absent). A value that names a
readable file is replaced by the file's contents — use that for key files.

The report has four legs and always ends in one line:

```
auth:  OK — access token acquired (value not shown)      # or FAIL + the fetcher's hint
fetch: OK — 37 grant row(s)                              # + truncation sentinel(s) if any
sample (first 5 of 37, redacted): ...                    # app_name/provider/scope count/user yes-no
shape: OK — every row matches the ingest contract (app_id, app_name, provider, scopes, user)
SMOKE: PASS
```

Exit code 0 on PASS/SKIP, 1 on FAIL. `--full` prints the sampled rows completely
(includes user identities — still never tokens). `--sample N` changes the sample size.
Secrets are never echoed, in any mode.

**After PASS**: store the same credentials via `POST /api/discovery/connectors` so the
backend does scheduled live pulls — see [the last section](#after-pass-wire-up-scheduled-pulls).

---

## Microsoft 365 / Entra ID

What the fetcher calls (Graph v1.0, app-only token):

- `POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token` —
  client-credentials grant, scope `https://graph.microsoft.com/.default`
- `GET /servicePrincipals?$select=id,appId,displayName,appRoles` — app identities
- `GET /oauth2PermissionGrants` — delegated (user/tenant-consented) grants
- `GET /users/{id}?$select=userPrincipalName` — resolve consenting principals to UPNs
- `GET /servicePrincipals/{id}/appRoleAssignments` — application (app-only) grants

So the app registration needs exactly two admin-consented **application** permissions:
`Application.Read.All` (servicePrincipals + appRoleAssignments) and `Directory.Read.All`
(oauth2PermissionGrants + user lookups). Delegated permissions will NOT work — the flow
has no signed-in user.

### Tenant setup

1. Entra admin center (`entra.microsoft.com`) → **Identity → Applications → App
   registrations → New registration**. Name it e.g. `palivane-grant-connector`, accounts
   in this org only, no redirect URI. Register.
2. From the app's **Overview** page, record **Directory (tenant) ID** → `tenant_id` and
   **Application (client) ID** → `client_id`.
3. **Certificates & secrets → New client secret**. Copy the secret **Value** immediately
   (it is shown once; the "Secret ID" column is NOT the secret) → `client_secret`.
4. **API permissions → Add a permission → Microsoft Graph → Application permissions** →
   add `Application.Read.All` and `Directory.Read.All`. Then click **Grant admin consent
   for &lt;tenant&gt;** (requires a privileged-role admin).

First-run gotchas:

- **Consent propagation delay**: right after granting consent, tokens can still be minted
  without the roles for several minutes (occasionally ~15). Symptom: auth OK but fetch
  fails with `HTTP 403 ... Authorization_RequestDenied`. Wait and rerun.
- `AADSTS7000215` (invalid client secret) usually means the Secret *ID* was pasted
  instead of the Value, or the secret expired.
- `AADSTS700016` means the app isn't in the tenant you pointed `tenant_id` at.
- Big tenants: the fetcher pages service principals up to a 2,000 bound and does per-SP
  appRoleAssignments calls, so the run can take minutes; past the bound you get a
  reported truncation sentinel (`__truncated_at_2000_service_principals__`) — expected,
  not a failure.

### Smoke command

```bash
export PALIVANE_SMOKE_MICROSOFT_365_TENANT_ID='<directory-tenant-id>'
export PALIVANE_SMOKE_MICROSOFT_365_CLIENT_ID='<application-client-id>'
export PALIVANE_SMOKE_MICROSOFT_365_CLIENT_SECRET='<client-secret-value>'
backend/.venv/bin/python scripts/connector_smoke.py --platform microsoft_365
```

PASS looks like: `auth: OK`, `fetch: OK — N grant row(s)` (delegated per-user consents
show `user=yes`; tenant-wide consents and application grants show `user=no` — that is
Graph's data model, not a bug), `shape: OK`, `SMOKE: PASS`. Then store the same three
fields via `POST /api/discovery/connectors` with `"platform": "microsoft_365"`.

---

## Slack

**Enterprise Grid required, full stop.** The fetcher calls
`GET https://slack.com/api/admin.apps.approved.list` (paged by cursor, optional
`team_id`), and Slack's `admin.*` APIs only exist for Grid organizations. On a plain
workspace the API answers `ok: false, error: feature_not_enabled` and the smoke fails
with the fetcher's exact hint:

```
fetch: FAIL — Slack API error feature_not_enabled: admin.apps.* needs an Enterprise Grid org
```

There is no workaround on non-Grid plans; use the manual export path
(`POST /api/discovery/oauth-grants`) instead.

The credential is an **org-admin user token** (`xoxp-…`) carrying the `admin.apps:read`
**user** scope — not a bot token, and the installing user must be an org owner/admin
(otherwise: `not_an_admin`).

### Minting the token

1. `api.slack.com/apps` → **Create New App → From scratch**, in any workspace of the Grid
   org.
2. **OAuth & Permissions → Scopes → User Token Scopes** → add `admin.apps:read`. (Leave
   bot scopes empty — the admin APIs ignore bot tokens.)
3. Install at the **organization** level: apps requesting `admin.*` scopes must be
   installed on the org, by an org owner/admin. Open the app's install/authorize flow
   while signed in as an org admin and pick the *organization* in the destination picker
   (not an individual workspace).
4. Copy the **User OAuth Token** (`xoxp-…`) → `admin_token`.
5. `team_id` is optional: set it to one workspace's `T…` id to limit the pull; omit it
   for the whole org (`team_not_found` means the id isn't a workspace of this org).

Other failure hints the fetcher maps for you: `invalid_auth`/`token_revoked` (reissue the
token), `missing_scope` (reinstall with `admin.apps:read`), `not_an_admin`.

### Smoke command

```bash
export PALIVANE_SMOKE_SLACK_ADMIN_TOKEN='xoxp-…'
# optional: export PALIVANE_SMOKE_SLACK_TEAM_ID='T0123456789'
backend/.venv/bin/python scripts/connector_smoke.py --platform slack
```

PASS looks like: `auth: no separate token exchange on this platform` (Slack validates the
token in-band on the first call), `fetch: OK — N grant row(s)`, every sample row
`user=no` (Slack reports approvals at org/workspace level, never the granting user —
expected), `shape: OK`, `SMOKE: PASS`. Then store `admin_token` (+ optional `team_id`)
via `POST /api/discovery/connectors` with `"platform": "slack"`.

---

## Salesforce

What the fetcher calls:

- `POST https://<mydomain>.my.salesforce.com/services/oauth2/token` —
  client-credentials grant (the generic `login.salesforce.com` host does NOT support this
  flow; the org's My Domain URL is required)
- `GET /services/data/v60.0/query?q=SELECT AppName, AppMenuItemId, User.Username FROM
  OauthToken` — one row per (connected app, user) token, paged via `nextRecordsUrl`

Reading the `OauthToken` sObject is gated on the query user having **Manage Users**; API
access needs **API Enabled**. Note: Salesforce does not expose per-token OAuth scopes on
`OauthToken`, so every row has `scopes=0` and Palivane's broad-scope flagging never
triggers for this platform — expected, documented in the fetcher.

### Tenant setup

1. **My Domain**: Setup → search "My Domain". `instance_url` is
   `https://<mydomain>.my.salesforce.com`.
2. **Connected app**: Setup → **App Manager → New Connected App**. Enable OAuth settings;
   the callback URL is a required field but unused by client-credentials — a placeholder
   like `https://localhost/callback` is fine. OAuth scopes: add **Manage user data via
   APIs (api)**. Check **Enable Client Credentials Flow**. Save.
3. **Run-as user**: App Manager → your app → **Manage → Edit Policies** → under *Client
   Credentials Flow*, set **Run As** to an integration user whose profile/permission set
   has **API Enabled** and **Manage Users** (the latter is what allows the `OauthToken`
   query — without it the fetch fails on the SOQL, typically `INVALID_TYPE`/insufficient
   access).
4. **Credentials**: App Manager → your app → **View → Manage Consumer Details** —
   **Consumer Key** → `client_id`, **Consumer Secret** → `client_secret`.

First-run gotchas:

- A freshly created connected app can take ~2–10 minutes to propagate; token requests in
  that window fail with `invalid_client` — wait and rerun.
- `invalid_grant` on the token call usually means the Client Credentials Flow checkbox is
  off or no run-as user is set.
- Sandbox orgs use `https://<mydomain>--<sandbox>.sandbox.my.salesforce.com`.

### Smoke command

```bash
export PALIVANE_SMOKE_SALESFORCE_INSTANCE_URL='https://<mydomain>.my.salesforce.com'
export PALIVANE_SMOKE_SALESFORCE_CLIENT_ID='<consumer-key>'
export PALIVANE_SMOKE_SALESFORCE_CLIENT_SECRET='<consumer-secret>'
backend/.venv/bin/python scripts/connector_smoke.py --platform salesforce
```

PASS looks like: `auth: OK`, `fetch: OK — N grant row(s)` with `user=yes` on rows tied to
a user and `scopes=0` everywhere (expected — see above), `shape: OK`, `SMOKE: PASS`.
Then store the same three fields via `POST /api/discovery/connectors` with
`"platform": "salesforce"`.

---

## Google Workspace (reference platform — already validated against a real tenant)

Included so the harness can re-verify the known-good platform. Setup summary (the
fetcher mints a service-account JWT impersonating an admin, lists users via
`admin.googleapis.com/admin/directory/v1/users`, then pulls each user's third-party
tokens from `/users/{email}/tokens`; user paging is bounded at 2,000 with a reported
truncation sentinel):

1. GCP: create a service account, enable the **Admin SDK API**, download the JSON key.
2. Google Admin console → Security → Access and data control → API controls →
   **Domain-wide delegation** → add the service account's client ID with exactly the two
   scopes the fetcher requests: `https://www.googleapis.com/auth/admin.directory.user.readonly`
   and `https://www.googleapis.com/auth/admin.directory.user.security`.
3. `admin_email` is the super-admin the service account impersonates.

```bash
export PALIVANE_SMOKE_GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON=/path/to/sa-key.json   # file path is read
export PALIVANE_SMOKE_GOOGLE_WORKSPACE_ADMIN_EMAIL='admin@yourdomain.com'
backend/.venv/bin/python scripts/connector_smoke.py --platform google_workspace
```

---

## Notion

Manual-export-only: Notion's public API has no endpoint that enumerates a workspace's
installed integrations or their OAuth grants (verified Aug 2026). The smoke prints that
explanation and exits `SMOKE: SKIP` (code 0):

```bash
backend/.venv/bin/python scripts/connector_smoke.py --platform notion
```

Use Settings & members → Connections and upload via `POST /api/discovery/oauth-grants`.

---

## After PASS: wire up scheduled pulls

The smoke proves the credential + fetcher work; the backend then does the same pull on a
schedule. Store the identical credential fields (encrypted at rest; never returned by the
API) and sync:

```bash
# admin bearer token for your Palivane deployment
curl -sX POST https://<palivane>/api/discovery/connectors \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"platform": "microsoft_365", "label": "prod",
       "credentials": {"tenant_id": "…", "client_id": "…", "client_secret": "…"}}'

# returns {"id": <id>, ...}; pull now (or from an operator cron):
curl -sX POST https://<palivane>/api/discovery/connectors/<id>/sync \
  -H "Authorization: Bearer $TOKEN"
```

Grants land through the same ingest as a manual export; re-POSTing the same
platform+label rotates the credential in place. Once a platform's smoke has passed
against a real tenant, update `docs/roadmap-frontier.md` to move it from "pending" to
validated.
