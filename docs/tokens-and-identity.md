# Palivane tokens & identity — deployment reference

How authentication and per-person attribution work across Palivane's planes, and what
you actually need to provision. This is the auth-model companion to
[claude-deployment.md](./claude-deployment.md) (which is the surface-by-surface how-to).

The short version: **three secrets run the whole company** — one upstream provider key,
one Palivane API key, one ingest token. Issuing tokens *per user* buys you something in
exactly one place (the gateway), and even there it's an attribution choice, not a
functional requirement.

---

## The four token types

| Token | Who holds it | How many | Server-side name |
| --- | --- | --- | --- |
| **Upstream provider key** | Palivane server only — never users | 1 per provider, per company | `GATEWAY_ANTHROPIC_KEY`, `GATEWAY_GEMINI_KEY`, `GATEWAY_UPSTREAM_KEY` |
| **Palivane API key** (`ak_…`) | Gateway clients (Claude Code, OpenAI/Gemini SDKs) | Your choice — see [below](#do-i-need-a-token-per-user) | minted at `/api/apikeys` |
| **Ingest token** | Browser extension + egress proxy | 1 per company (shared) | `EXTENSION_INGEST_TOKEN` |
| **Console JWT** | Console/dashboard users (admins, analysts) | per login | signed with `PALIVANE_SECRET_KEY` |

### 1. Upstream provider keys — server-side only
The real Anthropic/Gemini/OpenAI keys live on the Palivane server and are forwarded to
the provider on each allowed call (`gateway.py` — Anthropic as `Authorization: Bearer`,
Gemini as `x-goog-api-key`). Clients never see them. One per provider you front:

```bash
GATEWAY_ANTHROPIC_KEY=sk-ant-...   # the REAL Anthropic key
# GATEWAY_GEMINI_KEY=...           # or GEMINI_API_KEY
# GATEWAY_UPSTREAM_KEY=sk-...      # OpenAI-compatible upstream
```

### 2. Palivane API keys (`ak_…`) — gateway clients
Prefixed `ak_` (`security.py: API_KEY_PREFIX = "ak_"`), minted by an admin and shown
once. Validated by prefix lookup + timing-safe hash; accepted via `x-api-key`,
`Authorization: Bearer`, or `x-goog-api-key`/`?key=` depending on the SDK.

```bash
curl -X POST https://palivane.corp.example.com/api/apikeys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"label":"alice-laptop","actor":"alice@acme.com"}'   # -> token shown once: ak_...
```

The `actor` field is the attribution lever — see [below](#do-i-need-a-token-per-user).

### 3. Ingest token — shared by extension *and* proxy
One company-wide secret. The server checks it at `/api/ingest/ai-usage` against
`EXTENSION_INGEST_TOKEN`, presented by clients as the `X-Palivane-Token` header.

```bash
EXTENSION_INGEST_TOKEN=$(openssl rand -hex 24)
INGEST_TENANT=acme
```

Both shadow-AI capture planes authenticate with this **same** secret:
- **Browser extension** — set as the *Ingest token* in Options, or pushed via managed
  policy (`token` field).
- **Egress proxy** — the proxy reads it from its own env var `PALIVANE_TOKEN`, which you
  set to the `EXTENSION_INGEST_TOKEN` value:
  ```bash
  PALIVANE_TOKEN=$EXTENSION_INGEST_TOKEN mitmdump -s proxy/palivane_addon.py --listen-port 8081
  ```
  > Naming gotcha: the proxy's local variable is `PALIVANE_TOKEN`, not
  > `EXTENSION_INGEST_TOKEN`. Same secret, different local name.

### 4. Console JWT — dashboard users
HS256 JWTs signed with `PALIVANE_SECRET_KEY`, carrying `sub` / `tenant_id` / `role`
claims (`auth.py`). This is the standard login path for **every** console user; the
`role` claim (admin vs analyst) is what gates access — there is no separate
"security-team" token type. End users of the AI tools never get a JWT; they're on the
`ak_` key (gateway) or the shared ingest token (extension/proxy).

---

## Do I need a token per user?

**Extension & proxy → no.** Both authenticate with the single shared
`EXTENSION_INGEST_TOKEN`. Per-person attribution there does **not** come from the
token — it comes from a separate `user` field in the request body:
- **Extension:** the `user` field, templated from SSO via managed config.
- **Proxy:** the `PALIVANE_PROXY_USER` env var.

So: one token, many users, still attributed per person. The server records that `user`
value as the finding's `sender`.

**Gateway (Claude Code / SDKs) → either works. This is the real decision:**

| Approach | Result |
| --- | --- |
| **One shared `ak_…` for the whole company** | Fully functional — every prompt captured and enforced. But all traffic attributes to that key's `actor`, so findings show up as one actor (e.g. "engineering"). No per-person attribution; coverage reconciliation can't tell who's who. |
| **One `ak_…` per user** (`actor: alice@acme.com`) — *recommended* | Findings attribute to the individual. `/api/coverage/reconcile` can identify exactly who's covered vs. the shadow set. |

Per-user keys flow `actor` → `Principal.actor` → the finding's `sender`, which is the
same field coverage reconciliation matches on:

```bash
curl -X POST https://palivane.corp.example.com/api/coverage/reconcile \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"events":[{"actor":"alice@acme.com","tool":"claude.ai"},{"actor":"mallory@acme.com","tool":"claude.ai"}]}'
# -> {"covered":1,"uncovered_count":1,"uncovered":[{"actor":"mallory@acme.com",...}]}
```

### Provisioning per-user gateway keys without hardcoding
Push keys via Claude Code's enterprise `managed-settings.json` (highest precedence):

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://palivane.corp.example.com",
    "ANTHROPIC_AUTH_TOKEN": "ak_<the developer's Palivane key>"
  }
}
```

To avoid baking a key per machine, use Claude Code's `apiKeyHelper` to fetch each
user's `ak_…` dynamically. See
[claude-deployment.md §2](./claude-deployment.md#2-claude-code) for the full setup.

**Self-serve installers do this automatically** (when generated with `route_gateway=true` —
by default they leave Claude Code on its own Pro/Max sign-in with
`forceLoginMethod: "claudeai"` and install only the hooks). In gateway mode the
`/api/provision` installer wires `apiKeyHelper` to the bundled **`palivane-reenroll`**
helper instead of baking a static `ANTHROPIC_AUTH_TOKEN`. On each call the helper returns a live per-device key, and if that
key is revoked/rotated it re-enrolls from the on-disk enrollment token (`GET /api/enroll/check`
tells it "dead, re-enroll" vs "still good") — so a revoked key self-heals with no re-push.
The browser extension is symmetric: it's pushed the **enrollment token** via managed policy
and self-enrolls its own device key (re-enrolling on a 401), rather than carrying a static
ingest key. Enrolling with an email-shaped `user` (the extension sends it after sign-in)
attributes the device key to that person so it reconciles against the shadow set; without
one, attribution falls back to the device string (`whoami@hostname`), which won't.

---

## Minimum vs. recommended

**Minimum to function (whole company runs):**
- 1 upstream provider key (`GATEWAY_ANTHROPIC_KEY` / `…_GEMINI_KEY` / `…_UPSTREAM_KEY`)
- 1 Palivane API key (`ak_…`)
- 1 ingest token (`EXTENSION_INGEST_TOKEN`)

**Recommended for governance value:**
- Keep the upstream key and ingest token **one per company**.
- Issue **one gateway `ak_…` key per user** (with `actor` set) so attribution and
  coverage are per-person.
- The extension/proxy already get per-person attribution from the `user` field — no
  per-user tokens needed there.

The only place individual tokens genuinely buy you something is the gateway, and even
there it's an attribution choice, not a hard requirement.
