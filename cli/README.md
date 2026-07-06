# `warden connect` — self-serve Claude Code onboarding

The terminal equivalent of the browser-extension sign-in: a user connects **Claude Code**
to their Warden tenant by signing in through the console (login or SSO), with no admin
distributing tokens.

```bash
warden-connect https://app.warden.io      # or: WARDEN_URL=https://app.warden.io warden-connect
```

What happens:
1. Opens your browser to the Warden console and you authenticate (password or SSO).
2. The console mints a **per-user, tenant-scoped** capture key and hands it back to a
   loopback server the CLI started (state-checked; token only ever goes to `127.0.0.1`).
3. The CLI writes `~/.claude/settings.json` (mode `600`):
   ```json
   { "env": {
     "ANTHROPIC_BASE_URL": "https://app.warden.io/v1",
     "ANTHROPIC_AUTH_TOKEN": "ak_…"
   } }
   ```
4. Restart Claude Code — every prompt now routes through the Warden gateway, attributed to
   you, and is revocable in the console like any key.

Stdlib-only Python 3; no install needed. Drop it on PATH (e.g. `~/bin/warden-connect`).

## Managed fleets
On managed devices, prefer the zero-touch path instead: push Claude Code
`managed-settings.json` via MDM (the `/api/provision` installer generates it). Managed
settings take precedence over the user `settings.json` this CLI writes.

## Claude Desktop
Claude **Desktop** can't be onboarded this way — it talks to Anthropic directly over HTTPS
and doesn't read `ANTHROPIC_BASE_URL`. It's captured by the **egress proxy** (system proxy
+ corporate CA), which is an admin/MDM setup, not a per-user sign-in. See
[`docs/claude-deployment.md`](../docs/claude-deployment.md) and the
[MDM policy pack](../docs/mdm-policy-pack.md).
