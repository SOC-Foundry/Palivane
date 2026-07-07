# Warden CLI — self-serve onboarding + local planes

Four stdlib-only Python scripts (no install; drop them on PATH, e.g. `~/bin/`). Together
they give Warden **local, pre-execution visibility** — the surface the network planes
can't reach (cert-pinned clients, stdio MCP servers, on-device drift) — without an
endpoint agent: each is an app-scoped hook/shim that rides the existing ingest APIs.

| Script | Plane | Reports to |
| --- | --- | --- |
| `warden-connect` | onboarding — wires up everything below | — |
| `warden-hook` | Claude Code tool calls, **before execution** | `POST /api/ingest/mcp` |
| `warden-mcp` | local **stdio MCP servers**, inline | `POST /api/ingest/mcp` |
| `warden-posture` | device drift: IDE extensions, MCP configs | `POST /api/scan/*` |

All of them are **monitor by default, fail-open always**: Warden being down or slow
never blocks a developer. Enforcement is opt-in per plane (env vars below).

## `warden-connect` — self-serve onboarding

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
3. The CLI writes `~/.claude/settings.json` (mode `600`): the gateway routing
   (`ANTHROPIC_BASE_URL` → the Warden gateway, `ANTHROPIC_AUTH_TOKEN` → your key), the
   same pair as `WARDEN_URL`/`WARDEN_TOKEN` for the local planes, and — when the sibling
   scripts are on PATH — a **PreToolUse** hook (`warden-hook`) and a **SessionStart**
   hook (`warden-posture --async --quiet`). Hook merging is idempotent and leaves your
   other hooks alone.
4. Restart Claude Code — prompts route through the gateway, tool calls are inspected
   locally, posture reports on session start; all attributed to you and revocable in the
   console like any key.

## `warden-hook` — pre-execution tool-call inspection

A Claude Code **PreToolUse** hook: every tool call (built-ins like `Bash`/`Read`/`Write`
*and* MCP tools) is mapped onto Warden's MCP-activity shape and inspected **before it
runs** — dangerous commands, sensitive-resource access, secrets/PII in arguments, and
the org's MCP-server allowlist (built-ins are exempt from the allowlist; they aren't MCP
servers).

- **Monitor (default):** the verdict is recorded with zero added latency (a detached
  child posts the report).
- **Enforce (`WARDEN_ENFORCE=true`):** the hook scans synchronously and denies risky
  calls — the reason is shown to the model, which can adjust course.

Installed by `warden-connect`, or manually in `~/.claude/settings.json` /
`managed-settings.json` (MDM):

```json
{ "hooks": { "PreToolUse": [{ "matcher": "*", "hooks": [
    { "type": "command", "command": "/usr/local/bin/warden-hook", "timeout": 10 }]}]}}
```

Credentials: `WARDEN_URL` + `WARDEN_TOKEN` (an `ak_…` key) from the environment or the
settings `env` block; the gateway token written by `warden-connect` doubles as both.

## `warden-mcp` — inline inspection for local stdio MCP servers

Local stdio MCP servers never touch the network, so the egress proxy can't see them.
Wrap the server command and the JSON-RPC flows through untouched while every tool call,
resource read, and advertised tool description is inspected (tool poisoning included):

```json
{ "mcpServers": { "github": {
    "command": "warden-mcp",
    "args": ["--", "npx", "-y", "@modelcontextprotocol/server-github"] }}}
```

- **Monitor (default):** report-only, zero interference.
- **Enforce (`WARDEN_MCP_ENFORCE=true`):** a risky request is *not forwarded* — the
  client gets a JSON-RPC error naming the reason; a poisoned `tools/list` result is
  replaced the same way.

Framing is preserved exactly (original bytes forwarded, never re-serialized); non-JSON
lines and unknown methods pass straight through. `--name`/`WARDEN_MCP_SERVER` sets the
server name checked against the org allowlist (else guessed from the command, upgraded
by the server's own `initialize` response).

## `warden-posture` — device posture / drift

Reports what's actually on the device through the existing scan endpoints, so drift (a
rogue IDE extension, a new unapproved MCP server) surfaces as a finding shortly after it
happens:

- installed VS Code extensions (`code --list-extensions`) → `/api/scan/ide-extensions`
- MCP configs → `/api/scan/mcp-config`: `~/.claude.json` (synthesized down to
  `{"mcpServers": …}` — the raw file holds unrelated user state and never leaves the
  machine), `./.mcp.json`, VS Code and Cursor user configs.

A sha256 cache (`~/.warden/posture-cache.json`) skips unchanged state, so repeated runs
don't spam findings. `warden-connect` wires it to Claude Code session start; a cron or
launchd job works for non-Claude fleets. Flags: `--force`, `--dry-run`, `--quiet`,
`--async` (detach and return immediately).

## Managed fleets

On managed devices, prefer the zero-touch path: push Claude Code `managed-settings.json`
via MDM (the `/api/provision` installer generates it) — it can carry the same `env` and
`hooks` blocks `warden-connect` writes, plus the `warden-mcp` wrapper in a pushed MCP
config. Managed settings take precedence over the user `settings.json`.

## Claude Desktop

Claude **Desktop** can't be onboarded this way — it talks to Anthropic directly over HTTPS
and doesn't read `ANTHROPIC_BASE_URL`. It's captured by the **egress proxy** (system proxy
+ corporate CA), which is an admin/MDM setup, not a per-user sign-in. See
[`docs/claude-deployment.md`](../docs/claude-deployment.md) and the
[MDM policy pack](../docs/mdm-policy-pack.md).
