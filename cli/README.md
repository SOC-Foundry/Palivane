# Warden CLI — self-serve onboarding + local planes

Stdlib-only Python scripts (no install; drop them on PATH, e.g. `~/bin/`). Together
they give Warden **local, pre-execution visibility** — the surface the network planes
can't reach (cert-pinned clients, stdio MCP servers, on-device drift, secrets at rest) —
without an endpoint agent: each is an app-scoped hook/shim that rides the existing ingest APIs.

| Script | Plane | Reports to |
| --- | --- | --- |
| `warden-connect` | onboarding — wires up everything below | — |
| `warden-reenroll` | Claude Code `apiKeyHelper` — self-enrolls/rotates a per-device key | `POST /api/enroll` |
| `warden-hook` | **Claude Code** prompts + tool calls, before execution | `POST /api/ingest/{mcp,ai-usage}` |
| `warden-cursor-hook` | **Cursor** prompts + tool calls, before execution | `POST /api/ingest/{mcp,ai-usage}` |
| `warden-codex-hook` | **Codex CLI** prompts + tool calls, before execution | `POST /api/ingest/{mcp,ai-usage}` |
| `warden-gemini-hook` | **Gemini CLI** prompts + tool calls, before execution | `POST /api/ingest/{mcp,ai-usage}` |
| `warden-mcp` | local **stdio MCP servers**, inline | `POST /api/ingest/mcp` |
| `warden-posture` | device drift: IDE extensions, MCP configs | `POST /api/scan/*` |
| `warden-secrets` | **credentials at rest** (SSH/RSA keys, tokens, `.env`) | `POST /api/scan/secrets` |
| `warden-import` | pipe **TruffleHog / Gitleaks / GitGuardian** output into Warden | `POST /api/scan/import` |
| `warden-otel` | bridge **claude-otel** telemetry (Claude Code OTEL) into Warden | `POST /api/ingest/{ai-usage,mcp}` |

All of them are **monitor by default, fail-open always**: Warden being down or slow
never blocks a developer. Enforcement is opt-in per plane (env vars below). `warden-otel`
is inherently monitor-only — it reads *post-hoc* telemetry, so it observes but can't block.

## `warden-connect` — self-serve onboarding

The terminal equivalent of the browser-extension sign-in: a user connects **Claude Code**
to their Warden tenant by signing in through the console (login or SSO), with no admin
distributing tokens.

```bash
warden-connect https://app.warden.io      # or: WARDEN_URL=https://app.warden.io warden-connect
warden-connect --route-gateway            # additionally reroute API traffic via the gateway
```

What happens:
1. Opens your browser to the Warden console and you authenticate (password or SSO).
2. The console mints a **per-user, tenant-scoped** capture key and hands it back to a
   loopback server the CLI started (state-checked; token only ever goes to `127.0.0.1`).
3. The CLI writes `~/.claude/settings.json` (mode `600`): `WARDEN_URL`/`WARDEN_TOKEN` for
   the local planes, and — when the sibling scripts are on PATH — **PreToolUse** +
   **UserPromptSubmit** hooks (`warden-hook` — tool calls, and the typed prompt before it
   leaves the device) and a **SessionStart** hook (`warden-posture --async --quiet`). Hook
   merging is idempotent and leaves your other hooks alone.

   **Claude Code keeps its own sign-in by default** (Pro/Max subscription or API account).
   With `--route-gateway` it additionally writes the gateway routing
   (`ANTHROPIC_BASE_URL` → the Warden gateway, `ANTHROPIC_AUTH_TOKEN` → your key) — note
   that bills the org's provider key (API credits), not personal Pro/Max plans. Without
   the flag, a re-run **removes** gateway routing left by a previous connect (only when the
   base URL points at this Warden backend — a custom `ANTHROPIC_BASE_URL` the user set
   themselves is left alone). Fleet remediation is therefore: users re-run `warden-connect`.
4. If **Cursor** is installed (`~/.cursor` present) and `warden-cursor-hook` is on PATH, it
   also registers the hook for the five security events in `~/.cursor/hooks.json` and writes
   the creds to `~/.cursor/warden.json` (Cursor doesn't pass env to hook processes). Skipped
   silently if Cursor isn't present.
5. Likewise for the other agent CLIs: **Gemini CLI** (`~/.gemini` present +
   `warden-gemini-hook`) gets `BeforeAgent`/`BeforeTool` hooks in `~/.gemini/settings.json`
   + creds in `~/.gemini/warden.json`; **Codex CLI** (`~/.codex` present +
   `warden-codex-hook`) gets `UserPromptSubmit`/`PreToolUse` hooks in `~/.codex/hooks.json`
   + creds in `~/.codex/warden.json` (Codex asks you to trust the hook once — `/hooks`).
6. Restart the tools — prompts and tool calls are inspected locally, posture reports on
   session start (and with `--route-gateway`, prompts route through the gateway); all
   attributed to you and revocable in the console like any key.

## `warden-reenroll` — self-healing device key (apiKeyHelper)

A Claude Code [`apiKeyHelper`](https://docs.claude.com/en/docs/claude-code/settings): Claude
Code runs it to fetch the gateway credential, so its **stdout is only the key**. Instead of
baking a static `ANTHROPIC_AUTH_TOKEN` into managed settings (which dies the moment an admin
revokes it, needing a re-push to every machine), the `/api/provision` installer points
`apiKeyHelper` here. On each call it returns a live per-device key; if the cached key has
been revoked/rotated (`GET /api/enroll/check` returns 401) it re-enrolls from the on-disk
enrollment token — so a device self-heals within one apiKeyHelper TTL, no admin action.

```bash
warden-reenroll                    # print a live device key (apiKeyHelper mode)
warden-reenroll --refresh          # force a fresh enrollment, ignoring the cache
warden-reenroll --setup URL TOKEN  # write ~/.warden/enroll.json (installer helper)
```

Config (first found wins): `$WARDEN_URL`/`$WARDEN_ENROLL_TOKEN` env, else
`~/.warden/enroll.json`, else `/etc/warden/enroll.json` (system-wide, written by the
installer). Caches the device key at `~/.warden/device-key` (0600). Network down → falls
back to the cached key so Claude Code keeps working offline.

## `warden-hook` — pre-execution inspection of Claude Code tool calls & prompts

A Claude Code hook, dispatched on `hook_event_name`. **PreToolUse**: every tool call
(built-ins like `Bash`/`Read`/`Write` *and* MCP tools) is mapped onto Warden's
MCP-activity shape and inspected **before it runs** — dangerous commands,
sensitive-resource access, secrets/PII in arguments, and the org's MCP-server allowlist
(built-ins are exempt from the allowlist; they aren't MCP servers).
**UserPromptSubmit**: the typed prompt is scanned **before it leaves the device** — under
the default subscription sign-in no gateway or proxy is in the path, so this hook is the
only thing that sees it.

- **Monitor (default):** tool-call verdicts are recorded with zero added latency (a
  detached child posts the report). Prompts are scanned **inline even in monitor mode**,
  so a *confirmed* secret/PII leak (`force_block`) is stopped before it leaves — same
  rule as the egress proxy: block the certain, monitor the fuzzy.
- **Enforce (`WARDEN_ENFORCE=true`):** everything scans synchronously and any high-risk
  verdict is denied — the reason is shown to the model (tool calls) or the user (blocked
  prompts are erased).
- **Org-wide default:** an admin sets the stance once in the console (Settings →
  *Device enforcement*). `warden-connect` provisions it into every device it connects,
  and inline verdicts carry the live value (`enforce`) so prompt blocking follows the
  console without a reconnect. A local `WARDEN_ENFORCE=true` still wins.
- **Staged rollout:** a policy override (console → Policies) can force enforce/monitor
  for one user, a group glob (`*@pilot.acme.com`), or a single tool — pilot a team on
  enforcement while the rest of the org stays in monitor. Overrides ride the same
  verdict `enforce` field, so no device config changes.

Installed by `warden-connect`, or manually in `~/.claude/settings.json` /
`managed-settings.json` (MDM):

```json
{ "hooks": {
    "PreToolUse":       [{ "matcher": "*", "hooks": [
        { "type": "command", "command": "/usr/local/bin/warden-hook", "timeout": 10 }]}],
    "UserPromptSubmit": [{ "hooks": [
        { "type": "command", "command": "/usr/local/bin/warden-hook", "timeout": 10 }]}]}}
```

Credentials: `WARDEN_URL` + `WARDEN_TOKEN` (an `ak_…` key) from the environment or the
settings `env` block; the gateway token written by `warden-connect` doubles as both.

## `warden-cursor-hook` — Cursor coverage despite cert pinning

Cursor's chat endpoint pins its certificate (the proxy can't read it) and ignores
`OPENAI_BASE_URL` (the gateway can't be interposed). This adapter uses **Cursor's Hooks
API** (Cursor 1.7+) to inspect from *inside* Cursor — one script dispatched on
`hook_event_name`:

| Cursor event | Inspected | Reports to |
| --- | --- | --- |
| `beforeSubmitPrompt` | the prompt (+ attachments) — **data-loss the proxy can't see** | `/api/ingest/ai-usage` |
| `beforeShellExecution` | shell command | `/api/ingest/mcp` |
| `beforeMCPExecution` | MCP tool call (server/tool/args) | `/api/ingest/mcp` |
| `beforeReadFile` | file content pulled into context | `/api/ingest/mcp` |
| `afterFileEdit` | written content (secrets/PII) — monitor-only | `/api/ingest/mcp` |

- **Monitor (default):** verdict recorded via a detached child; the action is explicitly
  allowed with ~zero latency.
- **Enforce (`WARDEN_ENFORCE=true`):** synchronous scan; blocks are returned as Cursor's
  `permission: deny` (or `continue: false` for a prompt), with the reason shown to the
  user and agent. `afterFileEdit` is always monitor (Cursor accepts no output there).

Register in `~/.cursor/hooks.json`, `<project>/.cursor/hooks.json`, or the enterprise path
(MDM). The policy pack emits a ready-to-push `cursor-hooks.json`:

```json
{ "version": 1, "hooks": {
    "beforeSubmitPrompt":   [{ "command": "/usr/local/bin/warden-cursor-hook" }],
    "beforeShellExecution": [{ "command": "/usr/local/bin/warden-cursor-hook" }],
    "beforeMCPExecution":   [{ "command": "/usr/local/bin/warden-cursor-hook" }],
    "beforeReadFile":       [{ "command": "/usr/local/bin/warden-cursor-hook" }],
    "afterFileEdit":        [{ "command": "/usr/local/bin/warden-cursor-hook" }]}}
```

Credentials: `WARDEN_URL` + `WARDEN_TOKEN` from the environment, else `~/.cursor/warden.json`
(`{"url","token","enforce"}`), else the gateway pair `warden-connect` wrote to
`~/.claude/settings.json`.

## `warden-codex-hook` — Codex CLI coverage despite subscription auth

Under the default **ChatGPT-subscription sign-in**, Codex talks to the ChatGPT backend
and ignores `OPENAI_BASE_URL` (custom providers require API-key auth) — so neither the
gateway nor the proxy reliably sees its prompts. This adapter uses **Codex's lifecycle
hooks** (codex 0.116+, on by default in current releases; the schema mirrors Claude
Code's) to inspect from *inside* Codex:

| Codex event | Inspected | Reports to |
| --- | --- | --- |
| `UserPromptSubmit` | the typed prompt, before the model sees it | `/api/ingest/ai-usage` |
| `PreToolUse` | shell / MCP tool calls, before execution | `/api/ingest/mcp` |

Same monitor/enforce semantics as `warden-hook` (prompts scan inline even in monitor
mode; `force_block` always wins). Registered by `warden-connect` in `~/.codex/hooks.json`
(Codex asks for a one-time trust approval — `/hooks` inside Codex), or pushed fleet-wide
as **managed hooks** via Codex's `requirements.toml` (auto-trusted;
`allow_managed_hooks_only = true` locks out user hooks). The policy pack emits a
ready-to-push `codex-hooks.json`. Credentials: `WARDEN_URL` + `WARDEN_TOKEN` from the
environment, else `~/.codex/warden.json`, else `~/.claude/settings.json`.

## `warden-gemini-hook` — Gemini CLI coverage in every auth mode

Gemini CLI's endpoint depends on its auth mode (API key / Google login / Vertex), only
the API-key mode honors a base-URL override, and the default **"log in with Google"**
mode ignores it entirely. This adapter uses **Gemini CLI's hooks system**
(gemini-cli 0.26+) to inspect from *inside* the CLI, independent of auth mode:

| Gemini event | Inspected | Reports to |
| --- | --- | --- |
| `BeforeAgent` | the typed prompt, before the model sees it | `/api/ingest/ai-usage` |
| `BeforeTool` | shell / file / MCP tool calls, before execution | `/api/ingest/mcp` |

Same monitor/enforce semantics as `warden-hook` (prompts scan inline even in monitor
mode; `force_block` always wins); blocks return Gemini's `{"decision": "deny"}` with the
reason. Registered by `warden-connect` in `~/.gemini/settings.json` (note: Gemini hook
timeouts are **milliseconds**), or pushed fleet-wide to the system settings path (Linux
`/etc/gemini-cli/settings.json`, macOS `/Library/Application Support/GeminiCli/`,
Windows `C:\ProgramData\gemini-cli\`). The policy pack emits a ready-to-merge
`gemini-settings.json`. Credentials: `WARDEN_URL` + `WARDEN_TOKEN` from the environment,
else `~/.gemini/warden.json`, else `~/.claude/settings.json`.

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

Monitor mode **batches** its reports — one request per `WARDEN_MCP_BATCH` tool calls
(default 20) or every `WARDEN_MCP_FLUSH_MS` (default 2000), whichever first — so a busy
session doesn't hammer the backend; enforce mode scans each request inline. Server-side,
the backend drops benign tool calls from storage and meters sensor ingest **separately**
from the gateway (its own `INGEST_RATE_LIMIT` / per-tenant `ingest_rate_limit`), so this
traffic never trips the gateway rate limit.

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

## `warden-secrets` — credentials at rest (infostealer surface)

Infostealers don't phish — they grab credentials already on the box. This scans the places
they actually live and reports what it finds *before* a stealer does:

- well-known credential files: `~/.ssh/id_*` / `*.pem` / `*.key`, `~/.aws/credentials`,
  `~/.config/gh/hosts.yml`, `.git-credentials`, `.npmrc`, `.pypirc`, `.netrc`,
  `~/.docker/config.json`, `~/.kube/config`, **cloud service-account keys/tokens** (gcloud
  ADC + legacy, `~/.azure/accessTokens.json`), **DB creds** (`~/.pgpass`, `~/.my.cnf`),
  **Ansible/vault password** files, and shell history;
- a bounded sweep of dev/data roots (`~/src`, `~/code`, `~/Desktop`, `~/Documents`, … and
  `.`; prunes `node_modules`/`.git`/venvs, depth- and size-capped) for `.env`-style files,
  common **config files** (`settings.py`, `config.yml`, `appsettings.json`, `wp-config.php`,
  `docker-compose.yml`, …), **Terraform state** (`*.tfstate`), **key/cert material**
  (`*.pem`/`*.key`/`*.p12`/`*.pfx`/`*.ppk` — binary keystores flagged by extension), and
  **service-account JSON**. Add more roots (e.g. server paths) via `WARDEN_SECRETS_ROOTS`
  (`/etc:/opt:/srv`) or `--root`.

**Privacy by design:** detection runs locally and only **metadata** leaves the machine —
the secret *type*, path, line, a masked preview (`ghp_••••4f2a`), and whether the file is
world/group-readable. The raw secret never leaves the device. Each file becomes a
`credential_at_rest` finding (`POST /api/scan/secrets`) with a rotate/lock-down plan.

```bash
warden-secrets                     # scan + report to Warden
warden-secrets --dry-run           # print findings locally, send nothing
warden-secrets --root ~/work       # add a directory to the .env sweep
warden-secrets --engine trufflehog # drive TruffleHog (~800 detectors + live verify)
warden-secrets --engine gitleaks   # drive Gitleaks instead of the built-in patterns
```

With `--engine`, Warden runs the external scanner if it's on `PATH`, **masks its findings
locally** (raw secrets never leave), and feeds the same pipeline — so you get TruffleHog's
breadth and live-verification while Warden stays the system of record. Falls back to the
built-in regex scan if the tool isn't installed. Best scheduled (cron / launchd / Scheduled
Task) or pushed via MDM. Config: `WARDEN_URL`/`WARDEN_TOKEN` from the env or `warden-connect`.

## `warden-import` — pipe existing scanner jobs into Warden (CI)

Already run TruffleHog / Gitleaks / GitGuardian in CI? Pipe their JSON to `warden-import` and
the findings become unified Warden `credential_at_rest` findings — one console, one scoring
model, one alert/SIEM path across every scanner. The backend **masks the secret at ingest and
never persists the raw value**; TruffleHog's `Verified` flag escalates a live credential to
critical, and the command exits non-zero when any verified-live secret is found (so it can
fail the build).

```bash
trufflehog git file://. --json                        | warden-import trufflehog
gitleaks detect --report-format json -o /dev/stdout . | warden-import gitleaks
ggshield secret scan path . --json                    | warden-import gitguardian
```

## `warden-otel` — claude-otel telemetry bridge (optional)

For orgs already running [claude-otel](https://github.com/TachTech-Engineering/claude-otel)
(a local OTEL collector capturing Claude Code's native telemetry into `logs.jsonl`), this
tails that file and forwards the security-relevant events to Warden — a capture plane with
**no proxy, no CA, no hook**, from telemetry Claude Code already emits:

| Claude Code OTEL event | Inspected | Reports to |
| --- | --- | --- |
| `user_prompt` | prompt text — injection / secrets / PII | `/api/ingest/ai-usage` |
| `tool_result` | tool name + arguments — dangerous commands, sensitive paths, secrets | `/api/ingest/mcp` (batched) |
| `mcp_server_connection` | server name — untrusted-server allowlist | `/api/ingest/mcp` |

**Monitor-only:** OTEL is *post-hoc* (a `tool_result` fires after the tool ran), so this
plane observes and records — it can't block. Pair it with the inline hook/gateway for
enforcement. Its depth tracks the claude-otel **privacy profile**: `minimal` = coverage
only (content redacted), `standard` = prompt DLP, `full` = tool-argument DLP.

```bash
# one-shot (cron): forward any new telemetry, then exit
WARDEN_URL=… WARDEN_TOKEN=ak_… warden-otel --once
# sidecar: follow the collector's log continuously (systemd/launchd, next to claude-otel)
warden-otel
```

Reads `WARDEN_URL`/`WARDEN_TOKEN` from the env or `~/.claude/settings.json`. `WARDEN_OTEL_LOGS`
overrides the `logs.jsonl` path (defaults to claude-otel's data root per-OS); `WARDEN_OTEL_INTERVAL`
the follow poll seconds. A byte-accurate offset+inode cursor (`~/.warden/otel-state.json`)
survives restarts and log rotation, so nothing is double-sent or missed.

### Fileless / real-time: OTLP straight to Warden

Instead of the CLI tailing a file, point the claude-otel collector's `otlphttp` logs exporter
directly at Warden's OTLP receiver (`POST /v1/logs`, OTLP-JSON) — same mapping, no sidecar,
near-real-time. Add to the collector's `otel-collector.yaml` and **fan out** so the local
file (and your Panther pipeline) still works:

```yaml
exporters:
  otlphttp/warden:
    logs_endpoint: https://warden.example.com/v1/logs
    encoding: json
    headers:
      X-Warden-Token: ak_<a Warden capture key>

service:
  pipelines:
    logs:
      exporters: [file/logs, otlphttp/warden]   # keep the file; also ship to Warden
```

Warden always answers OTLP success (a telemetry export must never back up on our account);
one export counts as one hit against the tenant's ingest quota. Same monitor-only, same
privacy-profile scaling as the CLI. Choose the CLI when you'd rather not touch the collector
config; choose OTLP when you want fileless/real-time.

## Managed fleets

On managed devices, prefer the zero-touch path: push Claude Code `managed-settings.json`
via MDM (the `/api/provision` installer generates it) — it can carry the same `env` and
`hooks` blocks `warden-connect` writes, plus the `warden-mcp` wrapper in a pushed MCP
config. Managed settings take precedence over the user `settings.json`.

## Egress proxy (CLIs + desktop apps)

Tools that talk to Anthropic directly over HTTPS (and don't read `ANTHROPIC_BASE_URL`) are
captured by the **egress proxy** rather than by `warden connect`. `warden-desktop install`
sets it up, and it has two postures:

- **`--cli-only` (default)** — per-tool PATH shims route the AI CLIs (Claude Code, Codex,
  Gemini) through the proxy via `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`. **No sudo**, no
  system-wide changes; the right fit for small orgs without MDM.
- **`--desktop`** — installs the CA into the system trust store and sets the system proxy,
  so **Claude/ChatGPT Desktop**, Cursor, and browsers are governed system-wide (needs sudo,
  or push the proxy + CA via MDM for a zero-touch fleet).

The one-line installer runs `--cli-only` by default:

```bash
curl -fsSL https://warden.tachtech.net/install.sh | bash                  # CLI capture (no sudo)
curl -fsSL https://warden.tachtech.net/install.sh | bash -s -- --desktop  # + desktop apps/browsers
```

### Windows

`warden-desktop.ps1` is the PowerShell 5.1 port — same subcommands (`install`,
`install -CliOnly`, `uninstall`, `status`), all **per-user, no admin**: the CA goes into
the CurrentUser Root store (Windows shows a one-time confirmation dialog), the proxy is
the WinINET *user* proxy (WinHTTP/services are MDM territory), persistence is a hidden
per-user Scheduled Task, and the CLIs get `.cmd` shims in `%USERPROFILE%\.warden\bin`:

```powershell
iwr https://warden.tachtech.net/cli/warden-desktop.ps1 -OutFile warden-desktop.ps1
powershell -ExecutionPolicy Bypass -File warden-desktop.ps1 install            # or: install -CliOnly
```

See [`docs/claude-deployment.md`](../docs/claude-deployment.md) and the
[MDM policy pack](../docs/mdm-policy-pack.md).
