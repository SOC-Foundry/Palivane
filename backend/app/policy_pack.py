"""MDM policy-pack generator — agentless enforcement config.

Produces the config artifacts an organization's **MDM** pushes to managed devices so the
*enforcement* side of Palivane is handled without any Palivane agent on the box:

- **VS Code extension allowlist** (`extensions.allowed`) — lets only approved extensions
  install and blocks known-bad ones (the enforcement counterpart to /api/scan/ide-extensions);
- **system proxy** (macOS `.mobileconfig`, Windows `.reg`) — routes egress through the
  Palivane proxy so MCP/AI traffic is inspected;
- **browser extension force-install** (Chrome/Edge `ExtensionInstallForcelist`);
- a **CA deployment note** — the corporate/egress-proxy root CA must be trusted for TLS
  inspection (the cert itself is the org's; we only say where it goes).

Everything here is applied by the customer's MDM (Jamf/Intune/GPO), not by a Palivane
process — so it's agentless. Pure string templating, unit-testable.
"""

from __future__ import annotations

import json
import os


def vscode_extension_policy(allowed: list[str], denied: list[str]) -> str:
    """VS Code `extensions.allowed` settings. With an allowlist, deny-all-by-default (`*`)
    and permit the approved ids; always explicitly deny known-bad ids."""
    entries: dict[str, object] = {}
    if allowed:
        entries["*"] = False
        for e in allowed:
            entries[e] = True
    for d in denied:
        entries[d] = False
    return json.dumps({"extensions.allowed": entries}, indent=2)


def macos_proxy_profile(host: str, port: int) -> str:
    """A macOS configuration profile (.mobileconfig) setting a global manual HTTP/HTTPS proxy."""
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>io.palivane.proxy</string>
  <key>PayloadDisplayName</key><string>Palivane egress proxy</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.proxy.http.global</string>
      <key>PayloadIdentifier</key><string>io.palivane.proxy.http</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>ProxyType</key><string>Manual</string>
      <key>HTTPEnable</key><integer>1</integer>
      <key>HTTPProxy</key><string>{host}</string>
      <key>HTTPPort</key><integer>{port}</integer>
      <key>HTTPSEnable</key><integer>1</integer>
      <key>HTTPSProxy</key><string>{host}</string>
      <key>HTTPSPort</key><integer>{port}</integer>
    </dict>
  </array>
</dict>
</plist>
'''


def windows_proxy_reg(host: str, port: int) -> str:
    """A Windows .reg setting the per-user WinINET proxy (push via MDM/GPO)."""
    return ("Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings]\r\n"
            '"ProxyEnable"=dword:00000001\r\n'
            f'"ProxyServer"="{host}:{port}"\r\n')


_WEBSTORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"


def chrome_forcelist(extension_id: str, update_url: str = "") -> str:
    """ExtensionInstallForcelist value for Chrome/Edge (force-install the Palivane extension).

    Default pulls from the Chrome Web Store (the extension must be published there —
    Unlisted is fine). Pass a self-hosted `update_url` (your updates.xml) to force-install
    a self-hosted CRX with no Web Store submission — managed devices only."""
    from .config import settings
    eid = extension_id or settings.extension_id   # the configured published id (single source)
    return f"{eid};{update_url.strip() or _WEBSTORE_UPDATE_URL}"


def browser_extension_policy(palivane_id: str, palivane_update_url: str = "", lockdown: bool = False,
                             blocked_ids: list[str] | None = None, allowed_ids: list[str] | None = None,
                             blocked_hosts: list[str] | None = None) -> str:
    """Chrome/Edge `ExtensionSettings` policy — govern *third-party* browser extensions,
    including agentic AI ones (e.g. Claude for Chrome) that Palivane's own extension can't
    inspect (Chrome sandboxes extensions from each other). Two stances:

    - default (governed): everything `allowed`, but a denylist of AI extensions is `blocked`
      and permitted extensions are kept off sensitive origins via `runtime_blocked_hosts`.
    - lockdown: default `blocked`; only the allowlist (+ Palivane's own) may install.

    Palivane's own extension is always force-installed. Applied by MDM (Chrome/Edge enterprise)."""
    blocked_ids = blocked_ids or []
    allowed_ids = allowed_ids or []
    blocked_hosts = blocked_hosts or []

    default: dict = {"installation_mode": "blocked" if lockdown else "allowed"}
    if blocked_hosts:                       # keep ALL extensions off these origins
        default["runtime_blocked_hosts"] = blocked_hosts
    settings: dict = {"*": default}

    settings[palivane_id or "REPLACE_WITH_PALIVANE_EXTENSION_ID"] = {
        "installation_mode": "force_installed",
        "update_url": (palivane_update_url.strip() or _WEBSTORE_UPDATE_URL)}
    for i in allowed_ids:
        settings[i] = {"installation_mode": "allowed"}
    for i in blocked_ids:
        settings[i] = {"installation_mode": "blocked"}
    if not lockdown and not blocked_ids:
        # Placeholder so the admin sees where to list AI extensions to block by ID.
        settings["REPLACE_WITH_BLOCKED_AI_EXTENSION_ID"] = {"installation_mode": "blocked"}
    return json.dumps({"ExtensionSettings": settings}, indent=2)


def extension_updates_xml(extension_id: str, crx_url: str, version: str = "0.5.0") -> str:
    """Omaha `updates.xml` for a SELF-HOSTED extension — host this next to the .crx and point
    ExtensionInstallForcelist at its URL. Lets you force-install the extension via MDM without
    ever submitting it to the Web Store (the enterprise-policy exception to store-only installs)."""
    eid = extension_id or "REPLACE_WITH_EXTENSION_ID"
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!-- Self-hosted extension update manifest. Host alongside the signed .crx; set the CRX
     location in `codebase` and keep `version` in sync with the extension's manifest.json.
     Point ExtensionInstallForcelist at THIS file's URL: "{eid};https://your.host/updates.xml". -->
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="{eid}">
    <updatecheck codebase="{crx_url or 'https://your.host/palivane-extension.crx'}" version="{version}" />
  </app>
</gupdate>
'''


def claude_managed_settings(base_url: str, hook_path: str, posture_path: str,
                            route_gateway: bool = False) -> str:
    """Claude Code enterprise `managed-settings.json` — installs the local planes (Route C)
    fleet-wide: PreToolUse + UserPromptSubmit hooks (palivane-hook — pre-execution tool-call
    inspection, and the typed prompt before it leaves the device: under subscription
    sign-in no network plane sees it) and a SessionStart hook (palivane-posture, device
    drift). Managed settings take precedence over user settings.

    By default Claude Code keeps its own sign-in (Pro/Max subscription or API account)
    and `forceLoginMethod: "claudeai"` locks the login flow to subscription accounts.
    With `route_gateway=True` it instead routes prompts through the Palivane gateway
    (`ANTHROPIC_BASE_URL`/`ANTHROPIC_AUTH_TOKEN`) — billing the org's provider key.

    The `ak_…` placeholder is one per-developer Palivane key; for per-user attribution
    without baking it in, use Claude Code's apiKeyHelper. The two scripts must be deployed
    to `hook_path` / `posture_path` on the device (push via the same MDM)."""
    b = base_url.rstrip("/")
    token = "ak_REPLACE_WITH_PER_USER_PALIVANE_KEY"
    env = {
        "PALIVANE_URL": b,
        "PALIVANE_TOKEN": token,
    }
    if route_gateway:
        # No /v1 suffix: the Anthropic SDK appends /v1/messages itself, so a base of
        # {b}/v1 would resolve to {b}/v1/v1/messages and 405. (Unlike OPENAI_BASE_URL,
        # which does take /v1.) The gateway route is {b}/v1/messages.
        env = {"ANTHROPIC_BASE_URL": b, "ANTHROPIC_AUTH_TOKEN": token, **env}
    data = {
        "env": env,
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": hook_path, "timeout": 10}]}],
            "UserPromptSubmit": [{"hooks": [
                {"type": "command", "command": hook_path, "timeout": 10}]}],
            "SessionStart": [{"matcher": "*", "hooks": [
                {"type": "command", "command": f"{posture_path} --async --quiet"}]}],
        },
    }
    if not route_gateway:
        data["forceLoginMethod"] = "claudeai"
    return json.dumps(data, indent=2)


def openai_env(base_url: str) -> str:
    """Drop-in env for OpenAI SDK / CLI clients — routes them through the Palivane gateway's
    OpenAI-compatible endpoint (`/v1/chat/completions`) instead of api.openai.com. Covers
    clients that pin certs or otherwise bypass the egress proxy. `OPENAI_BASE_URL` is the
    current var; `OPENAI_API_BASE` is the legacy name older SDKs still read."""
    b = base_url.rstrip("/")
    return (
        "# Route OpenAI SDK/CLI clients through the Palivane gateway (agentless — no proxy CA\n"
        "# needed). Push via MDM as machine/user environment variables. The ak_ value is a\n"
        "# per-user Palivane capture key and doubles as the gateway auth token.\n"
        f'OPENAI_BASE_URL="{b}/v1"\n'
        f'OPENAI_API_BASE="{b}/v1"\n'
        'OPENAI_API_KEY="ak_REPLACE_WITH_PER_USER_PALIVANE_KEY"\n'
    )


def gemini_config(base_url: str, gemini_hook_path: str = "/usr/local/bin/palivane-gemini-hook") -> str:
    """Gemini routing note + SDK snippet. Google's google-genai SDK has no universal base-url
    *env var*, so the agentless paths for Gemini are the system proxy (this pack's proxy
    profile inspects generativelanguage.googleapis.com) and, for the Gemini CLI itself,
    the local hooks (gemini-settings.json in this pack) — which work in every auth mode,
    including the default Google login that ignores base-URL overrides. Where a client can
    be code-configured, point it at the gateway's `/v1beta` endpoint as shown."""
    b = base_url.rstrip("/")
    return (
        "Gemini coverage\n"
        "===============\n"
        "Gemini CLI (the agent) — LOCAL HOOKS, the primary plane. The CLI's endpoint depends\n"
        "on its auth mode and the default 'log in with Google' mode ignores base-URL\n"
        "overrides, so gemini-settings.json in this pack registers palivane-gemini-hook\n"
        "(gemini-cli 0.26+) inside the CLI instead:\n"
        "  - BeforeAgent -> prompt data-loss (secrets/PII/shadow-AI), before it leaves\n"
        "  - BeforeTool  -> shell/file/MCP tool calls (dangerous commands, allowlist)\n"
        f"Deploy palivane-gemini-hook to {gemini_hook_path} and push gemini-settings.json to\n"
        "the system settings path (Linux /etc/gemini-cli/settings.json, macOS\n"
        "/Library/Application Support/GeminiCli/settings.json, Windows\n"
        "C:\\ProgramData\\gemini-cli\\settings.json) or merge into ~/.gemini/settings.json.\n"
        "Monitor by default (confirmed secret/PII leaks in prompts still hard-block); set\n"
        "PALIVANE_ENFORCE=true to block on any high-risk verdict. Provide PALIVANE_URL/\n"
        f"PALIVANE_TOKEN via machine env (PALIVANE_URL={b}) or ~/.gemini/palivane.json.\n\n"
        "Gemini SDK/API clients — the SYSTEM PROXY in this pack. It inspects all three\n"
        "modes once your root CA is trusted (see ca-note.txt):\n"
        "  - API-key mode  -> generativelanguage.googleapis.com\n"
        "  - OAuth / Code Assist (default 'log in with Google') -> cloudcode-pa.googleapis.com\n"
        "  - Vertex mode   -> aiplatform.googleapis.com\n\n"
        "For clients you can configure in code, point the Python google-genai SDK at the\n"
        "Palivane gateway's Gemini-shaped endpoint:\n\n"
        "  from google import genai\n"
        "  from google.genai.types import HttpOptions\n"
        f'  client = genai.Client(\n'
        f'      api_key="ak_REPLACE_WITH_PER_USER_PALIVANE_KEY",\n'
        f'      http_options=HttpOptions(base_url="{b}"),  # SDK appends /v1beta/models/...\n'
        "  )\n\n"
        f"Gateway Gemini endpoint: {b}/v1beta/models/{{model}}:generateContent\n"
    )


def gemini_settings(gemini_hook_path: str) -> str:
    """Gemini CLI `settings.json` hooks block registering palivane-gemini-hook on the two
    security-relevant events (gemini-cli 0.26+; timeouts are milliseconds). Push to the
    system settings path via MDM or merge into ~/.gemini/settings.json. Local +
    pre-execution, so it works in every auth mode."""
    entry = {"name": "palivane", "type": "command", "command": gemini_hook_path,
             "timeout": 10000}
    return json.dumps({
        "hooks": {
            "BeforeAgent": [{"hooks": [entry]}],          # prompt data-loss, pre-send
            "BeforeTool": [{"matcher": ".*", "hooks": [entry]}],  # shell/file/MCP calls
        },
    }, indent=2)


def codex_hooks(codex_hook_path: str) -> str:
    """Codex CLI `hooks.json` registering palivane-codex-hook on the two security-relevant
    lifecycle events (codex 0.116+; the schema mirrors Claude Code's). Drop in
    ~/.codex/hooks.json, or push as MANAGED hooks via requirements.toml — managed hooks
    are auto-trusted, and `allow_managed_hooks_only = true` there locks out user hooks."""
    entry = {"type": "command", "command": codex_hook_path, "timeout": 10}
    return json.dumps({
        "hooks": {
            "UserPromptSubmit": [{"hooks": [entry]}],           # prompt data-loss, pre-send
            "PreToolUse": [{"matcher": ".*", "hooks": [entry]}],  # shell/MCP tool calls
        },
    }, indent=2)


def codex_note(base_url: str, codex_hook_path: str) -> str:
    """How Palivane covers Codex CLI — and why the network planes can't."""
    b = base_url.rstrip("/")
    return (
        "Codex CLI coverage\n"
        "==================\n"
        "Under the default ChatGPT-subscription sign-in, Codex talks to the ChatGPT backend\n"
        "and IGNORES OPENAI_BASE_URL (custom providers require API-key auth), so the gateway\n"
        "env in openai.env only covers API-key installs. Palivane covers subscription-auth\n"
        "Codex with LOCAL hooks instead (codex-hooks.json in this pack, codex 0.116+):\n"
        "  - UserPromptSubmit -> prompt data-loss (secrets/PII/shadow-AI), before it leaves\n"
        "  - PreToolUse       -> shell/MCP tool calls (dangerous commands, allowlist)\n"
        f"Deploy palivane-codex-hook to {codex_hook_path} and drop codex-hooks.json in\n"
        "~/.codex/hooks.json — or better, push it as managed hooks via Codex's\n"
        "requirements.toml (auto-trusted; add allow_managed_hooks_only = true to lock out\n"
        "user-defined hooks). User-level hooks need a one-time /hooks trust approval.\n"
        "Monitor by default (confirmed secret/PII leaks in prompts still hard-block); set\n"
        "PALIVANE_ENFORCE=true to block on any high-risk verdict. Provide PALIVANE_URL/\n"
        f"PALIVANE_TOKEN via machine env (PALIVANE_URL={b}) or ~/.codex/palivane.json.\n"
    )


def copilot_hooks(copilot_hook_path: str) -> str:
    """GitHub Copilot hook file registering palivane-copilot-hook on its two lifecycle
    events (Copilot's schema: version: 1, lowerCamelCase events, a `bash` command,
    per-hook timeoutSec). One file serves all three Copilot surfaces: drop in
    ~/.copilot/hooks/palivane.json per device (Copilot CLI), or commit/push as
    .github/hooks/palivane.json per repo — where it also drives VS Code agent mode and
    the CLOUD coding agent (hooks run inside the Actions environment; deploy the hook
    script in a setup step there)."""
    entry = {"type": "command", "bash": copilot_hook_path, "timeoutSec": 10}
    return json.dumps({
        "version": 1,
        "hooks": {
            "preToolUse": [dict(entry)],           # shell/edit/MCP calls — deniable
            "userPromptSubmitted": [dict(entry)],  # prompt record — observe-only
        },
    }, indent=2)


def copilot_note(base_url: str, copilot_hook_path: str) -> str:
    """How Palivane covers GitHub Copilot — and what this plane can/can't block."""
    b = base_url.rstrip("/")
    return (
        "GitHub Copilot coverage\n"
        "=======================\n"
        "Copilot has no base-URL override, so the gateway can't be interposed and the\n"
        "egress proxy sees only TLS to GitHub — not tool calls. Palivane covers Copilot\n"
        "with its native hooks (copilot-hooks.json in this pack):\n"
        "  - preToolUse          -> shell/edit/MCP tool calls, DENIABLE pre-execution\n"
        "                           (dangerous commands, MCP allowlist, secrets in args)\n"
        "  - userPromptSubmitted -> prompt record — OBSERVE-ONLY (Copilot ignores hook\n"
        "                           output here; the proxy remains the prompt-DLP backstop)\n"
        "One hook file covers all three Copilot surfaces:\n"
        f"  - Copilot CLI: deploy palivane-copilot-hook to {copilot_hook_path} and drop\n"
        "    copilot-hooks.json in ~/.copilot/hooks/palivane.json (or push via MDM).\n"
        "  - VS Code agent mode + the CLOUD coding agent: commit copilot-hooks.json as\n"
        "    .github/hooks/palivane.json in each governed repo — the cloud agent runs it\n"
        "    inside the Actions environment (install the hook script in a setup step).\n"
        "    Note: GitHub's own cloud-agent firewall does NOT cover MCP servers; this\n"
        "    hook plus palivane-mcp wrapping of ~/.copilot/mcp-config.json closes that.\n"
        "Semantics to know: Copilot DENIES on a hook's non-zero exit (fail-closed) but\n"
        "ALLOWS on timeout (fail-open) — palivane-copilot-hook always exits 0 and lets the\n"
        "verdict speak. Known upstream gap: subagent tool calls may not fire preToolUse\n"
        "(github/copilot-cli#2392) — don't claim subagent coverage yet.\n"
        "Monitor by default. Tool calls scan inline, so the org's enforce stance\n"
        "(console Settings → Enforcement, stageable per user/tool) denies high-risk tool\n"
        "calls centrally — prompts can't block at this plane. Set PALIVANE_ENFORCE=true to\n"
        f"also enforce from device-local config. Provide PALIVANE_URL/PALIVANE_TOKEN via\n"
        f"machine env (PALIVANE_URL={b}) or ~/.copilot/palivane.json.\n"
    )


def cursor_hooks(hook_path: str) -> str:
    """Cursor `hooks.json` registering palivane-cursor-hook on the security-relevant agent
    events. Push to the enterprise path via MDM (macOS /Library/Application Support/Cursor/,
    Linux /etc/cursor/, Windows C:\\ProgramData\\Cursor\\) or drop in ~/.cursor/hooks.json.
    Local + pre-execution, so it works despite Cursor's cert pinning."""
    entry = [{"command": hook_path}]
    return json.dumps({
        "version": 1,
        "hooks": {
            "beforeSubmitPrompt": entry,     # prompt data-loss (the proxy can't see this)
            "beforeShellExecution": entry,   # dangerous commands
            "beforeMCPExecution": entry,     # MCP tool calls (server allowlist, poisoning)
            "beforeReadFile": entry,         # secrets/PII pulled into context
            "afterFileEdit": entry,          # secrets/PII written (monitor-only)
        },
    }, indent=2)


def cursor_note(base_url: str, hook_path: str) -> str:
    """How Palivane covers Cursor — and the one thing it can't."""
    b = base_url.rstrip("/")
    return (
        "Cursor coverage\n"
        "===============\n"
        "Cursor's model/chat endpoint (api2.cursor.sh) PINS its certificate, so the egress\n"
        "proxy can't read its prompts, and Cursor ignores OPENAI_BASE_URL, so the gateway\n"
        "can't be interposed. Palivane covers Cursor with LOCAL planes instead, which are\n"
        "immune to the pinning:\n\n"
        "1. Cursor hooks (cursor-hooks.json in this pack) — palivane-cursor-hook runs inside\n"
        "   Cursor before each action and reports/blocks:\n"
        "     - beforeSubmitPrompt   -> prompt data-loss (secrets/PII/shadow-AI)\n"
        "     - beforeShellExecution -> dangerous commands\n"
        "     - beforeMCPExecution   -> MCP tool calls (server allowlist, tool poisoning)\n"
        "     - beforeReadFile       -> secrets/PII pulled into context\n"
        "     - afterFileEdit        -> secrets/PII written (monitor-only)\n"
        f"   Deploy palivane-cursor-hook to {hook_path} and push cursor-hooks.json to Cursor's\n"
        "   enterprise hooks path (or ~/.cursor/hooks.json). Monitor by default; set\n"
        "   PALIVANE_ENFORCE=true to block. Provide PALIVANE_URL/PALIVANE_TOKEN via machine env\n"
        f"   (PALIVANE_URL={b}) or ~/.cursor/palivane.json.\n"
        "2. MCP servers — wrap Cursor's .cursor/mcp.json stdio servers with palivane-mcp for\n"
        "   inline tool inspection (belt-and-suspenders with beforeMCPExecution).\n"
        "3. Git plane — secrets/PII in the code Cursor commits (pre-commit hook + Action).\n"
        "4. Gateway — for any first-party AI your org routes explicitly.\n\n"
        "Optional (pilots): Cursor Settings -> Models -> Override OpenAI Base URL =\n"
        f"  {b}/v1  (key = an ak_ Palivane key). This routes Cursor's OpenAI-compatible calls\n"
        "  through the gateway, but disables Agent/Composer/Tab — most orgs prefer the hooks.\n\n"
        "What is NOT captured: nothing, once the hooks are installed — beforeSubmitPrompt\n"
        "sees the prompt locally before it leaves. Without the hooks, Cursor's cloud chat is\n"
        "opaque to the network planes.\n"
    )


def _engine_args(engine: str) -> list[str]:
    """['--engine', 'trufflehog'] when an external scanner is chosen, else []. palivane-secrets
    falls back to its built-in regex scan if the tool isn't installed, so this is safe to
    ship fleet-wide even on devices that don't have TruffleHog/Gitleaks."""
    e = (engine or "").strip().lower()
    return ["--engine", e] if e in ("trufflehog", "gitleaks") else []


def secrets_launchd(base_url: str, secrets_path: str, engine: str = "trufflehog") -> str:
    """macOS LaunchAgent — runs palivane-secrets daily (3am) as the signed-in user, so it
    can read ~/.ssh etc. and the palivane-connect creds. Push to ~/Library/LaunchAgents via MDM."""
    b = base_url.rstrip("/")
    argv = "".join(f"<string>{a}</string>" for a in [secrets_path, *_engine_args(engine)])
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.palivane.secrets</string>
  <key>ProgramArguments</key>
  <array>{argv}</array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>3</integer><key>Minute</key><integer>0</integer></dict>
  <key>EnvironmentVariables</key>
  <dict><key>PALIVANE_URL</key><string>{b}</string></dict>
  <key>StandardErrorPath</key><string>/tmp/palivane-secrets.log</string>
</dict>
</plist>
'''


def secrets_cron(base_url: str, secrets_path: str, engine: str = "trufflehog") -> str:
    """Linux cron fragment (drop in /etc/cron.d/ or a user crontab) — daily at 03:00.
    PALIVANE_TOKEN comes from the palivane-connect creds file the scanner reads, or set it here."""
    b = base_url.rstrip("/")
    cmd = " ".join([secrets_path, *_engine_args(engine)])
    return (f"# Palivane endpoint credential scan — daily. Runs as the target user so it can\n"
            f"# read ~/.ssh etc. Token resolves from ~/.claude/settings.json / ~/.cursor/palivane.json.\n"
            f"PALIVANE_URL={b}\n"
            f"0 3 * * * {os.getenv('USER', '<user>')} {cmd}\n")


def secrets_win_task(base_url: str, secrets_path: str, engine: str = "trufflehog") -> str:
    """Windows Task Scheduler XML — daily at 03:00. Import with schtasks /create /xml.

    Runs the scanner through the launcher `palivane-desktop.ps1 install` writes
    (%USERPROFILE%\\.warden\\bin\\palivane-secrets.cmd), which resolves an interpreter and
    carries PALIVANE_URL/PALIVANE_TOKEN. An explicit Windows `secrets_path` (containing a
    backslash) overrides it — e.g. a packaged palivane-secrets.exe you deploy yourself."""
    b = base_url.rstrip("/")
    win = (secrets_path if "\\" in secrets_path
           else r"%USERPROFILE%\.warden\bin\palivane-secrets.cmd")
    args = _engine_args(engine)
    args_xml = f"\n      <Arguments>{' '.join(args)}</Arguments>" if args else ""
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T03:00:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
      <Enabled>true</Enabled>
    </CalendarTrigger>
  </Triggers>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions>
    <Exec>
      <Command>{win}</Command>{args_xml}
      <Environment><Variable name="PALIVANE_URL">{b}</Variable></Environment>
    </Exec>
  </Actions>
</Task>
'''


def ca_note() -> str:
    return (
        "Deploy your egress-proxy / corporate root CA to the SYSTEM trust store via MDM so "
        "TLS inspection (and thus MCP + AI-traffic inspection) works:\n"
        "  - macOS: a Certificate payload in a configuration profile (Jamf/Intune).\n"
        "  - Windows: push to 'Trusted Root Certification Authorities' via GPO/Intune.\n"
        "Without the CA, HTTPS bodies can't be inspected and the proxy fails open. "
        "Cert-pinned clients (e.g. Cursor's chat endpoint) bypass inspection regardless."
    )


def render_pack(base_url: str, extension_id: str, proxy_host: str, proxy_port: int,
                allowed_exts: list[str], denied_exts: list[str],
                hook_path: str = "/usr/local/bin/palivane-hook",
                posture_path: str = "/usr/local/bin/palivane-posture",
                cursor_hook_path: str = "/usr/local/bin/palivane-cursor-hook",
                gemini_hook_path: str = "/usr/local/bin/palivane-gemini-hook",
                codex_hook_path: str = "/usr/local/bin/palivane-codex-hook",
                copilot_hook_path: str = "/usr/local/bin/palivane-copilot-hook",
                secrets_path: str = "/usr/local/bin/palivane-secrets",
                secrets_engine: str = "trufflehog",
                ext_update_url: str = "", ext_crx_url: str = "",
                ext_version: str = "0.5.0",
                browser_ext_lockdown: bool = False, browser_ext_blocklist: list[str] | None = None,
                browser_ext_allowlist: list[str] | None = None,
                browser_ext_blocked_hosts: list[str] | None = None,
                route_gateway: bool = False) -> dict[str, str]:
    b = base_url.rstrip("/")
    self_host_ext = bool(ext_update_url.strip())
    readme = (
        "Palivane MDM policy pack — apply these with your MDM (Jamf/Intune/GPO). No Palivane\n"
        "agent is installed; the OS/editor/browser/Claude Code enforce the policy.\n\n"
        f"Palivane backend: {b}\n"
        f"Egress proxy:   {proxy_host or '<set proxy_host>'}:{proxy_port}\n\n"
        "1. vscode-extensions.json  -> push as VS Code machine settings (locks extensions.allowed).\n"
        "2. macos-proxy.mobileconfig / windows-proxy.reg -> system proxy to the Palivane proxy.\n"
        "3. chrome-edge-forcelist.txt -> ExtensionInstallForcelist (force-install the extension).\n"
        "3c. chrome-extension-settings.json -> Chrome/Edge ExtensionSettings: govern THIRD-PARTY\n"
        "    browser extensions (e.g. agentic AI ones like Claude for Chrome that Palivane can't\n"
        "    inspect). Block unsanctioned AI extensions by ID, and/or keep permitted ones off\n"
        "    sensitive origins via runtime_blocked_hosts. Edit the placeholders with your IDs.\n"
        + ("   Points at the Chrome Web Store (extension must be published there; Unlisted is fine).\n"
           if not self_host_ext else
           "   Points at your SELF-HOSTED updates.xml — no Web Store submission needed (managed\n"
           "   devices only). Host extension-updates.xml + the signed .crx and set their URLs.\n"
           "3b. extension-updates.xml -> the self-hosted update manifest for the forcelist above.\n")
        + "4. ca-note.txt -> deploy your root CA to the system trust store (required for TLS inspection).\n"
        "5. claude-managed-settings.json -> Claude Code managed-settings.json (the local-plane\n"
        + ("   hooks + gateway routing: prompts bill the org's provider key via ANTHROPIC_BASE_URL).\n"
           if route_gateway else
           "   hooks; Claude Code keeps its own sign-in — forceLoginMethod locks login to\n"
           "   claude.ai Pro/Max subscriptions. Re-generate with route_gateway for gateway billing.\n")
        + "   Deploy palivane-hook/palivane-posture to the paths it references\n"
        f"   ({hook_path}, {posture_path})"
        + (" and replace the ak_ placeholder with each dev's key\n"
           "   (or use apiKeyHelper)" if route_gateway else "")
        + ". Set PALIVANE_ENFORCE=true in env to block locally; default monitors.\n"
        "   Paths: macOS /Library/Application Support/ClaudeCode/, Linux /etc/claude-code/,\n"
        "   Windows C:\\Program Files\\ClaudeCode\\.\n"
        "6. openai.env -> environment variables that route OpenAI SDK/CLI clients through the\n"
        "   gateway (OPENAI_BASE_URL). Push as machine/user env via MDM; agentless, no CA needed.\n"
        "6b. codex-hooks.json + codex.txt -> Codex CLI local hooks (palivane-codex-hook — prompt +\n"
        "   tool-call inspection; covers ChatGPT-subscription auth, which ignores OPENAI_BASE_URL).\n"
        f"   Deploy the hook to {codex_hook_path}; see codex.txt for managed-hooks distribution.\n"
        "6c. copilot-hooks.json + copilot.txt -> GitHub Copilot hooks (palivane-copilot-hook —\n"
        "   deniable tool-call inspection; prompts observe-only at this plane). One file covers\n"
        "   Copilot CLI (~/.copilot/hooks/), and — committed as .github/hooks/palivane.json —\n"
        f"   VS Code agent mode + the cloud coding agent. Deploy the hook to {copilot_hook_path}.\n"
        "7. gemini.txt + gemini-settings.json -> Gemini CLI local hooks (palivane-gemini-hook —\n"
        "   prompt + tool-call inspection in every auth mode; deploy the hook to\n"
        f"   {gemini_hook_path}) and SDK routing notes. The system proxy above covers\n"
        "   Gemini SDK/API clients the hooks don't.\n"
        "8. cursor-hooks.json -> Cursor hooks.json registering palivane-cursor-hook (local,\n"
        "   pinning-proof). Deploy palivane-cursor-hook to the path it references\n"
        f"   ({cursor_hook_path}); push to Cursor's enterprise hooks path or ~/.cursor/hooks.json.\n"
        "   See cursor.txt for the full Cursor story (chat pins its cert; hooks close the gap).\n"
        "9. palivane-secrets.plist / .cron / -task.xml -> schedule the endpoint credential scan\n"
        f"   (palivane-secrets at {secrets_path}"
        + (f" --engine {secrets_engine}" if secrets_engine in ("trufflehog", "gitleaks") else "")
        + ") daily via launchd (macOS) / cron (Linux) /\n"
        "   Task Scheduler (Windows). Finds SSH/RSA keys, tokens, and .env secrets at rest\n"
        f"   before an infostealer does; reports metadata only. With --engine, drives\n"
        f"   {secrets_engine or 'the built-in scan'} (falls back to built-in if not installed).\n\n"
        "Coverage: browser UIs (claude.ai / chatgpt.com / gemini.google.com) via the extension;\n"
        "OpenAI + Gemini + Anthropic API clients via the system proxy (needs the CA); explicit\n"
        "gateway redirect for Claude Code (item 5) and OpenAI SDKs (item 6); Codex CLI (item 6b),\n"
        "GitHub Copilot (item 6c), Gemini CLI (item 7), and Cursor (item 8) via local hooks —\n"
        "prompts + tool calls in every auth mode, despite cert pinning; and credential-at-rest\n"
        "hygiene (item 9).\n"
    )
    artifacts = {
        "README.txt": readme,
        "vscode-extensions.json": vscode_extension_policy(allowed_exts, denied_exts),
        "macos-proxy.mobileconfig": macos_proxy_profile(proxy_host or "proxy.example.com", proxy_port),
        "windows-proxy.reg": windows_proxy_reg(proxy_host or "proxy.example.com", proxy_port),
        "chrome-edge-forcelist.txt": chrome_forcelist(extension_id, ext_update_url),
        "chrome-extension-settings.json": browser_extension_policy(
            extension_id, ext_update_url, browser_ext_lockdown, browser_ext_blocklist,
            browser_ext_allowlist, browser_ext_blocked_hosts),
        "claude-managed-settings.json": claude_managed_settings(b, hook_path, posture_path,
                                                                route_gateway=route_gateway),
        "openai.env": openai_env(b),
        "codex-hooks.json": codex_hooks(codex_hook_path),
        "codex.txt": codex_note(b, codex_hook_path),
        "copilot-hooks.json": copilot_hooks(copilot_hook_path),
        "copilot.txt": copilot_note(b, copilot_hook_path),
        "gemini.txt": gemini_config(b, gemini_hook_path),
        "gemini-settings.json": gemini_settings(gemini_hook_path),
        "cursor-hooks.json": cursor_hooks(cursor_hook_path),
        "cursor.txt": cursor_note(b, cursor_hook_path),
        "palivane-secrets.plist": secrets_launchd(b, secrets_path, secrets_engine),
        "palivane-secrets.cron": secrets_cron(b, secrets_path, secrets_engine),
        "palivane-secrets-task.xml": secrets_win_task(b, secrets_path, secrets_engine),
        "ca-note.txt": ca_note(),
    }
    # Self-hosted extension path (no Web Store): ship the update manifest to host next to the CRX.
    if self_host_ext:
        artifacts["extension-updates.xml"] = extension_updates_xml(extension_id, ext_crx_url, ext_version)
    return artifacts
