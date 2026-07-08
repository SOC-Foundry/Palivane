"""MDM policy-pack generator — agentless enforcement config.

Produces the config artifacts an organization's **MDM** pushes to managed devices so the
*enforcement* side of Warden is handled without any Warden agent on the box:

- **VS Code extension allowlist** (`extensions.allowed`) — lets only approved extensions
  install and blocks known-bad ones (the enforcement counterpart to /api/scan/ide-extensions);
- **system proxy** (macOS `.mobileconfig`, Windows `.reg`) — routes egress through the
  Warden proxy so MCP/AI traffic is inspected;
- **browser extension force-install** (Chrome/Edge `ExtensionInstallForcelist`);
- a **CA deployment note** — the corporate/egress-proxy root CA must be trusted for TLS
  inspection (the cert itself is the org's; we only say where it goes).

Everything here is applied by the customer's MDM (Jamf/Intune/GPO), not by a Warden
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
  <key>PayloadIdentifier</key><string>net.tachtech.warden.proxy</string>
  <key>PayloadDisplayName</key><string>Warden egress proxy</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.proxy.http.global</string>
      <key>PayloadIdentifier</key><string>net.tachtech.warden.proxy.http</string>
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
    """ExtensionInstallForcelist value for Chrome/Edge (force-install the Warden extension).

    Default pulls from the Chrome Web Store (the extension must be published there —
    Unlisted is fine). Pass a self-hosted `update_url` (your updates.xml) to force-install
    a self-hosted CRX with no Web Store submission — managed devices only."""
    eid = extension_id or "REPLACE_WITH_PUBLISHED_EXTENSION_ID"
    return f"{eid};{update_url.strip() or _WEBSTORE_UPDATE_URL}"


def browser_extension_policy(warden_id: str, warden_update_url: str = "", lockdown: bool = False,
                             blocked_ids: list[str] | None = None, allowed_ids: list[str] | None = None,
                             blocked_hosts: list[str] | None = None) -> str:
    """Chrome/Edge `ExtensionSettings` policy — govern *third-party* browser extensions,
    including agentic AI ones (e.g. Claude for Chrome) that Warden's own extension can't
    inspect (Chrome sandboxes extensions from each other). Two stances:

    - default (governed): everything `allowed`, but a denylist of AI extensions is `blocked`
      and permitted extensions are kept off sensitive origins via `runtime_blocked_hosts`.
    - lockdown: default `blocked`; only the allowlist (+ Warden's own) may install.

    Warden's own extension is always force-installed. Applied by MDM (Chrome/Edge enterprise)."""
    blocked_ids = blocked_ids or []
    allowed_ids = allowed_ids or []
    blocked_hosts = blocked_hosts or []

    default: dict = {"installation_mode": "blocked" if lockdown else "allowed"}
    if blocked_hosts:                       # keep ALL extensions off these origins
        default["runtime_blocked_hosts"] = blocked_hosts
    settings: dict = {"*": default}

    settings[warden_id or "REPLACE_WITH_WARDEN_EXTENSION_ID"] = {
        "installation_mode": "force_installed",
        "update_url": (warden_update_url.strip() or _WEBSTORE_UPDATE_URL)}
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
    <updatecheck codebase="{crx_url or 'https://your.host/warden-extension.crx'}" version="{version}" />
  </app>
</gupdate>
'''


def claude_managed_settings(base_url: str, hook_path: str, posture_path: str) -> str:
    """Claude Code enterprise `managed-settings.json` — routes prompts through the Warden
    gateway AND installs the local planes (Route C) fleet-wide: a PreToolUse hook
    (warden-hook, pre-execution tool-call inspection) and a SessionStart hook
    (warden-posture, device drift). Managed settings take precedence over user settings.

    The `ak_…` placeholder is one per-developer Warden key; for per-user attribution
    without baking it in, use Claude Code's apiKeyHelper. The two scripts must be deployed
    to `hook_path` / `posture_path` on the device (push via the same MDM)."""
    b = base_url.rstrip("/")
    token = "ak_REPLACE_WITH_PER_USER_WARDEN_KEY"
    return json.dumps({
        "env": {
            "ANTHROPIC_BASE_URL": f"{b}/v1",
            "ANTHROPIC_AUTH_TOKEN": token,
            "WARDEN_URL": b,
            "WARDEN_TOKEN": token,
        },
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [
                {"type": "command", "command": hook_path, "timeout": 10}]}],
            "SessionStart": [{"matcher": "*", "hooks": [
                {"type": "command", "command": f"{posture_path} --async --quiet"}]}],
        },
    }, indent=2)


def openai_env(base_url: str) -> str:
    """Drop-in env for OpenAI SDK / CLI clients — routes them through the Warden gateway's
    OpenAI-compatible endpoint (`/v1/chat/completions`) instead of api.openai.com. Covers
    clients that pin certs or otherwise bypass the egress proxy. `OPENAI_BASE_URL` is the
    current var; `OPENAI_API_BASE` is the legacy name older SDKs still read."""
    b = base_url.rstrip("/")
    return (
        "# Route OpenAI SDK/CLI clients through the Warden gateway (agentless — no proxy CA\n"
        "# needed). Push via MDM as machine/user environment variables. The ak_ value is a\n"
        "# per-user Warden capture key and doubles as the gateway auth token.\n"
        f'OPENAI_BASE_URL="{b}/v1"\n'
        f'OPENAI_API_BASE="{b}/v1"\n'
        'OPENAI_API_KEY="ak_REPLACE_WITH_PER_USER_WARDEN_KEY"\n'
    )


def gemini_config(base_url: str) -> str:
    """Gemini routing note + SDK snippet. Google's google-genai SDK has no universal base-url
    *env var*, so the reliable agentless path for Gemini is the system proxy (this pack's
    proxy profile inspects generativelanguage.googleapis.com). Where a client can be code-
    configured, point it at the gateway's `/v1beta` endpoint as shown."""
    b = base_url.rstrip("/")
    return (
        "Gemini routing\n"
        "==============\n"
        "Gemini's official SDKs don't honor a standard base-URL environment variable, so the\n"
        "primary agentless capture for Gemini is the SYSTEM PROXY in this pack. It inspects the\n"
        "Gemini CLI in all three modes once your root CA is trusted (see ca-note.txt):\n"
        "  - API-key mode  -> generativelanguage.googleapis.com\n"
        "  - OAuth / Code Assist (default 'log in with Google') -> cloudcode-pa.googleapis.com\n"
        "  - Vertex mode   -> aiplatform.googleapis.com\n\n"
        "For clients you can configure in code, point the Python google-genai SDK at the\n"
        "Warden gateway's Gemini-shaped endpoint:\n\n"
        "  from google import genai\n"
        "  from google.genai.types import HttpOptions\n"
        f'  client = genai.Client(\n'
        f'      api_key="ak_REPLACE_WITH_PER_USER_WARDEN_KEY",\n'
        f'      http_options=HttpOptions(base_url="{b}"),  # SDK appends /v1beta/models/...\n'
        "  )\n\n"
        f"Gateway Gemini endpoint: {b}/v1beta/models/{{model}}:generateContent\n"
    )


def cursor_hooks(hook_path: str) -> str:
    """Cursor `hooks.json` registering warden-cursor-hook on the security-relevant agent
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
    """How Warden covers Cursor — and the one thing it can't."""
    b = base_url.rstrip("/")
    return (
        "Cursor coverage\n"
        "===============\n"
        "Cursor's model/chat endpoint (api2.cursor.sh) PINS its certificate, so the egress\n"
        "proxy can't read its prompts, and Cursor ignores OPENAI_BASE_URL, so the gateway\n"
        "can't be interposed. Warden covers Cursor with LOCAL planes instead, which are\n"
        "immune to the pinning:\n\n"
        "1. Cursor hooks (cursor-hooks.json in this pack) — warden-cursor-hook runs inside\n"
        "   Cursor before each action and reports/blocks:\n"
        "     - beforeSubmitPrompt   -> prompt data-loss (secrets/PII/shadow-AI)\n"
        "     - beforeShellExecution -> dangerous commands\n"
        "     - beforeMCPExecution   -> MCP tool calls (server allowlist, tool poisoning)\n"
        "     - beforeReadFile       -> secrets/PII pulled into context\n"
        "     - afterFileEdit        -> secrets/PII written (monitor-only)\n"
        f"   Deploy warden-cursor-hook to {hook_path} and push cursor-hooks.json to Cursor's\n"
        "   enterprise hooks path (or ~/.cursor/hooks.json). Monitor by default; set\n"
        "   WARDEN_ENFORCE=true to block. Provide WARDEN_URL/WARDEN_TOKEN via machine env\n"
        f"   (WARDEN_URL={b}) or ~/.cursor/warden.json.\n"
        "2. MCP servers — wrap Cursor's .cursor/mcp.json stdio servers with warden-mcp for\n"
        "   inline tool inspection (belt-and-suspenders with beforeMCPExecution).\n"
        "3. Git plane — secrets/PII in the code Cursor commits (pre-commit hook + Action).\n"
        "4. Gateway — for any first-party AI your org routes explicitly.\n\n"
        "Optional (pilots): Cursor Settings -> Models -> Override OpenAI Base URL =\n"
        f"  {b}/v1  (key = an ak_ Warden key). This routes Cursor's OpenAI-compatible calls\n"
        "  through the gateway, but disables Agent/Composer/Tab — most orgs prefer the hooks.\n\n"
        "What is NOT captured: nothing, once the hooks are installed — beforeSubmitPrompt\n"
        "sees the prompt locally before it leaves. Without the hooks, Cursor's cloud chat is\n"
        "opaque to the network planes.\n"
    )


def _engine_args(engine: str) -> list[str]:
    """['--engine', 'trufflehog'] when an external scanner is chosen, else []. warden-secrets
    falls back to its built-in regex scan if the tool isn't installed, so this is safe to
    ship fleet-wide even on devices that don't have TruffleHog/Gitleaks."""
    e = (engine or "").strip().lower()
    return ["--engine", e] if e in ("trufflehog", "gitleaks") else []


def secrets_launchd(base_url: str, secrets_path: str, engine: str = "trufflehog") -> str:
    """macOS LaunchAgent — runs warden-secrets daily (3am) as the signed-in user, so it
    can read ~/.ssh etc. and the warden-connect creds. Push to ~/Library/LaunchAgents via MDM."""
    b = base_url.rstrip("/")
    argv = "".join(f"<string>{a}</string>" for a in [secrets_path, *_engine_args(engine)])
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>net.tachtech.warden.secrets</string>
  <key>ProgramArguments</key>
  <array>{argv}</array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>3</integer><key>Minute</key><integer>0</integer></dict>
  <key>EnvironmentVariables</key>
  <dict><key>WARDEN_URL</key><string>{b}</string></dict>
  <key>StandardErrorPath</key><string>/tmp/warden-secrets.log</string>
</dict>
</plist>
'''


def secrets_cron(base_url: str, secrets_path: str, engine: str = "trufflehog") -> str:
    """Linux cron fragment (drop in /etc/cron.d/ or a user crontab) — daily at 03:00.
    WARDEN_TOKEN comes from the warden-connect creds file the scanner reads, or set it here."""
    b = base_url.rstrip("/")
    cmd = " ".join([secrets_path, *_engine_args(engine)])
    return (f"# Warden endpoint credential scan — daily. Runs as the target user so it can\n"
            f"# read ~/.ssh etc. Token resolves from ~/.claude/settings.json / ~/.cursor/warden.json.\n"
            f"WARDEN_URL={b}\n"
            f"0 3 * * * {os.getenv('USER', '<user>')} {cmd}\n")


def secrets_win_task(base_url: str, secrets_path: str, engine: str = "trufflehog") -> str:
    """Windows Task Scheduler XML — daily at 03:00. Import with schtasks /create /xml."""
    b = base_url.rstrip("/")
    win = secrets_path if "\\" in secrets_path else r"C:\Program Files\Warden\warden-secrets.exe"
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
      <Environment><Variable name="WARDEN_URL">{b}</Variable></Environment>
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
                hook_path: str = "/usr/local/bin/warden-hook",
                posture_path: str = "/usr/local/bin/warden-posture",
                cursor_hook_path: str = "/usr/local/bin/warden-cursor-hook",
                secrets_path: str = "/usr/local/bin/warden-secrets",
                secrets_engine: str = "trufflehog",
                ext_update_url: str = "", ext_crx_url: str = "",
                ext_version: str = "0.5.0",
                browser_ext_lockdown: bool = False, browser_ext_blocklist: list[str] | None = None,
                browser_ext_allowlist: list[str] | None = None,
                browser_ext_blocked_hosts: list[str] | None = None) -> dict[str, str]:
    b = base_url.rstrip("/")
    self_host_ext = bool(ext_update_url.strip())
    readme = (
        "Warden MDM policy pack — apply these with your MDM (Jamf/Intune/GPO). No Warden\n"
        "agent is installed; the OS/editor/browser/Claude Code enforce the policy.\n\n"
        f"Warden backend: {b}\n"
        f"Egress proxy:   {proxy_host or '<set proxy_host>'}:{proxy_port}\n\n"
        "1. vscode-extensions.json  -> push as VS Code machine settings (locks extensions.allowed).\n"
        "2. macos-proxy.mobileconfig / windows-proxy.reg -> system proxy to the Warden proxy.\n"
        "3. chrome-edge-forcelist.txt -> ExtensionInstallForcelist (force-install the extension).\n"
        "3c. chrome-extension-settings.json -> Chrome/Edge ExtensionSettings: govern THIRD-PARTY\n"
        "    browser extensions (e.g. agentic AI ones like Claude for Chrome that Warden can't\n"
        "    inspect). Block unsanctioned AI extensions by ID, and/or keep permitted ones off\n"
        "    sensitive origins via runtime_blocked_hosts. Edit the placeholders with your IDs.\n"
        + ("   Points at the Chrome Web Store (extension must be published there; Unlisted is fine).\n"
           if not self_host_ext else
           "   Points at your SELF-HOSTED updates.xml — no Web Store submission needed (managed\n"
           "   devices only). Host extension-updates.xml + the signed .crx and set their URLs.\n"
           "3b. extension-updates.xml -> the self-hosted update manifest for the forcelist above.\n")
        + "4. ca-note.txt -> deploy your root CA to the system trust store (required for TLS inspection).\n"
        "5. claude-managed-settings.json -> Claude Code managed-settings.json (gateway routing +\n"
        "   the local-plane hooks). Deploy warden-hook/warden-posture to the paths it references\n"
        f"   ({hook_path}, {posture_path}) and replace the ak_ placeholder with each dev's key\n"
        "   (or use apiKeyHelper). Set WARDEN_ENFORCE=true in env to block locally; default monitors.\n"
        "   Paths: macOS /Library/Application Support/ClaudeCode/, Linux /etc/claude-code/,\n"
        "   Windows C:\\Program Files\\ClaudeCode\\.\n"
        "6. openai.env -> environment variables that route OpenAI SDK/CLI clients through the\n"
        "   gateway (OPENAI_BASE_URL). Push as machine/user env via MDM; agentless, no CA needed.\n"
        "7. gemini.txt -> Gemini routing (SDK snippet + note). Gemini has no base-URL env var,\n"
        "   so the system proxy above is its primary agentless capture path.\n"
        "8. cursor-hooks.json -> Cursor hooks.json registering warden-cursor-hook (local,\n"
        "   pinning-proof). Deploy warden-cursor-hook to the path it references\n"
        f"   ({cursor_hook_path}); push to Cursor's enterprise hooks path or ~/.cursor/hooks.json.\n"
        "   See cursor.txt for the full Cursor story (chat pins its cert; hooks close the gap).\n"
        "9. warden-secrets.plist / .cron / -task.xml -> schedule the endpoint credential scan\n"
        f"   (warden-secrets at {secrets_path}"
        + (f" --engine {secrets_engine}" if secrets_engine in ("trufflehog", "gitleaks") else "")
        + ") daily via launchd (macOS) / cron (Linux) /\n"
        "   Task Scheduler (Windows). Finds SSH/RSA keys, tokens, and .env secrets at rest\n"
        f"   before an infostealer does; reports metadata only. With --engine, drives\n"
        f"   {secrets_engine or 'the built-in scan'} (falls back to built-in if not installed).\n\n"
        "Coverage: browser UIs (claude.ai / chatgpt.com / gemini.google.com) via the extension;\n"
        "OpenAI + Gemini + Anthropic API clients via the system proxy (needs the CA); explicit\n"
        "gateway redirect for Claude Code (item 5) and OpenAI SDKs (item 6); Cursor via local\n"
        "hooks (item 8) despite its cert pinning; and credential-at-rest hygiene (item 9).\n"
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
        "claude-managed-settings.json": claude_managed_settings(b, hook_path, posture_path),
        "openai.env": openai_env(b),
        "gemini.txt": gemini_config(b),
        "cursor-hooks.json": cursor_hooks(cursor_hook_path),
        "cursor.txt": cursor_note(b, cursor_hook_path),
        "warden-secrets.plist": secrets_launchd(b, secrets_path, secrets_engine),
        "warden-secrets.cron": secrets_cron(b, secrets_path, secrets_engine),
        "warden-secrets-task.xml": secrets_win_task(b, secrets_path, secrets_engine),
        "ca-note.txt": ca_note(),
    }
    # Self-hosted extension path (no Web Store): ship the update manifest to host next to the CRX.
    if self_host_ext:
        artifacts["extension-updates.xml"] = extension_updates_xml(extension_id, ext_crx_url, ext_version)
    return artifacts
