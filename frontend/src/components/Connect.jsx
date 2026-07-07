import { useState } from "react";
import { api } from "../api.js";

function Block({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="code-block">
      <button className="copy-btn" onClick={() => {
        navigator.clipboard?.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200);
      }}>{copied ? "copied" : "copy"}</button>
      <pre>{text}</pre>
    </div>
  );
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

export default function Connect({ tenant }) {
  const [key, setKey] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [provBusy, setProvBusy] = useState("");
  const [proxyHost, setProxyHost] = useState("");
  const [packBusy, setPackBusy] = useState(false);
  const origin = window.location.origin;

  async function getPolicyPack() {
    setPackBusy(true); setErr(null);
    try {
      const res = await api.policyPack({ base_url: origin, proxy_host: proxyHost });
      Object.entries(res.artifacts).forEach(([name, content]) => download(name, content));
    } catch (e) { setErr(String(e.message || e)); }
    finally { setPackBusy(false); }
  }

  async function mint() {
    setBusy(true); setErr(null);
    try {
      const res = await api.createApiKey({ label: `capture (${tenant?.slug || "org"})`, actor: "" });
      setKey(res.token);
    } catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  }

  // Mint a key + download a prefilled per-OS device installer.
  async function getInstaller(platform) {
    setProvBusy(platform); setErr(null);
    try {
      const res = await api.provision({ platform, base_url: origin, actor: "" });
      const ext = platform === "windows" ? "ps1" : "sh";
      download(`warden-install-${platform}.${ext}`, res.scripts[platform]);
    } catch (e) { setErr(String(e.message || e)); }
    finally { setProvBusy(""); }
  }

  const K = key || "ak_<generate a key above>";

  const extPolicy = JSON.stringify({
    backendUrl: { Value: origin },
    token: { Value: K },
    enforce: { Value: true },
  }, null, 2);

  const claudeCode = JSON.stringify({
    env: { ANTHROPIC_BASE_URL: `${origin}/v1`, ANTHROPIC_AUTH_TOKEN: K },
  }, null, 2);

  const proxyCmd =
    `WARDEN_URL=${origin} WARDEN_TOKEN=${K} WARDEN_PROXY_ENFORCE=true \\\n` +
    `  mitmdump -s proxy/warden_addon.py --listen-port 8081`;

  const hooksSettings = JSON.stringify({
    env: { WARDEN_URL: origin, WARDEN_TOKEN: K },
    hooks: {
      PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "/usr/local/bin/warden-hook", timeout: 10 }] }],
      SessionStart: [{ matcher: "*", hooks: [{ type: "command", command: "/usr/local/bin/warden-posture --async --quiet" }] }],
    },
  }, null, 2);

  const mcpWrap = JSON.stringify({
    mcpServers: { github: { command: "warden-mcp", args: ["--", "npx", "-y", "@modelcontextprotocol/server-github"] } },
  }, null, 2);

  return (
    <div className="connect">
      <div className="connect-head">
        <h2>Connect sources</h2>
        <button className="primary-btn slim" onClick={mint} disabled={busy}>
          {busy ? "…" : key ? "Generate another key" : "Generate a capture key"}
        </button>
      </div>
      {err && <div className="error">{err}</div>}
      {key && <p className="key-note">Capture key (shown once — copy it now):<br/><code>{key}</code></p>}
      <p className="muted">Each source authenticates with this org's key and routes findings here
        (<code>{origin}</code>). Push the config below via your MDM, or paste it during setup.</p>

      <div className="connect-card">
        <h3>① Browser (claude.ai, ChatGPT, Gemini)</h3>
        <p className="muted">Install the Warden extension, then push this managed-config policy
           (Chrome/Edge enterprise → 3rdparty/extensions/&lt;id&gt;/policy). For a pilot, set the
           same values in the extension's Options.</p>
        <Block text={extPolicy} />
      </div>

      <div className="connect-card">
        <h3>② Claude Code / Anthropic & OpenAI clients</h3>
        <p className="muted">Push as Claude Code <code>managed-settings.json</code> (Linux
           <code>/etc/claude-code/</code>, macOS <code>/Library/Application Support/ClaudeCode/</code>).</p>
        <Block text={claudeCode} />
        <p className="muted" style={{ marginTop: 10 }}>Or self-serve (BYOD / pilots) — the user
           runs <code>warden-connect {origin}</code> to sign in and configure their own Claude
           Code. No token distribution.</p>
      </div>

      <div className="connect-card">
        <h3>③ Desktop apps / network (egress proxy)</h3>
        <p className="muted">Run the proxy near your egress and route managed devices through it
           (system proxy + corporate CA via MDM).</p>
        <Block text={proxyCmd} />
      </div>

      <div className="connect-card">
        <h3>④ Claude Code tool calls &amp; local MCP servers (hooks)</h3>
        <p className="muted">What the network planes can't see: the agent's <em>local</em> actions —
           shell commands, file access, stdio MCP servers — inspected before execution. Merge into
           <code> ~/.claude/settings.json</code> or the managed settings above (deploy
           <code> warden-hook</code>/<code>warden-posture</code> from <code>cli/</code> to a fixed
           path first). Monitor by default; <code>WARDEN_ENFORCE=true</code> blocks.</p>
        <Block text={hooksSettings} />
        <p className="muted" style={{ marginTop: 10 }}>Wrap any stdio MCP server with
           <code> warden-mcp</code> for inline inspection (<code>WARDEN_MCP_ENFORCE=true</code> blocks):</p>
        <Block text={mcpWrap} />
        <p className="muted" style={{ marginTop: 8 }}>Self-serve: <code>warden-connect {origin}</code> installs
           the hooks automatically alongside the gateway routing.</p>
      </div>

      <div className="connect-card">
        <h3>⑤ One-run device installer</h3>
        <p className="muted">Download a prefilled setup script (carries a reusable enrollment
           token) — run it on any number of devices; each self-enrolls for its own per-device
           key, then configures Claude Code + the browser extension policy. Hand to a user or
           push via MDM.</p>
        <div className="form-row" style={{ gap: 10 }}>
          <button className="primary-btn slim" disabled={!!provBusy}
                  onClick={() => getInstaller("macos")}>
            {provBusy === "macos" ? "…" : "Download macOS installer (.sh)"}
          </button>
          <button className="primary-btn slim" disabled={!!provBusy}
                  onClick={() => getInstaller("windows")}>
            {provBusy === "windows" ? "…" : "Download Windows installer (.ps1)"}
          </button>
        </div>
        <p className="muted" style={{ marginTop: 8 }}>Each download mints a new enrollment token —
           treat the file as a secret; revoke it anytime under enrollment tokens.</p>
      </div>

      <div className="connect-card">
        <h3>⑥ MDM policy pack (agentless enforcement)</h3>
        <p className="muted">Download the config your MDM (Jamf / Intune / GPO) pushes to enforce
           policy with no Warden agent: VS Code extension allowlist, system-proxy profiles
           (macOS/Windows), browser force-install, a CA note, and the Claude Code
           <code>managed-settings.json</code> (gateway routing + the Route C hooks). Uses this org's
           approved-extension lists. See <code>docs/mdm-policy-pack.md</code>.</p>
        <div className="form-row" style={{ gap: 10 }}>
          <input placeholder="egress proxy host (e.g. proxy.corp.com)"
                 value={proxyHost} onChange={(e) => setProxyHost(e.target.value)} />
          <button className="primary-btn slim" disabled={packBusy} onClick={getPolicyPack}>
            {packBusy ? "…" : "Download policy pack"}
          </button>
        </div>
      </div>
    </div>
  );
}
