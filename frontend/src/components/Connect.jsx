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

export default function Connect({ tenant }) {
  const [key, setKey] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const origin = window.location.origin;

  async function mint() {
    setBusy(true); setErr(null);
    try {
      const res = await api.createApiKey({ label: `capture (${tenant?.slug || "org"})`, actor: "" });
      setKey(res.token);
    } catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
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
      </div>

      <div className="connect-card">
        <h3>③ Desktop apps / network (egress proxy)</h3>
        <p className="muted">Run the proxy near your egress and route managed devices through it
           (system proxy + corporate CA via MDM).</p>
        <Block text={proxyCmd} />
      </div>
    </div>
  );
}
