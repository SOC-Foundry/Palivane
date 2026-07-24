import { useState, useEffect } from "react";
import { api } from "../api.js";

// Live "is each plane actually reporting?" strip — turns setup from fire-and-hope into
// fire-and-watch. Polls /api/setup-status (findings in the last 24h, per surface).
function Readiness() {
  const [s, setS] = useState(null);
  useEffect(() => {
    let live = true;
    const load = () => api.setupStatus().then((r) => live && setS(r)).catch(() => {});
    load();
    const t = setInterval(load, 15000);
    return () => { live = false; clearInterval(t); };
  }, []);
  if (!s) return null;
  const planes = [
    ["Browser", s.planes.shadow_ai],
    ["Claude Code / gateway", s.planes.gateway],
    ["Agent tool-calls", s.planes.mcp],
    ["Credentials at rest", s.planes.secrets],
  ];
  const noUpstream = s.upstream_forwards && !s.upstream_forwards.anthropic;
  return (
    <div className="readiness">
      {noUpstream && (
        <div className="error" style={{ marginBottom: 8 }}>
          No model provider key set — self-serve connects skip gateway routing (local hooks
          still capture; Claude Code keeps its own account), and manually configured gateway
          clients get a stub reply. An admin can add your org's Anthropic API key under{" "}
          <strong>Settings → Gateway upstreams</strong>, then users re-run{" "}
          <code>warden-connect</code> to enable routing.
        </div>
      )}
      <span className="muted">Reporting (last 24h):</span>
      {planes.map(([label, n]) => (
        <span key={label} className={`plane-pill ${n > 0 ? "on" : "off"}`}>
          <span className="dot" /> {label}{n > 0 ? ` · ${n}` : " · waiting"}
        </span>
      ))}
    </div>
  );
}

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
  // Bound the enrollment token baked into the installer — it's a reusable secret in a file.
  const [expiresInDays, setExpiresInDays] = useState("30"); // blank = never (not recommended)
  const [maxUses, setMaxUses] = useState("");               // blank = unlimited within window
  // Off by default: Claude Code keeps its own sign-in (Pro/Max). On = route prompts
  // through the Warden gateway and bill the org's provider key.
  const [routeGateway, setRouteGateway] = useState(false);
  const origin = window.location.origin;
  // Device installers are free (device_setup); only the MDM policy pack is gated on "mdm".
  const hasMdm = (tenant?.plan_features || []).includes("mdm");

  async function getPolicyPack() {
    setPackBusy(true); setErr(null);
    try {
      const res = await api.policyPack({ base_url: origin, proxy_host: proxyHost,
                                         route_gateway: routeGateway });
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
      const days = expiresInDays.trim();
      const uses = maxUses.trim();
      const res = await api.provision({
        platform, base_url: origin, actor: "",
        expires_in_days: days === "" ? null : Number(days),
        max_uses: uses === "" ? null : Number(uses),
        route_gateway: routeGateway,
      });
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

  const installCli = `curl -fsSL ${origin}/install.sh | bash`;
  const installDesktop = `curl -fsSL ${origin}/install.sh | bash -s -- --desktop`;

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

  const otelCmd =
    `WARDEN_URL=${origin} WARDEN_TOKEN=${K} \\\n` +
    `  warden-otel            # sidecar next to the claude-otel collector (--once for cron)`;

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

      <div className="quickstart">
        <h3>⚡ Quick start — cover your whole org in one step</h3>
        <p className="muted">Most orgs don't need the per-source setup below. Pick how you deliver
           software to your fleet — Warden generates everything (browser + Claude Code + agent
           tool-calls) already pointed here and pre-configured with this org's policy.</p>
        <label className="muted" style={{ fontSize: 12, display: "block", margin: "4px 0 8px" }}>
          <input type="checkbox" checked={routeGateway}
                 onChange={(e) => setRouteGateway(e.target.checked)}
                 style={{ marginRight: 6 }} />
          Route Claude Code through the Warden gateway (bills your org's provider key).
          Off = devs keep their own claude.ai sign-in (Pro/Max); hooks still monitor either way.
        </label>
        <div className="qs-paths">
          <div className="qs-path">
            <h4>You hand out a setup script <span className="muted">· free</span></h4>
            <p className="muted">One installer per OS, run on any number of devices. Each
               self-enrolls for its own per-device key, then configures every source.</p>
            <div className="form-row" style={{ gap: 8 }}>
              <button className="primary-btn slim" disabled={!!provBusy}
                      onClick={() => getInstaller("macos")}>
                {provBusy === "macos" ? "…" : "macOS (.sh)"}
              </button>
              <button className="primary-btn slim" disabled={!!provBusy}
                      onClick={() => getInstaller("windows")}>
                {provBusy === "windows" ? "…" : "Windows (.ps1)"}
              </button>
              <button className="primary-btn slim" disabled={!!provBusy}
                      onClick={() => getInstaller("linux")}>
                {provBusy === "linux" ? "…" : "Linux (.sh)"}
              </button>
            </div>
            <div className="form-row" style={{ gap: 8, marginTop: 8, alignItems: "center" }}>
              <label className="muted" style={{ fontSize: 12 }}>Token expires in
                <input type="number" min="1" placeholder="never" value={expiresInDays}
                       onChange={(e) => setExpiresInDays(e.target.value)}
                       style={{ width: 64, margin: "0 4px" }} /> days
              </label>
              <label className="muted" style={{ fontSize: 12 }}>max enrollments
                <input type="number" min="1" placeholder="unlimited" value={maxUses}
                       onChange={(e) => setMaxUses(e.target.value)}
                       style={{ width: 80, marginLeft: 4 }} />
              </label>
            </div>
          </div>
          <div className="qs-path">
            <h4>You use MDM (Jamf · Intune · GPO){!hasMdm && <span className="muted"> · Team plan</span>}</h4>
            <p className="muted">Agentless. One pack your MDM pushes: extension force-install,
               system-proxy profile, and Claude Code managed settings + hooks.</p>
            {!hasMdm && (
              <p className="muted">🔒 The MDM policy pack is a Team plan feature —{" "}
                 <a href="mailto:sales@tachtech.net">contact us</a>. (The setup script on the
                 left covers the same sources and is free.)</p>
            )}
            <div className="form-row" style={{ gap: 8 }}>
              <input placeholder="egress proxy host (optional)" value={proxyHost}
                     onChange={(e) => setProxyHost(e.target.value)} />
              <button className="primary-btn slim" disabled={packBusy || !hasMdm} onClick={getPolicyPack}>
                {packBusy ? "…" : "Download policy pack"}
              </button>
            </div>
          </div>
        </div>
        <p className="muted" style={{ marginTop: 4 }}>Each download carries a reusable enrollment
           token — treat the file as a secret; revoke it anytime under enrollment tokens. MDM
           details: <code>docs/mdm-policy-pack.md</code>.</p>
        <Readiness />
      </div>

      <div className="connect-divider">Per-source setup (pilots &amp; manual)</div>

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
           runs <code>warden-connect {origin}</code> to sign in and wire up the local hooks;
           Claude Code keeps its own sign-in (Pro/Max subscription or API account). Add
           <code> --route-gateway</code> to also reroute API traffic through the gateway.
           No token distribution.</p>
        <p className="muted" style={{ marginTop: 8 }}>Gateway-routed clients forward with your
           org's own provider account (API credits, not personal Pro/Max plans) — add your
           Anthropic API key under
           <strong> Settings → Gateway upstreams</strong> or they'll get a stub reply.</p>
      </div>

      <div className="connect-card">
        <h3>③ Desktop apps / CLIs / network (egress proxy)</h3>
        <p className="muted">One-line installer — no clone required. Defaults to <strong>CLI
           governance</strong>: per-tool shims route the AI CLIs (Claude Code, Codex, Gemini)
           through the proxy, <em>no sudo</em>. The right fit for small orgs without MDM; the
           user signs in via browser (<code>warden connect</code>), no token to distribute.</p>
        <Block text={installCli} />
        <p className="muted" style={{ marginTop: 10 }}>Add <code>--desktop</code> to also govern the
           Claude/ChatGPT <strong>desktop apps</strong> and browsers system-wide (system proxy + CA
           trust; asks for sudo). Superset of the default — includes the CLI shims.</p>
        <Block text={installDesktop} />
        <p className="muted" style={{ marginTop: 10 }}>Fleets: push the system proxy + corporate CA
           via MDM (the policy pack above), or run the addon directly near your egress:</p>
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
           the hooks automatically (add <code>--route-gateway</code> for gateway routing).</p>
      </div>

      <div className="connect-card">
        <h3>⑤ claude-otel telemetry bridge (optional)</h3>
        <p className="muted">Already running <code>claude-otel</code>? <code>warden-otel</code> tails its
           OTEL log and forwards Claude Code's prompts and tool calls to Warden — a capture plane with
           <em> no proxy, CA, or hook</em>. Monitor-only (telemetry is post-hoc, so it observes but can't
           block); depth follows the claude-otel privacy profile.</p>
        <Block text={otelCmd} />
      </div>
    </div>
  );
}
