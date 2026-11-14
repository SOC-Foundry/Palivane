import { useState, useEffect, useRef } from "react";
import { api } from "../api.js";

// Connect: get every capture plane pointed at this org. The quick start (one installer per
// OS, or one MDM pack) covers most orgs; below it, one tile per source with what it covers
// and whether it is reporting. A tile opens its own setup underneath the grid, one at a
// time, so the page is a screen tall instead of four.

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

// Live "is each plane reporting?", polled from /api/setup-status (findings in the last 24h,
// per surface), so setup is fire-and-watch rather than fire-and-hope.
function useSetupStatus() {
  const [s, setS] = useState(null);
  useEffect(() => {
    let live = true;
    const load = () => api.setupStatus().then((r) => live && setS(r)).catch(() => {});
    load();
    const t = setInterval(load, 60000);
    return () => { live = false; clearInterval(t); };
  }, []);
  return s;
}

function StatusDot({ n }) {
  if (n == null) return null;
  return (
    <span className={`src-status ${n > 0 ? "on" : "off"}`} title="Findings from this source in the last 24 hours">
      <span className="dot" />{n > 0 ? `${n} in 24h` : "waiting"}
    </span>
  );
}

// The canary self-test: is anything reaching the console? One command on a laptop, or one
// paste into an AI site, raises a finding the engine recognises as the org's own test secret.
// Reviewed on arrival, so it proves the path without leaving work in the queue.
function SelfTest() {
  const [s, setS] = useState(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    let live = true;
    const load = () => api.selftest().then((r) => live && setS(r)).catch((e) => live && setErr(String(e.message || e)));
    load();
    const t = setInterval(load, 15000);
    return () => { live = false; clearInterval(t); };
  }, []);
  const ago = (iso) => {
    if (!iso) return "";
    const m = Math.round((Date.now() - new Date(iso + (iso.endsWith("Z") ? "" : "Z")).getTime()) / 60000);
    return m < 1 ? "just now" : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`;
  };
  return (
    <div className="panel quickstart">
      <div className="qs-head">
        <h2>Self-test: prove the path</h2>
      </div>
      <p className="muted" style={{ marginTop: 4 }}>
        On any installed laptop, run <code>palivane-hook selftest</code>. It sends the org's own
        test secret through the real capture path and prints the verdict; the finding lands here
        already reviewed, so nothing is left to triage.
        {s?.canary && <> To test the browser extension or the proxy, paste this into any AI
          tool instead: <code>{s.canary}</code></>}
      </p>
      {err && <p className="mine-err">{err}</p>}
      {s && (
        s.count === 0 ? (
          <p className="muted">No canary has arrived yet{s.first_key_at ? ` (first capture key minted ${ago(s.first_key_at)})` : ""}.</p>
        ) : (
          <p>
            <strong>{s.count}</strong> self-test{s.count === 1 ? "" : "s"} recorded. Last seen{" "}
            <strong>{ago(s.last.at)}</strong> from {s.last.sender || "an unnamed device"} via {s.last.channel || s.last.surface}
            {" "}({s.last.severity}{s.last.action ? `, ${s.last.action}` : ""}).
            {s.minutes_to_first_finding != null && <> First finding arrived{" "}
              <strong>{s.minutes_to_first_finding < 1 ? "under a minute" : `${s.minutes_to_first_finding} minutes`}</strong>{" "}
              after the first capture key was minted.</>}
          </p>
        )
      )}
    </div>
  );
}

export default function Connect({ tenant, onNavigate }) {
  const [key, setKey] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [provBusy, setProvBusy] = useState("");
  const [proxyHost, setProxyHost] = useState("");
  const [packBusy, setPackBusy] = useState(false);
  // Bound the enrollment token baked into the installer, it's a reusable secret in a file.
  const [expiresInDays, setExpiresInDays] = useState("30"); // blank = never (not recommended)
  const [maxUses, setMaxUses] = useState("");               // blank = unlimited within window
  // Off by default: Claude Code keeps its own sign-in (Pro/Max). On = route prompts
  // through the Palivane gateway and bill the org's provider key.
  const [routeGateway, setRouteGateway] = useState(false);
  const [openTile, setOpenTile] = useState(null);
  const status = useSetupStatus();
  const origin = window.location.origin;
  // Device installers are free (device_setup); only the MDM policy pack is gated on "mdm".
  const hasMdm = (tenant?.plan_features || []).includes("mdm");
  const planes = status?.planes || {};
  const noUpstream = status?.upstream_forwards && !status.upstream_forwards.anthropic;
  const go = (view, section) => (e) => {
    if (!onNavigate) return;
    e.preventDefault();
    onNavigate(view, null, { section });
  };

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
      download(`palivane-install-${platform}.${ext}`, res.scripts[platform]);
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
    `PALIVANE_URL=${origin} PALIVANE_TOKEN=${K} PALIVANE_PROXY_ENFORCE=true \\\n` +
    `  mitmdump -s proxy/palivane_addon.py --listen-port 8081`;

  const hooksSettings = JSON.stringify({
    env: { PALIVANE_URL: origin, PALIVANE_TOKEN: K },
    hooks: {
      PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "/usr/local/bin/palivane-hook", timeout: 10 }] }],
      SessionStart: [{ matcher: "*", hooks: [{ type: "command", command: "/usr/local/bin/palivane-posture --async --quiet" }] }],
    },
  }, null, 2);

  const mcpWrap = JSON.stringify({
    mcpServers: { github: { command: "palivane-mcp", args: ["--", "npx", "-y", "@modelcontextprotocol/server-github"] } },
  }, null, 2);

  const otelCmd =
    `PALIVANE_URL=${origin} PALIVANE_TOKEN=${K} \\\n` +
    `  palivane-otel            # sidecar next to the claude-otel collector (--once for cron)`;

  const mcpAdd = `claude mcp add --transport http palivane ${origin}/api/mcp/`;

  const TILES = [
    { id: "coding", name: "AI coding tools", covers: "Claude Code, Cursor, Codex, Gemini CLI, Copilot: prompts and tool calls, before they run",
      n: planes.mcp, detail: (
        <>
          <p className="muted">Self-serve (BYOD, pilots): each developer runs this and signs in. It wires the
             hooks into every coding tool present, with no token to distribute.</p>
          <Block text={`palivane-connect ${origin}`} />
          <p className="muted">Fleets: merge into <code>~/.claude/settings.json</code> or the managed settings
             (deploy <code>palivane-hook</code> and <code>palivane-posture</code> to a fixed path first).
             Monitor by default; <code>PALIVANE_ENFORCE=true</code> blocks.</p>
          <Block text={hooksSettings} />
          <p className="muted">Wrap a local stdio MCP server with <code>palivane-mcp</code> for inline
             inspection (<code>PALIVANE_MCP_ENFORCE=true</code> blocks):</p>
          <Block text={mcpWrap} />
        </>
      ) },
    { id: "browser", name: "Browser extension", covers: "claude.ai, ChatGPT, Gemini, Copilot web: checked before the prompt is sent",
      n: planes.shadow_ai, detail: (
        <>
          <p className="muted">Install the Palivane extension from the Chrome Web Store (Chrome and Edge),
             then push this managed-config policy (Chrome/Edge enterprise → 3rdparty/extensions/&lt;id&gt;/policy).
             For a pilot, set the same values in the extension's Options, or click Sign in to Palivane in its popup.</p>
          <Block text={extPolicy} />
        </>
      ) },
    // No status dot: the proxy and the extension report on the same surface, so a count here
    // would repeat the browser's.
    { id: "desktop", name: "Desktop apps & CLIs", covers: "Claude and ChatGPT desktop, AI sidebar extensions, IDE assistants: a local proxy",
      detail: (
        <>
          <p className="muted">One line, no sudo: per-tool shims route the AI CLIs through the proxy.
             The user signs in in the browser; no token to distribute.</p>
          <Block text={installCli} />
          <p className="muted">Add <code>--desktop</code> to also cover the desktop apps and browsers
             system-wide (system proxy and CA trust; asks for sudo).</p>
          <Block text={installDesktop} />
          <p className="muted">Fleets: push the system proxy and CA with the MDM pack, or run the addon
             near your egress:</p>
          <Block text={proxyCmd} />
        </>
      ) },
    { id: "gateway", name: "LLM gateway", covers: "Your own apps and SDKs (OpenAI, Anthropic, Gemini): a base-URL change, scored inline",
      n: planes.gateway, detail: (
        <>
          <p className="muted">Point a client at Palivane instead of the provider. For Claude Code, push as
             <code> managed-settings.json</code> (Linux <code>/etc/claude-code/</code>, macOS
             <code> /Library/Application Support/ClaudeCode/</code>):</p>
          <Block text={claudeCode} />
          <p className="muted">Gateway traffic is forwarded with your org's own provider key (API credits,
             not personal Pro/Max plans). Set it under{" "}
             <a href="/app/settings/gateway" onClick={go("settings", "gateway")}>Settings → Gateway &amp; keys</a>,
             or gateway clients get a stub reply.</p>
        </>
      ) },
    { id: "saas", name: "Slack, GitHub & SaaS", covers: "Slack (one click), GitHub, Teams, email, Drive and SharePoint: read-only connectors",
      detail: (
        <p className="muted">Connectors are set up under{" "}
          <a href="/app/settings/integrations" onClick={go("settings", "integrations")}>Settings → Alerts &amp; integrations</a>:
          Slack (Add to Slack, real-time, optional notify / delete / alert channel), GitHub secret scanning, and
          the rest. Nothing is installed on devices.</p>
      ) },
    { id: "claude", name: "Claude Enterprise", covers: "Every Claude product via Anthropic's Inference hooks: nothing on devices",
      detail: (
        <p className="muted">For Claude Enterprise orgs: an Owner points Organization settings → Inference hooks at
          Palivane. Generate the endpoint and secrets under{" "}
          <a href="/app/settings/integrations" onClick={go("settings", "integrations")}>Settings → Alerts &amp; integrations</a>.</p>
      ) },
    { id: "assistant", name: "Your AI assistant", covers: "Ask Claude or any MCP client about findings, and triage from there",
      detail: (
        <>
          <p className="muted">Palivane's console is a hosted MCP server. Add it, approve it in the browser, and
             ask what leaked today or work the queue. It acts as you, with your role's permissions.</p>
          <Block text={mcpAdd} />
        </>
      ) },
    { id: "secrets", name: "Credentials at rest", covers: "Keys sitting on laptops, found where they are; only masked findings leave",
      n: planes.secrets, detail: (
        <p className="muted">Installed and scheduled by the setup script and the MDM pack above
          (<code>palivane-secrets</code>, daily). Buckets, repositories and databases use the at-rest scanners;
          see the docs for S3 and repo scanning.</p>
      ) },
    { id: "otel", name: "claude-otel bridge", covers: "Already running claude-otel? Forward its telemetry: monitor-only, no proxy or hook",
      detail: (
        <>
          <p className="muted"><code>palivane-otel</code> tails the OTEL log and forwards Claude Code's prompts
             and tool calls. Telemetry is after the fact, so this observes but cannot block.</p>
          <Block text={otelCmd} />
        </>
      ) },
  ];
  const open = TILES.find((t) => t.id === openTile);
  const detailRef = useRef(null);
  // The setup opens below the grid; bring it into view rather than leave it off-screen.
  useEffect(() => {
    if (openTile) detailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [openTile]);

  return (
    <div className="connect connect-v2">
      <div className="content-head">
        <div>
          <h1 className="page-title">Connect</h1>
          <p className="page-sub">Point every source at this org (<code>{origin}</code>). Most orgs only need the quick start.</p>
        </div>
        <div className="head-actions">
          <button className="primary-btn slim" onClick={mint} disabled={busy}>
            {busy ? "..." : key ? "Generate another key" : "Generate a capture key"}
          </button>
        </div>
      </div>
      {err && <div className="error">{err}</div>}
      {key && <p className="key-note">Capture key (shown once, copy it now): <code>{key}</code></p>}

      <div className="panel quickstart">
        <div className="qs-head">
          <h2>Quick start: cover your whole org</h2>
          <label className="qs-option" title="Off: developers keep their own claude.ai sign-in (Pro/Max); the hooks monitor either way.">
            <input type="checkbox" checked={routeGateway} onChange={(e) => setRouteGateway(e.target.checked)} />
            Route Claude Code through the gateway (bills your org's provider key)
          </label>
        </div>
        <div className="qs-paths">
          <div className="qs-path">
            <h4>A setup script <span className="muted">· free</span></h4>
            <p className="muted">One installer per OS, for any number of devices. Each enrolls with its own
               key and configures every source.</p>
            <div className="qs-buttons">
              {[["macos", "macOS"], ["windows", "Windows"], ["linux", "Linux"]].map(([p, label]) => (
                <button key={p} className="primary-btn slim" disabled={!!provBusy} onClick={() => getInstaller(p)}>
                  {provBusy === p ? "..." : label}
                </button>
              ))}
            </div>
            <div className="qs-token">
              <label>Token expires in
                <input type="number" min="1" placeholder="never" value={expiresInDays}
                       onChange={(e) => setExpiresInDays(e.target.value)} /> days</label>
              <label>Max devices
                <input type="number" min="1" placeholder="any" value={maxUses}
                       onChange={(e) => setMaxUses(e.target.value)} /></label>
            </div>
          </div>
          <div className="qs-path">
            <h4>Your MDM <span className="muted">· Jamf, Intune, GPO{!hasMdm && " · Team plan"}</span></h4>
            <p className="muted">One pack your MDM pushes: extension force-install, proxy profile, Claude Code
               managed settings and hooks. No agent.</p>
            {!hasMdm && (
              <p className="muted">The MDM pack is a Team plan feature: <a href="mailto:sales@palivane.io">contact us</a>.
                 The setup script covers the same sources for free.</p>
            )}
            <div className="qs-buttons">
              <input placeholder="egress proxy host (optional)" value={proxyHost}
                     onChange={(e) => setProxyHost(e.target.value)} />
              <button className="primary-btn slim" disabled={packBusy || !hasMdm} onClick={getPolicyPack}>
                {packBusy ? "..." : "Download policy pack"}
              </button>
            </div>
          </div>
        </div>
        <p className="muted qs-foot">Each download carries a reusable enrollment token: treat the file as a
           secret, and revoke it anytime under Connections → enrollment tokens.</p>
        {noUpstream && (
          <div className="qs-hint">
            No model provider key yet, so gateway routing is skipped (the hooks still capture, and Claude Code keeps
            its own account). Add your org's Anthropic key under{" "}
            <a href="/app/settings/gateway" onClick={go("settings", "gateway")}>Settings → Gateway &amp; keys</a> to enable it.
          </div>
        )}
      </div>

      <SelfTest />

      <h2 className="src-title">Sources</h2>
      <div className="src-grid">
        {TILES.map((t) => (
          <button key={t.id} type="button" className={`src-tile ${openTile === t.id ? "open" : ""}`}
                  aria-expanded={openTile === t.id} onClick={() => setOpenTile(openTile === t.id ? null : t.id)}>
            <span className="src-name">{t.name}</span>
            <span className="src-covers">{t.covers}</span>
            <span className="src-foot">
              <StatusDot n={t.n} />
              <span className="src-open">{openTile === t.id ? "Close" : "Set up"}</span>
            </span>
          </button>
        ))}
      </div>
      {open && (
        <div className="panel src-detail" ref={detailRef}>
          <div className="src-detail-head">
            <h3>{open.name}</h3>
            <button type="button" className="link-btn" onClick={() => setOpenTile(null)}>close</button>
          </div>
          {open.detail}
        </div>
      )}
    </div>
  );
}
