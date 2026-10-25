// Shadow-AI Discovery, the inventory of every AI tool in use, sanctioned or not.
// Ingests CASB/SWG/proxy/DNS logs (attribution) and merges what the capture planes actually
// saw (real sensitive-data exposure per tool). Rolls up by tool and by team, marks each tool
// against the live allowlist, and lets an admin sanction/unsanction a tool in one click.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

// Parse "actor,destination[,team]" CSV lines OR a JSON array of {actor,destination,team,count}.
function parseEvents(text) {
  const t = text.trim();
  if (!t) return [];
  if (t.startsWith("[")) {
    try { return JSON.parse(t).filter((e) => e && e.actor); } catch { return null; }
  }
  return t.split("\n").map((line) => {
    const [actor, destination, team] = line.split(",").map((s) => (s || "").trim());
    return actor && destination ? { actor, destination, team: team || "" } : null;
  }).filter(Boolean);
}

const RISK_CLASS = (r) => (r >= 80 ? "critical" : r >= 60 ? "high" : r >= 35 ? "suspicious" : r >= 15 ? "low" : "benign");

const errText = (e) => String(e.message || e).replace(/^\d+:\s*/, "");

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

// Browser extensions installed beside Palivane's own, from browsers whose user shared the list
// (the extension's optional `management` permission). AI ones first; the id is what Chrome's
// ExtensionSettings policy blocks or allows, so the table ends in that action.
function BrowserExtensions({ tenant, onTenant }) {
  const [inv, setInv] = useState(null);
  const [showAll, setShowAll] = useState(false);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const hasMdm = (tenant?.plan_features || []).includes("mdm");

  const load = useCallback(async () => {
    try { setInv(await api.discoveryBrowserExtensions()); }
    catch (e) { setErr(errText(e)); }
  }, []);
  useEffect(() => { load(); }, [load]);

  // Same allowlist the AI-tool table edits; an extension is sanctioned by its id.
  async function toggleSanction(x) {
    const cur = (tenant?.sanctioned_ai_tools || "").split(",").map((s) => s.trim()).filter(Boolean);
    const drop = new Set([x.id, x.ai_product.toLowerCase()]);
    const next = x.sanctioned ? cur.filter((s) => !drop.has(s.toLowerCase())) : [...cur, x.id];
    try {
      onTenant?.(await api.updateTenant({ sanctioned_ai_tools: next.join(", ") }));
      await load();
    } catch (e) { setErr(errText(e)); }
  }

  const unsanctioned = (inv?.extensions || []).filter((x) => x.ai_product && !x.sanctioned);
  async function downloadBlockPolicy() {
    setBusy(true); setErr(null);
    try {
      const res = await api.policyPack({ base_url: window.location.origin,
                                         browser_ext_blocklist: unsanctioned.map((x) => x.id).join(",") });
      download("chrome-extension-settings.json", res.artifacts["chrome-extension-settings.json"]);
    } catch (e) { setErr(errText(e)); }
    finally { setBusy(false); }
  }

  const s = inv?.summary;
  const rows = (inv?.extensions || []).filter((x) => showAll || x.ai_product);
  return (
    <div className="panel settings-card">
      <h2>AI browser extensions</h2>
      <p className="muted" style={{ marginTop: 0 }}>Chrome won't let Palivane read what another
         extension sends, but it can list what's installed once the person shares it (a click in
         the Palivane extension's Options). The ID is what Chrome's <code>ExtensionSettings</code>
         policy blocks or allows.</p>
      {s && s.devices > 0 && (
        <div className="usage-stats">
          <div><span className="usage-n">{s.devices}</span><span className="usage-l">browsers reporting</span></div>
          <div><span className="usage-n">{s.ai_extensions}</span><span className="usage-l">AI extensions</span></div>
          <div><span className="usage-n" style={{ color: "var(--crit)" }}>{s.unsanctioned_ai}</span><span className="usage-l">unsanctioned</span></div>
          <div><span className="usage-n">{s.ai_users}</span><span className="usage-l">users with one</span></div>
        </div>
      )}
      {rows.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr>
              <th>Extension</th><th>ID</th><th>Status</th><th>Browsers</th><th>Users</th>
              <th>Site access</th><th>Installed</th><th></th>
            </tr></thead>
            <tbody>
              {rows.map((x) => (
                <tr key={x.id}>
                  <td><strong>{x.ai_product || x.name || x.id}</strong>
                    {x.ai_product && x.name && x.name !== x.ai_product &&
                      <div className="muted" style={{ fontSize: 11 }}>{x.name}</div>}
                    {x.versions.length > 0 &&
                      <div className="muted" style={{ fontSize: 11 }}>v{x.versions.join(", v")}</div>}
                  </td>
                  <td><code style={{ fontSize: 11, userSelect: "all" }}>{x.id}</code></td>
                  <td>{!x.ai_product ? <span className="muted">-</span>
                    : x.sanctioned ? <span className="cat cat-unsanctioned_ai">Sanctioned</span>
                    : <span className="cat cat-secret_leak">Unsanctioned</span>}</td>
                  <td title={`${x.enabled_count} of ${x.device_count} have it turned on`}>
                    {x.enabled_count}/{x.device_count}</td>
                  <td title={x.users.join(", ")}>{x.user_count}</td>
                  <td>{x.all_sites ? <span style={{ color: "var(--high)", fontWeight: 700 }}>all sites</span>
                                   : <span className="muted">limited</span>}</td>
                  <td className="muted">{x.install_types.join(", ") || "-"}</td>
                  <td>{x.ai_product && (
                    <button className="link-btn" onClick={() => toggleSanction(x)}>
                      {x.sanctioned ? "Unsanction" : "Sanction"}
                    </button>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <p className="muted">{s && s.devices > 0
            ? "No AI extensions in the browsers that report."
            : "No browser has shared its extension list yet."}</p>}
      {err && <div className="error">{err}</div>}
      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", marginTop: 10 }}>
        {s && s.extensions > s.ai_extensions && (
          <button className="link-btn" onClick={() => setShowAll(!showAll)}>
            {showAll ? "Show AI extensions only" : `Show all ${s.extensions} extensions`}
          </button>)}
        {unsanctioned.length > 0 && (hasMdm
          ? <button className="primary-btn slim" onClick={downloadBlockPolicy} disabled={busy}>
              {busy ? "..." : `Download ExtensionSettings blocking ${unsanctioned.length}`}
            </button>
          : <span className="muted" style={{ fontSize: 12 }}>To block them, list these IDs in
              Chrome's <code>ExtensionSettings</code> policy as <code>"installation_mode": "blocked"</code>.</span>)}
      </div>
    </div>
  );
}

export default function Discovery({ tenant, onTenant }) {
  const [inv, setInv] = useState(null);
  const [text, setText] = useState("");
  const [msg, setMsg] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try { setInv(await api.discoveryInventory()); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function ingest() {
    setErr(null); setMsg(null);
    const events = parseEvents(text);
    if (events === null) { setErr("Couldn't parse, use `actor,destination[,team]` lines or a JSON array."); return; }
    if (!events.length) { setErr("Paste at least one `actor,destination` line."); return; }
    setBusy(true);
    try {
      const r = await api.discoveryIngest(events);
      setMsg(`Matched ${r.matched} of ${r.events} events to ${r.tools_seen.length} AI tool(s)`
             + (r.unrecognized ? ` · ${r.unrecognized} unrecognized` : "") + ".");
      setText("");
      await load();
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }

  async function toggleSanction(tool, sanctioned) {
    const cur = (tenant?.sanctioned_ai_tools || "").split(",").map((s) => s.trim()).filter(Boolean);
    let next;
    if (sanctioned) next = cur.filter((s) => s.toLowerCase() !== tool.domain.toLowerCase() && s.toLowerCase() !== tool.tool.toLowerCase());
    else next = [...cur, tool.domain || tool.tool];
    try {
      const t = await api.updateTenant({ sanctioned_ai_tools: next.join(", ") });
      onTenant?.(t);
      await load();
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }

  const s = inv?.summary;
  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Shadow-AI discovery</h1>
          <p className="page-sub">Every AI tool in use (sanctioned or not) from your logs and from
             what Palivane actually captured. Unlike log-only tools, the exposure column shows the
             <strong> real sensitive data</strong> each tool received.</p>
        </div>
      </div>

      {s && (
        <div className="panel settings-card">
          <div className="usage-stats">
            <div><span className="usage-n">{s.tools}</span><span className="usage-l">AI tools</span></div>
            <div><span className="usage-n" style={{ color: "var(--crit)" }}>{s.unsanctioned_tools}</span><span className="usage-l">unsanctioned</span></div>
            <div><span className="usage-n">{s.users}</span><span className="usage-l">users</span></div>
            <div><span className="usage-n" style={{ color: "var(--high)" }}>{s.sensitive_events}</span><span className="usage-l">sensitive exposures</span></div>
            <div title="Distinct users reaching an AI tool from a personal (free-mail) account rather than a corporate identity">
              <span className="usage-n" style={{ color: "var(--high)" }}>{s.personal_account_users ?? 0}</span>
              <span className="usage-l">personal accounts</span></div>
            <div><span className="usage-n">{s.teams}</span><span className="usage-l">teams</span></div>
          </div>
        </div>
      )}

      {/* Inventory by tool */}
      <div className="panel settings-card">
        <h2>AI tool inventory</h2>
        {inv && inv.tools.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr>
                <th>Tool</th><th>Category</th><th>Status</th><th>Users</th><th>Events</th>
                <th>Exposure</th><th>Risk</th><th></th>
              </tr></thead>
              <tbody>
                {inv.tools.map((t) => (
                  <tr key={t.tool}>
                    <td><strong>{t.tool}</strong><div className="muted" style={{ fontSize: 11 }}>{t.domain}</div>
                      {t.personal_user_count > 0 && (
                        <span className="cat cat-pii_exposure" style={{ fontSize: 10, marginTop: 3, display: "inline-block" }}
                              title="Users on this tool via a personal (free-mail) account">
                          {t.personal_user_count} personal
                        </span>)}
                    </td>
                    <td className="muted">{t.category_label}</td>
                    <td>{t.sanctioned
                      ? <span className="cat cat-unsanctioned_ai">Sanctioned</span>
                      : <span className="cat cat-secret_leak">Unsanctioned</span>}</td>
                    <td>{t.user_count}</td>
                    <td>{t.events}</td>
                    <td>{t.sensitive_events
                      ? <span style={{ color: "var(--high)", fontWeight: 700 }}>{t.sensitive_events} 🔓</span>
                      : <span className="muted">-</span>}</td>
                    <td><span className={`sev sev-${RISK_CLASS(t.risk)}`}>{t.risk}</span></td>
                    <td>
                      <button className="link-btn" onClick={() => toggleSanction(t, t.sanctioned)}>
                        {t.sanctioned ? "Unsanction" : "Sanction"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <p className="muted">No AI usage discovered yet. Ingest logs below, or connect a capture plane.</p>}
      </div>

      {/* By team */}
      {inv && inv.teams.length > 0 && (
        <div className="panel settings-card">
          <h2>By team / department</h2>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Team</th><th>Users</th><th>AI tools</th><th>Unsanctioned</th><th>Exposure</th><th>Risk</th></tr></thead>
              <tbody>
                {inv.teams.map((g) => (
                  <tr key={g.team}>
                    <td><strong>{g.team}</strong></td>
                    <td>{g.user_count}</td>
                    <td>{g.tool_count}</td>
                    <td>{g.unsanctioned_count
                      ? <span style={{ color: "var(--crit)", fontWeight: 700 }}>{g.unsanctioned_count}</span>
                      : <span className="muted">0</span>}</td>
                    <td>{g.sensitive_events || <span className="muted">-</span>}</td>
                    <td><span className={`sev sev-${RISK_CLASS(g.max_risk)}`}>{g.max_risk}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <BrowserExtensions tenant={tenant} onTenant={onTenant} />

      {/* Ingest logs */}
      <div className="panel settings-card">
        <h2>Discover from logs</h2>
        <p className="muted" style={{ marginTop: 0 }}>Paste CASB / SWG / proxy / DNS log lines as
           <code> actor,destination[,team]</code> (one per line), or a JSON array of
           <code> {"{actor, destination, team, count}"}</code>. Destinations are matched against
           Palivane's AI-tool catalog.</p>
        <textarea rows={7} style={{ width: "100%" }}
          placeholder={"alice@acme.com,chatgpt.com,Sales\nbob@acme.com,https://otter.ai/,Legal"}
          value={text} onChange={(e) => setText(e.target.value)} />
        {err && <div className="error">{err}</div>}
        {msg && <div className="hint" style={{ color: "var(--benign)" }}>{msg}</div>}
        <button className="primary-btn slim" onClick={ingest} disabled={busy}>
          {busy ? "..." : "Ingest logs"}
        </button>
      </div>
    </div>
  );
}
