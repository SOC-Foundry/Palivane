// Fleet, sensor health across the org: who is reporting, who has gone quiet, which scans
// failed open, which devices still present revoked (dead) keys, and what AI assets the
// devices have installed. Built to stay readable at a few hundred people: the ledger is one
// row per person (a sensor row is keyed by tool, so one developer is twenty or thirty of
// them), paged, worst first, and showing only what needs a look unless asked otherwise.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconRefresh } from "./icons.jsx";
import ContainmentPanel from "./Containment.jsx";

const HEALTH_CLASS = { fresh: "sev-benign", stale: "sev-suspicious", dark: "sev-critical" };
const PEOPLE_PAGE = 50;
const SHORT_LIST = 10;    // rows a panel shows before "Show all"

function fmtWhen(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts)
    : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

// A sensor's installed build. Detection/policy is server-side and always current, so a
// lagging build only means stale *plumbing* (hooks, addon, scanner patterns), it
// self-updates at the next session start via palivane-posture.
function clientCell(row) {
  if (!row.client) return "-";
  const label = `${row.client} ${row.client_version || "?"}`;
  if (row.client_current) return label;
  // A RETIRED build will never self-update, nothing publishes that name any more, so the
  // "refreshes at next session start" promise below would be a lie. It needs a re-connect.
  if (row.client_retired) {
    return <span style={{ color: "var(--crit)" }}
                 title="A retired client build, this name is no longer published, so it will never self-update. Re-run `palivane connect` on this device.">{label} · retired</span>;
  }
  return <span style={{ color: "var(--susp)" }} title="Older than this deployment ships, refreshes at next session start">{label} · stale</span>;
}

// Why a scan failed open, in the words the client reported (a fixed vocabulary, SEC-01).
const REASON_LABEL = {
  timeout: "timeout", network: "network error", "server-error": "server error (5xx)",
  "auth-rejected": "key rejected", "rate-limited": "rate limited", "http-error": "HTTP error",
  "bad-response": "unreadable response", "breaker-open": "circuit breaker open", error: "error",
  "update-failed": "proxy update rolled back",
  "unparsed-prompt": "prompt-like request it could not read",
};

function reasonsText(reasons) {
  return Object.entries(reasons || {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${REASON_LABEL[k] || k} ×${n}`)
    .join(", ") || "-";
}

// "Show all" for a panel that is usually short but has no natural cap.
function ShowAll({ total, shown, open, onToggle, what }) {
  if (total <= shown && !open) return null;
  return (
    <button type="button" className="link-btn" onClick={onToggle}>
      {open ? `Show the first ${SHORT_LIST}` : `Show all ${total} ${what}`}
    </button>
  );
}

// AI-asset inventory: what palivane-posture (and the browser extension) found installed on
// each device, so "which devices have X" has an answer the day X is reported compromised.
const ASSET_KINDS = [
  ["", "all kinds"], ["mcp_server", "MCP servers"], ["ide_extension", "IDE extensions"],
  ["browser_extension", "browser extensions"], ["agent", "coding agents"],
  ["skill", "skills"], ["plugin", "plugins"],
];
const KIND_LABEL = Object.fromEntries(ASSET_KINDS.filter(([k]) => k));
const ASSET_PAGE = 50;
const DEVICE_PAGE = 100;

// Where an item was found / extra facts worth a glance (hook state for agents).
function assetDetail(d) {
  const x = d.extra || {};
  const bits = [];
  if (d.source) bits.push(d.source);
  if (x.palivane_hooks) {
    const off = x.hooks_enabled === false ? " (hooks disabled)" : "";
    bits.push(`Palivane hooks: ${x.palivane_hooks}${off}`);
  }
  if (x.package) bits.push(x.package);
  if (x.host) bits.push(x.host);
  if (x.enabled === false) bits.push("disabled");
  return bits.join(" · ") || "-";
}

function AssetDevices({ asset }) {
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const more = useCallback(async (offset) => {
    setBusy(true); setErr(null);
    try {
      const d = await api.fleetAssetDevices(asset.kind, asset.name, { limit: DEVICE_PAGE, offset });
      setRows((prev) => (offset ? [...prev, ...d.devices] : d.devices));
      setTotal(d.total);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }, [asset.kind, asset.name]);
  useEffect(() => { more(0); }, [more]);

  if (err) return <div className="error">{err}</div>;
  if (!rows.length) return <p className="muted">{busy ? "Loading devices..." : "No devices."}</p>;
  return (
    <>
      <table className="data-table">
        <thead><tr><th>Device</th><th>Actor</th><th>Version</th><th>Details</th><th>First seen</th><th>Last seen</th></tr></thead>
        <tbody>
          {rows.map((d) => (
            <tr key={d.device}>
              <td>{d.device}</td>
              <td className="muted">{d.actor || "-"}</td>
              <td>{d.version || "-"}</td>
              <td className="muted">{assetDetail(d)}</td>
              <td className="muted">{fmtWhen(d.first_seen)}</td>
              <td className="muted">{fmtWhen(d.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length < total && (
        <button type="button" className="ghost-btn" disabled={busy} onClick={() => more(rows.length)}>
          Show more ({total - rows.length} left)
        </button>
      )}
    </>
  );
}

// Search-first: the inventory is every item on every device, which is a long list for one
// developer and a very long one for a fleet. The counts per kind say what is out there;
// the table opens for a search, a kind, or on request.
function AssetInventory() {
  const [query, setQuery] = useState("");
  const [needle, setNeedle] = useState("");
  const [kind, setKind] = useState("");
  const [offset, setOffset] = useState(0);
  const [browse, setBrowse] = useState(false);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [open, setOpen] = useState(null);

  // Debounce typing so each keystroke isn't a request.
  useEffect(() => {
    const t = setTimeout(() => { setNeedle(query.trim()); setOffset(0); }, 300);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    let live = true;
    setErr(null);
    api.fleetAssets({ kind, name: needle, limit: ASSET_PAGE, offset })
      .then((d) => { if (live) { setData(d); setOpen(null); } })
      .catch((e) => { if (live) setErr(String(e.message || e).replace(/^\d+:\s*/, "")); });
    return () => { live = false; };
  }, [kind, needle, offset]);

  const assets = data?.assets || [];
  const total = data?.total || 0;
  const devices = data?.summary?.devices ?? 0;
  const kinds = data?.summary?.kinds || {};
  const expanded = Boolean(needle || kind || browse);
  const keyOf = (a) => `${a.kind}|${a.name}`;

  return (
    <div className="panel settings-card">
      <h2>AI assets</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        MCP servers, extensions, coding agents, skills and plugins installed across {devices} device{devices === 1 ? "" : "s"},
        as each device last reported them. Search to find which devices have a given item.
      </p>
      {Object.keys(kinds).length > 0 && (
        <div className="head-actions" style={{ justifyContent: "flex-start", marginBottom: 12 }}>
          {ASSET_KINDS.filter(([k]) => k && kinds[k]).map(([k, label]) => (
            <button key={k} type="button" className={`chip ${kind === k ? "chip-on" : "chip-off"}`}
                    style={{ cursor: "pointer" }} aria-pressed={kind === k}
                    onClick={() => { setKind(kind === k ? "" : k); setOffset(0); }}>
              {kinds[k]} {label}
            </button>
          ))}
        </div>
      )}
      <div className="override-row">
        <input type="search" placeholder="Which devices have... (name, publisher, marketplace)" value={query}
               aria-label="Search AI assets" onChange={(e) => setQuery(e.target.value)} />
        <select value={kind} aria-label="Asset kind" onChange={(e) => { setKind(e.target.value); setOffset(0); }}>
          {ASSET_KINDS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
        </select>
      </div>
      {err && <div className="error">{err}</div>}
      {!expanded && data && (
        total
          ? <button type="button" className="link-btn" onClick={() => setBrowse(true)}>Browse all {total} items</button>
          : <p className="muted">No inventory reported yet. Devices report it via palivane-posture at session start.</p>
      )}
      {expanded && (assets.length ? (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr><th aria-label="Expand" /><th>Kind</th><th>Name</th><th>Versions</th><th>Source</th><th>Devices</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {assets.map((a) => {
                const k = keyOf(a);
                const isOpen = open === k;
                return [
                  <tr key={k} style={{ cursor: "pointer" }} onClick={() => setOpen(isOpen ? null : k)}>
                    <td>
                      <button type="button" className="ghost-btn" aria-expanded={isOpen}
                              aria-label={`${isOpen ? "Hide" : "Show"} devices with ${a.name}`}
                              onClick={(e) => { e.stopPropagation(); setOpen(isOpen ? null : k); }}>
                        {isOpen ? "▾" : "▸"}
                      </button>
                    </td>
                    <td className="muted">{KIND_LABEL[a.kind] || a.kind}</td>
                    <td><code>{a.name}</code></td>
                    <td className="muted">{a.versions.length ? a.versions.join(", ") : "-"}</td>
                    <td className="muted">{a.sources.length ? a.sources.join(", ") : "-"}</td>
                    <td><strong>{a.device_count}</strong></td>
                    <td className="muted">{fmtWhen(a.last_seen)}</td>
                  </tr>,
                  isOpen && (
                    <tr key={`${k}|devices`}>
                      <td colSpan={7}><AssetDevices asset={a} /></td>
                    </tr>
                  ),
                ];
              })}
            </tbody>
          </table>
        </div>
      ) : data && (
        <p className="muted">
          {needle || kind ? "No matching assets." : "No inventory reported yet. Devices report it via palivane-posture at session start."}
        </p>
      ))}
      {expanded && (
        <div className="head-actions">
          {browse && !needle && !kind && (
            <button type="button" className="link-btn" onClick={() => setBrowse(false)}>Collapse</button>
          )}
          {total > ASSET_PAGE && (
            <>
              <button type="button" className="ghost-btn" disabled={offset === 0}
                      onClick={() => setOffset(Math.max(0, offset - ASSET_PAGE))}>Previous</button>
              <span className="muted">{offset + 1}-{Math.min(offset + ASSET_PAGE, total)} of {total}</span>
              <button type="button" className="ghost-btn" disabled={offset + ASSET_PAGE >= total}
                      onClick={() => setOffset(offset + ASSET_PAGE)}>Next</button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// People each plane covered, per calendar month: the head count behind per-developer pricing.
// Counts only (the meter keeps a keyed hash per person, never a name).
function DeveloperMeter() {
  const [d, setD] = useState(null);
  useEffect(() => { api.fleetDevelopers(3).then(setD).catch(() => setD(null)); }, []);
  const months = d?.months || [];
  if (!months.length) return null;
  const cols = [["agent", "Agent plane"], ["browser_only", "Browser / desktop only"],
                ["browser", "Browser"], ["desktop", "Desktop apps"],
                ["claude_enterprise", "Claude Enterprise"], ["ci_repos", "CI repos"]];
  return (
    <div className="panel settings-card">
      <h2>People covered, by month</h2>
      <p className="muted" style={{ marginTop: 0 }}>Distinct people each plane reported for in the
         month (UTC). <strong>Agent plane</strong> is coding-tool hooks and MCP tool calls;
         <strong> browser / desktop only</strong> is people seen there and not on the agent plane.
         CI counts repositories.</p>
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Month</th>{cols.map(([k, l]) => <th key={k}>{l}</th>)}<th>Unattributed</th></tr></thead>
          <tbody>
            {months.map((m) => (
              <tr key={m.month}>
                <td style={{ whiteSpace: "nowrap" }}>{m.month}</td>
                {cols.map(([k]) => <td key={k}>{k === "agent" ? <strong>{m[k]}</strong> : m[k]}</td>)}
                <td className="muted" title="Planes that had reports naming no person (a shared key with no user set)">
                  {m.unattributed ? `${m.unattributed} plane${m.unattributed > 1 ? "s" : ""}` : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// On the mcp plane a sensor row is one per client and the tools it called are counted
// inside it; elsewhere `tool` is the assistant, scan kind or repo.
function toolCell(row) {
  const names = Object.entries(row.tools || {}).sort((a, b) => b[1] - a[1]);
  if (!names.length) return row.tool || "-";
  const top = names.slice(0, 12).map(([t, n]) => `${t} ×${n}`).join(", ");
  return <span title={names.length > 12 ? `${top}, …` : top}>{names.length} tool{names.length === 1 ? "" : "s"}</span>;
}

// The sensors one person has, under their row in the ledger.
function PersonSensors({ rows }) {
  return (
    <table className="data-table">
      <thead>
        <tr><th>Plane</th><th>Tool</th><th>Client</th><th>Last seen</th><th>Events</th><th>Failed open</th><th>Health</th></tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={`${row.plane}|${row.tool}|${row.client}|${i}`}>
            <td className="muted">{row.plane}</td>
            <td className="muted">{toolCell(row)}</td>
            <td className="muted">{clientCell(row)}</td>
            <td className="muted">{fmtWhen(row.last_seen)}</td>
            <td>{row.count}</td>
            <td title={row.scan_fail_count ? `since ${fmtWhen(row.first_scan_fail)}: ${reasonsText(row.scan_fail_reasons)}` : undefined}
                style={row.scan_fail_count ? { color: "var(--susp)" } : undefined}>
              {row.scan_fail_count || 0}
            </td>
            <td><span className={`badge ${HEALTH_CLASS[row.health] || "sev-low"}`}>{row.health}</span></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function planesText(planes) {
  return Object.entries(planes || {})
    .sort((a, b) => b[1] - a[1])
    .map(([p, n]) => (n > 1 ? `${p} ×${n}` : p))
    .join(", ") || "-";
}

function buildsCell(p) {
  if (!p.stale_builds) return <span className="muted">current</span>;
  const retired = p.retired_builds ? `${p.retired_builds} retired` : "";
  const stale = p.stale_builds - p.retired_builds ? `${p.stale_builds - p.retired_builds} stale` : "";
  return <span style={{ color: p.retired_builds ? "var(--crit)" : "var(--susp)" }}>{[retired, stale].filter(Boolean).join(", ")}</span>;
}

// A person's identity keeping a machine's hours is an agent nobody registered: a cron'd
// coding agent, a CI job, running under someone's key, with that person's permissions and
// none of an agent's limits. Register it, and it gets its own identity.
function UnattendedAgents({ tick }) {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState(null);
  useEffect(() => { api.fleetUnattended().then(setData).catch(() => setData(null)); }, [tick]);
  const rows = data?.unattended || [];
  if (!rows.length) return null;

  async function register(actor) {
    setBusy(actor); setMsg(null);
    const name = `agent:${actor}`;
    try {
      const r = await api.agentCreate({ name, kind: "service" });
      setMsg({ ok: true, text: `Registered ${name}. Its identity token is shown once: ${r.token}. Put it on the machine that runs as ${actor} (PALIVANE_AGENT_TOKEN), and its actions attribute to the agent, with the agent's limits.` });
      setData({ ...data, unattended: rows.filter((x) => x.actor !== actor) });
    } catch (e) { setMsg({ ok: false, text: String(e.message || e).replace(/^\d+:\s*/, "") }); }
    finally { setBusy(""); }
  }

  return (
    <div className="panel settings-card">
      <h2>Agents under a person's key <span className="count-pill">{rows.length}</span></h2>
      <p className="muted" style={{ marginTop: 0 }}>
        These identities were active in {data.limits.hours} of 24 hours on {data.limits.days} of the
        last 7 days: a machine's cadence, not a person's. A scheduled coding agent or a CI job is
        running under someone's key, with that person's permissions and none of an agent's limits.
        Register it to give it its own identity.
      </p>
      {msg && <div className={msg.ok ? "flash-ok" : "flash-err"}>{msg.text}</div>}
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Identity</th><th>Hours of the day</th><th>Days</th><th>Last seen</th><th></th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.actor}>
                <td><strong>{r.actor}</strong></td>
                <td>{r.hours_of_day} of 24</td>
                <td>{r.days} of 7</td>
                <td className="muted">{fmtWhen(r.last_seen)}</td>
                <td><button type="button" className="ghost-btn slim" disabled={busy === r.actor}
                            onClick={() => register(r.actor)}>Register as agent</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// One row per person, paged, worst first. Defaults to the people with something to look
// at: a sensor past 24h, a scan that failed open this week, or a stale/retired build.
function PeopleLedger({ tick }) {
  const [attention, setAttention] = useState(true);
  const [query, setQuery] = useState("");
  const [needle, setNeedle] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [open, setOpen] = useState(null);

  useEffect(() => {
    const t = setTimeout(() => { setNeedle(query.trim()); setOffset(0); }, 300);
    return () => clearTimeout(t);
  }, [query]);

  useEffect(() => {
    let live = true;
    setErr(null);
    api.fleetPeople({ attention: attention ? 1 : 0, q: needle, limit: PEOPLE_PAGE, offset })
      .then((d) => { if (live) { setData(d); setOpen(null); } })
      .catch((e) => { if (live) setErr(String(e.message || e).replace(/^\d+:\s*/, "")); });
    return () => { live = false; };
  }, [attention, needle, offset, tick]);

  const people = data?.people || [];
  const total = data?.total || 0;
  const s = data?.summary || {};

  return (
    <div className="panel settings-card">
      <h2>
        People
        {s.people > 0 && <span className="count-pill">{s.people}</span>}
        <span className="head-actions" style={{ marginLeft: "auto", fontWeight: 400 }}>
          <label className="muted" style={{ fontSize: 12 }}>
            <input type="checkbox" checked={attention}
                   onChange={(e) => { setAttention(e.target.checked); setOffset(0); }} /> needs attention only
          </label>
        </span>
      </h2>
      <p className="muted" style={{ marginTop: 0 }}>
        One row per person, worst first. A person's health is their <em>oldest</em> sensor, so
        someone whose laptop hook went dark stays flagged while their browser extension keeps
        reporting. Expand a row for the sensors.
      </p>
      <div className="override-row">
        <input type="search" placeholder="Find a person..." value={query} aria-label="Search people"
               onChange={(e) => setQuery(e.target.value)} />
      </div>
      {err && <div className="error">{err}</div>}
      {data && !people.length && (
        <p className="muted">
          {needle ? "Nobody matches."
            : attention ? (s.people ? "Everyone is reporting, current, and scanned. Nothing needs a look."
                                    : "No sensor activity captured yet.")
            : "No sensor activity captured yet."}
        </p>
      )}
      {people.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr><th aria-label="Expand" /><th>Person</th><th>Planes</th><th>Sensors</th><th>Last seen</th><th>Oldest sensor</th><th>Events</th><th>Failed open 7d</th><th>Builds</th><th>Health</th></tr>
            </thead>
            <tbody>
              {people.map((p) => {
                const isOpen = open === p.actor;
                return [
                  <tr key={p.actor} style={{ cursor: "pointer" }} onClick={() => setOpen(isOpen ? null : p.actor)}>
                    <td>
                      <button type="button" className="ghost-btn" aria-expanded={isOpen}
                              aria-label={`${isOpen ? "Hide" : "Show"} sensors for ${p.actor}`}
                              onClick={(e) => { e.stopPropagation(); setOpen(isOpen ? null : p.actor); }}>
                        {isOpen ? "▾" : "▸"}
                      </button>
                    </td>
                    <td><strong>{p.actor || "(unattributed)"}</strong>
                      {p.round_the_clock && (
                        <span className="chip chip-warn" style={{ marginLeft: 8 }}
                              title="Active in 20 of 24 hours on 5 of the last 7 days: a machine's cadence on a person's identity. Likely an unregistered agent under their key; see the panel above.">
                          24/7
                        </span>
                      )}
                    </td>
                    <td className="muted">{planesText(p.planes)}</td>
                    <td>{p.sensors}</td>
                    <td className="muted">{fmtWhen(p.last_seen)}</td>
                    <td className="muted">{fmtWhen(p.oldest_seen)}</td>
                    <td>{p.events}</td>
                    <td style={p.failed_open ? { color: "var(--susp)" } : undefined}>{p.failed_open || 0}</td>
                    <td>{buildsCell(p)}</td>
                    <td><span className={`badge ${HEALTH_CLASS[p.worst] || "sev-low"}`}>{p.worst}</span></td>
                  </tr>,
                  isOpen && (
                    <tr key={`${p.actor}|sensors`}>
                      <td colSpan={10}><PersonSensors rows={p.rows} /></td>
                    </tr>
                  ),
                ];
              })}
            </tbody>
          </table>
        </div>
      )}
      {total > PEOPLE_PAGE && (
        <div className="head-actions">
          <button type="button" className="ghost-btn" disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - PEOPLE_PAGE))}>Previous</button>
          <span className="muted">{offset + 1}-{Math.min(offset + PEOPLE_PAGE, total)} of {total}</span>
          <button type="button" className="ghost-btn" disabled={offset + PEOPLE_PAGE >= total}
                  onClick={() => setOffset(offset + PEOPLE_PAGE)}>Next</button>
        </div>
      )}
    </div>
  );
}

export default function Fleet() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(0);
  const [allFailed, setAllFailed] = useState(false);
  const [allDead, setAllDead] = useState(false);

  const load = useCallback(async () => {
    setErr(null); setBusy(true);
    try { setData(await api.fleet({ sensors: 0 })); setTick((t) => t + 1); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const s = data?.summary || {};
  const deadKeys = data?.dead_keys || [];
  const failedOpen = data?.failed_open_devices || [];
  const failedShown = allFailed ? failedOpen : failedOpen.slice(0, SHORT_LIST);
  const deadShown = allDead ? deadKeys : deadKeys.slice(0, SHORT_LIST);

  return (
    <div className="connect page-wide">
      <div className="content-head">
        <div>
          <h1 className="page-title">Fleet</h1>
          <p className="page-sub">Who is reporting and who has gone quiet, one row per person;
             which devices let scans fail open or present revoked keys; and which AI assets
             the devices have installed.</p>
        </div>
        <div className="head-actions">
          <button type="button" className="ghost-btn" onClick={load} disabled={busy}>
            <IconRefresh /> <span>Refresh</span>
          </button>
        </div>
      </div>

      {err && <div className="error">{err}</div>}

      {data && (
        <>
          <ContainmentPanel />

          <div className="panel settings-card">
            <div className="usage-stats">
              <div><span className="usage-n">{s.actors ?? "-"}</span><span className="usage-l">people</span></div>
              <div><span className="usage-n">{s.sensors ?? "-"}</span><span className="usage-l">sensors</span></div>
              <div><span className="usage-n">{s.fresh ?? "-"}</span><span className="usage-l">fresh &lt;24h</span></div>
              <div><span className="usage-n">{s.stale ?? "-"}</span><span className="usage-l">stale 24-72h</span></div>
              <div><span className="usage-n">{s.dark ?? "-"}</span><span className="usage-l">dark &gt;72h</span></div>
              <div><span className="usage-n">{s.dead_keys ?? "-"}</span><span className="usage-l">dead keys</span></div>
              <div><span className="usage-n">{s.stale_clients ?? "-"}</span><span className="usage-l">stale builds</span></div>
              <div><span className="usage-n">{s.failed_open_devices ?? "-"}</span><span className="usage-l">devices failed open 7d</span></div>
            </div>
          </div>

          {failedOpen.length > 0 && (
            <div className="panel settings-card">
              <h2>Scans failed open <span className="count-pill">{failedOpen.length}</span></h2>
              <p style={{ color: "var(--susp)", marginTop: 0 }}>
                When a scan cannot complete (Palivane unreachable, a timeout, a rejected key) the
                sensor lets the user through <strong>unscanned</strong> rather than block them. Each
                device counts those and reports the tally the next time it reaches Palivane, one
                row per device here however many tools it was asked about. A device that never
                reaches it again shows up as dark in the people list instead.
              </p>
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>Person</th><th>Client</th><th>Sensors</th><th>Failed open</th><th>Since</th><th>Last</th><th>Why</th></tr>
                  </thead>
                  <tbody>
                    {failedShown.map((row) => (
                      <tr key={`fo|${row.actor}|${row.client}`}>
                        <td>{row.actor || "(unattributed)"}</td>
                        <td className="muted">{clientCell(row)}</td>
                        <td className="muted" title={row.tools.join(", ")}>{row.sensors}</td>
                        <td><strong>{row.failed_open}</strong></td>
                        <td className="muted">{fmtWhen(row.first_scan_fail)}</td>
                        <td className="muted">{fmtWhen(row.last_scan_fail)}</td>
                        <td className="muted">{reasonsText(row.reasons)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <ShowAll total={failedOpen.length} shown={failedShown.length} open={allFailed}
                       onToggle={() => setAllFailed((v) => !v)} what="devices" />
            </div>
          )}
          {deadKeys.length > 0 && (
            <div className="panel settings-card">
              <h2>Devices presenting revoked keys <span className="count-pill">{deadKeys.length}</span></h2>
              <p style={{ color: "var(--crit)", marginTop: 0 }}>
                These devices keep sending events with a revoked key. They <strong>fail open</strong>:
                their traffic is no longer inspected. Re-run <code>palivane-connect</code> on each
                device to enroll a fresh key.
              </p>
              <div className="table-scroll">
                <table className="data-table">
                  <thead><tr><th>Label</th><th>Actor</th><th>Key prefix</th><th>Last failed</th></tr></thead>
                  <tbody>
                    {deadShown.map((k) => (
                      <tr key={k.id}>
                        <td>{k.label || "-"}</td>
                        <td>{k.actor || "-"}</td>
                        <td className="muted"><code>{k.prefix}</code></td>
                        <td className="muted">{fmtWhen(k.last_failed_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <ShowAll total={deadKeys.length} shown={deadShown.length} open={allDead}
                       onToggle={() => setAllDead((v) => !v)} what="devices" />
            </div>
          )}

          <UnattendedAgents tick={tick} />
          <PeopleLedger tick={tick} />
          <DeveloperMeter />
          <AssetInventory />
        </>
      )}
      {!data && !err && <p className="muted">Loading fleet...</p>}
    </div>
  );
}
