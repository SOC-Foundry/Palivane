// Fleet, sensor health across the org: which actors/planes are reporting, which have
// gone quiet, and which devices are still presenting revoked (dead) keys.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconRefresh } from "./icons.jsx";

const HEALTH_CLASS = { fresh: "sev-benign", stale: "sev-suspicious", dark: "sev-critical" };

function fmtWhen(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
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

function AssetInventory() {
  const [query, setQuery] = useState("");
  const [needle, setNeedle] = useState("");
  const [kind, setKind] = useState("");
  const [offset, setOffset] = useState(0);
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
  const keyOf = (a) => `${a.kind}|${a.name}`;

  return (
    <div className="panel settings-card">
      <h2>AI assets</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        MCP servers, extensions, coding agents, skills and plugins installed across {devices} device{devices === 1 ? "" : "s"},
        as each device last reported them. Search to find which devices have a given item.
      </p>
      <div className="override-row">
        <input type="search" placeholder="Which devices have... (name, publisher, marketplace)" value={query}
               aria-label="Search AI assets" onChange={(e) => setQuery(e.target.value)} />
        <select value={kind} aria-label="Asset kind" onChange={(e) => { setKind(e.target.value); setOffset(0); }}>
          {ASSET_KINDS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
        </select>
      </div>
      {err && <div className="error">{err}</div>}
      {assets.length ? (
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
      )}
      {total > ASSET_PAGE && (
        <div className="head-actions">
          <button type="button" className="ghost-btn" disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - ASSET_PAGE))}>Previous</button>
          <span className="muted">{offset + 1}-{Math.min(offset + ASSET_PAGE, total)} of {total}</span>
          <button type="button" className="ghost-btn" disabled={offset + ASSET_PAGE >= total}
                  onClick={() => setOffset(offset + ASSET_PAGE)}>Next</button>
        </div>
      )}
    </div>
  );
}

export default function Fleet() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setErr(null); setBusy(true);
    try { setData(await api.fleet()); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const s = data?.summary || {};
  const sensors = data?.sensors || [];
  const deadKeys = data?.dead_keys || [];
  const failedOpen = sensors
    .filter((r) => r.scan_fail_count > 0)
    .sort((a, b) => String(b.last_scan_fail || "").localeCompare(String(a.last_scan_fail || "")));

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Fleet</h1>
          <p className="page-sub">Sensor health per actor and plane, who is reporting,
             who has gone quiet, which scans failed open, which devices present revoked keys,
             and which AI assets each device has installed.</p>
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
          <div className="panel settings-card">
            <div className="usage-stats">
              <div><span className="usage-n">{s.actors ?? "-"}</span><span className="usage-l">actors</span></div>
              <div><span className="usage-n">{s.fresh ?? "-"}</span><span className="usage-l">fresh &lt;24h</span></div>
              <div><span className="usage-n">{s.stale ?? "-"}</span><span className="usage-l">stale 24-72h</span></div>
              <div><span className="usage-n">{s.dark ?? "-"}</span><span className="usage-l">dark &gt;72h</span></div>
              <div><span className="usage-n">{s.dead_keys ?? "-"}</span><span className="usage-l">dead keys</span></div>
              <div><span className="usage-n">{s.stale_clients ?? "-"}</span><span className="usage-l">stale builds</span></div>
              <div><span className="usage-n">{s.failed_open ?? "-"}</span><span className="usage-l">failed open 7d</span></div>
            </div>
          </div>

          {failedOpen.length > 0 && (
            <div className="panel settings-card">
              <h2>Scans failed open</h2>
              <p style={{ color: "var(--susp)", marginTop: 0 }}>
                When a scan cannot complete (Palivane unreachable, a timeout, a rejected key) the
                sensor lets the user through <strong>unscanned</strong> rather than block them. Each
                device counts those and reports the tally the next time it reaches Palivane. A device
                that never reaches it again shows up as stale or dark below instead.
              </p>
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>Actor</th><th>Client</th><th>Plane / tool</th><th>Failed open</th><th>Since</th><th>Last</th><th>Why</th></tr>
                  </thead>
                  <tbody>
                    {failedOpen.map((row, i) => (
                      <tr key={`fo|${row.actor}|${row.plane}|${row.tool}|${i}`}>
                        <td>{row.actor}</td>
                        <td className="muted">{row.client || "-"}</td>
                        <td className="muted">{row.plane}{row.tool ? ` / ${row.tool}` : ""}</td>
                        <td><strong>{row.scan_fail_count}</strong></td>
                        <td className="muted">{fmtWhen(row.first_scan_fail)}</td>
                        <td className="muted">{fmtWhen(row.last_scan_fail)}</td>
                        <td className="muted">{reasonsText(row.scan_fail_reasons)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div className="panel settings-card">
            <h2>Sensors</h2>
            {sensors.length ? (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>Actor</th><th>Plane</th><th>Tool</th><th>Client</th><th>Last seen</th><th>Events</th><th>Failed open</th><th>Health</th></tr>
                  </thead>
                  <tbody>
                    {sensors.map((row, i) => (
                      <tr key={`${row.actor}|${row.plane}|${row.tool}|${i}`}>
                        <td>{row.actor}</td>
                        <td className="muted">{row.plane}</td>
                        <td className="muted">{row.tool || "-"}</td>
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
              </div>
            ) : <p className="muted">No sensor activity captured yet.</p>}
          </div>

          <AssetInventory />

          {deadKeys.length > 0 && (
            <div className="panel settings-card">
              <h2>Devices presenting revoked keys</h2>
              <p style={{ color: "var(--crit)", marginTop: 0 }}>
                These devices keep sending events with a revoked key. They <strong>fail open</strong>
                their traffic is no longer inspected. Re-run <code>palivane-connect</code> on each
                device to enroll a fresh key.
              </p>
              <div className="table-scroll">
                <table className="data-table">
                  <thead><tr><th>Label</th><th>Actor</th><th>Key prefix</th><th>Last failed</th></tr></thead>
                  <tbody>
                    {deadKeys.map((k) => (
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
            </div>
          )}
        </>
      )}
      {!data && !err && <p className="muted">Loading fleet...</p>}
    </div>
  );
}
