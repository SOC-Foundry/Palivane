// Fleet — sensor health across the org: which actors/planes are reporting, which have
// gone quiet, and which devices are still presenting revoked (dead) keys.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconRefresh } from "./icons.jsx";

const HEALTH_CLASS = { fresh: "sev-benign", stale: "sev-suspicious", dark: "sev-critical" };

function fmtWhen(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

// A sensor's installed build. Detection/policy is server-side and always current, so a
// lagging build only means stale *plumbing* (hooks, addon, scanner patterns) — it
// self-updates at the next session start via palivane-posture.
function clientCell(row) {
  if (!row.client) return "—";
  const label = `${row.client} ${row.client_version || "?"}`;
  if (row.client_current) return label;
  // A RETIRED build will never self-update — nothing publishes that name any more, so the
  // "refreshes at next session start" promise below would be a lie. It needs a re-connect.
  if (row.client_retired) {
    return <span style={{ color: "var(--crit)" }}
                 title="A retired client build — this name is no longer published, so it will never self-update. Re-run `palivane connect` on this device.">{label} · retired</span>;
  }
  return <span style={{ color: "var(--susp)" }} title="Older than this deployment ships — refreshes at next session start">{label} · stale</span>;
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

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Fleet</h1>
          <p className="page-sub">Sensor health per actor and plane — who is reporting,
             who has gone quiet, and which devices present revoked keys.</p>
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
              <div><span className="usage-n">{s.actors ?? "—"}</span><span className="usage-l">actors</span></div>
              <div><span className="usage-n">{s.fresh ?? "—"}</span><span className="usage-l">fresh &lt;24h</span></div>
              <div><span className="usage-n">{s.stale ?? "—"}</span><span className="usage-l">stale 24–72h</span></div>
              <div><span className="usage-n">{s.dark ?? "—"}</span><span className="usage-l">dark &gt;72h</span></div>
              <div><span className="usage-n">{s.dead_keys ?? "—"}</span><span className="usage-l">dead keys</span></div>
              <div><span className="usage-n">{s.stale_clients ?? "—"}</span><span className="usage-l">stale builds</span></div>
            </div>
          </div>

          <div className="panel settings-card">
            <h2>Sensors</h2>
            {sensors.length ? (
              <table className="data-table">
                <thead>
                  <tr><th>Actor</th><th>Plane</th><th>Tool</th><th>Client</th><th>Last seen</th><th>Events</th><th>Health</th></tr>
                </thead>
                <tbody>
                  {sensors.map((row, i) => (
                    <tr key={`${row.actor}|${row.plane}|${row.tool}|${i}`}>
                      <td>{row.actor}</td>
                      <td className="muted">{row.plane}</td>
                      <td className="muted">{row.tool || "—"}</td>
                      <td className="muted">{clientCell(row)}</td>
                      <td className="muted">{fmtWhen(row.last_seen)}</td>
                      <td>{row.count}</td>
                      <td><span className={`badge ${HEALTH_CLASS[row.health] || "sev-low"}`}>{row.health}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <p className="muted">No sensor activity captured yet.</p>}
          </div>

          {deadKeys.length > 0 && (
            <div className="panel settings-card">
              <h2>Devices presenting revoked keys</h2>
              <p style={{ color: "var(--crit)", marginTop: 0 }}>
                These devices keep sending events with a revoked key. They <strong>fail open</strong> —
                their traffic is no longer inspected. Re-run <code>palivane-connect</code> on each
                device to enroll a fresh key.
              </p>
              <table className="data-table">
                <thead><tr><th>Label</th><th>Actor</th><th>Key prefix</th><th>Last failed</th></tr></thead>
                <tbody>
                  {deadKeys.map((k) => (
                    <tr key={k.id}>
                      <td>{k.label || "—"}</td>
                      <td>{k.actor || "—"}</td>
                      <td className="muted"><code>{k.prefix}</code></td>
                      <td className="muted">{fmtWhen(k.last_failed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
      {!data && !err && <p className="muted">Loading fleet…</p>}
    </div>
  );
}
