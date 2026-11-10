// Sessions, the unified cross-vendor session audit. One row per actor summarizing
// everything they did across EVERY agent product (Claude Code, Cursor, Codex, Gemini CLI,
// Copilot, browser AI, MCP) in the window; click through to the normalized, chronological
// timeline of that actor's activity across all of them. The "one console for every agent"
// view no single-vendor log can produce.
import { Fragment, useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconRefresh } from "./icons.jsx";

const SEV = { benign: "sev-benign", low: "sev-benign", suspicious: "sev-suspicious",
              high: "sev-high", critical: "sev-critical" };

function fmtWhen(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts)
    : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export default function Sessions() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [days, setDays] = useState(7);
  const [open, setOpen] = useState(null);      // actor whose timeline is expanded
  const [timeline, setTimeline] = useState({}); // actor -> events

  const load = useCallback(async () => {
    setErr(null); setBusy(true);
    try { setData(await api.auditSessions(days)); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }, [days]);
  useEffect(() => { load(); }, [load]);

  async function toggle(actor) {
    if (open === actor) { setOpen(null); return; }
    setOpen(actor);
    if (!timeline[actor]) {
      try {
        const r = await api.auditTimeline(actor, days);
        setTimeline((t) => ({ ...t, [actor]: r.events || [] }));
      } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    }
  }

  const sessions = data?.sessions || [];

  return (
    <div className="page-wide">
      <div className="content-head">
        <div>
          <h1 className="page-title">Sessions</h1>
          <p className="page-sub">Unified cross-vendor audit, every actor's activity across
            all agent tools in one normalized timeline. Palivane's retention, not any vendor's cap.</p>
        </div>
        <div className="head-actions">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={1}>Last 24h</option>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
          </select>
          <button type="button" className="ghost-btn"
                  onClick={() => api.downloadAudit(days, "jsonl").catch((e) => setErr(String(e.message || e)))}>
            Export JSONL
          </button>
          <button type="button" className="ghost-btn"
                  onClick={() => api.downloadAudit(days, "cef").catch((e) => setErr(String(e.message || e)))}>
            Export CEF
          </button>
          <button type="button" className="ghost-btn" onClick={load} disabled={busy}>
            <IconRefresh /> <span>Refresh</span>
          </button>
        </div>
      </div>

      {err && <div className="error">{err}</div>}
      {!sessions.length && !busy && <div className="panel muted">No agent activity in this window.</div>}

      {sessions.length > 0 && (
        <div className="panel settings-card">
          <h2>Actors <span className="count-pill">{sessions.length}</span></h2>
          <div className="table-scroll">
            <table className="data-table session-table">
              <thead>
                <tr><th>Peak</th><th>Actor</th><th>Events</th><th>Tools</th><th>Kill-chain stages</th><th>Last seen</th></tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <Fragment key={s.actor}>
                    <tr className={open === s.actor ? "row-on" : ""} style={{ cursor: "pointer" }}
                        onClick={() => toggle(s.actor)} aria-expanded={open === s.actor}>
                      <td><span className={`chip ${SEV[s.peak_severity] || ""}`}>{s.peak_severity}</span></td>
                      <td>
                        <strong>{s.actor}</strong>
                        {s.chain_detected &&
                          <span className="chip sev-critical" style={{ marginLeft: 8 }}
                                title="A correlated attack chain fired for this actor">⛓ attack chain</span>}
                      </td>
                      <td>{s.events}</td>
                      <td><span className="chip-row">{s.vendors.map((v) => <span key={v} className="chip">{v}</span>)}</span></td>
                      <td className="muted">{s.stages.length ? s.stages.join(" → ") : "-"}</td>
                      <td className="muted nowrap">{fmtWhen(s.last_seen)}</td>
                    </tr>
                    {open === s.actor && (
                      <tr className="session-timeline-row">
                        <td colSpan={6}>
                          <div className="session-timeline">
                            {(timeline[s.actor] || []).map((e) => (
                              <div key={e.finding_id} className="session-event">
                                <span className="muted nowrap">{fmtWhen(e.ts)}</span>
                                <span className="chip">{e.vendor}</span>
                                <span className={`chip ${SEV[e.severity] || ""}`}>{e.severity}</span>
                                <span>{e.action}</span>
                                {e.stages.length > 0 && <span className="muted">· {e.stages.join(", ")}</span>}
                                {e.is_chain && <span className="chip sev-critical">chain</span>}
                              </div>
                            ))}
                            {!timeline[s.actor] && <div className="muted">Loading timeline...</div>}
                            {timeline[s.actor] && !timeline[s.actor].length && <div className="muted">No events.</div>}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
