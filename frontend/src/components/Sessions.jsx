// Sessions, the unified cross-vendor session audit. One row per actor summarizing
// everything they did across EVERY agent product (Claude Code, Cursor, Codex, Gemini CLI,
// Copilot, browser AI, MCP) in the window; click through to the normalized, chronological
// timeline of that actor's activity across all of them. The "one console for every agent"
// view no single-vendor log can produce.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconRefresh } from "./icons.jsx";

const SEV = { benign: "sev-benign", low: "sev-benign", suspicious: "sev-suspicious",
              high: "sev-high", critical: "sev-critical" };

function fmtWhen(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
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
    <div className="view">
      <div className="view-head">
        <div>
          <h1>Sessions</h1>
          <p className="muted">Unified cross-vendor audit, every actor's activity across
            all agent tools in one normalized timeline. Palivane's retention, not any vendor's cap.</p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={1}>Last 24h</option>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
          </select>
          <button type="button" className="mini-btn"
                  onClick={() => api.downloadAudit(days, "jsonl").catch((e) => setErr(String(e.message || e)))}>
            Export JSONL
          </button>
          <button type="button" className="mini-btn"
                  onClick={() => api.downloadAudit(days, "cef").catch((e) => setErr(String(e.message || e)))}>
            Export CEF
          </button>
          <button type="button" className="mini-btn" onClick={load} disabled={busy}>
            <IconRefresh /> Refresh
          </button>
        </div>
      </div>

      {err && <div className="banner banner-error">{err}</div>}
      {!sessions.length && !busy && <div className="panel muted">No agent activity in this window.</div>}

      {sessions.map((s) => (
        <div key={s.actor} className="panel" style={{ marginBottom: 10 }}>
          <div className="session-row" style={{ display: "flex", alignItems: "center", gap: 12,
                 cursor: "pointer", flexWrap: "wrap" }} onClick={() => toggle(s.actor)}>
            <span className={`chip ${SEV[s.peak_severity] || ""}`}>{s.peak_severity}</span>
            <strong style={{ minWidth: 180 }}>{s.actor}</strong>
            {s.chain_detected &&
              <span className="chip sev-critical" title="A correlated attack chain fired for this actor">⛓ attack chain</span>}
            <span className="muted">{s.events} event{s.events === 1 ? "" : "s"}</span>
            <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {s.vendors.map((v) => <span key={v} className="chip">{v}</span>)}
            </span>
            {s.stages.length > 0 &&
              <span className="muted" style={{ marginLeft: "auto" }}>{s.stages.join(" → ")}</span>}
            <span className="muted">{fmtWhen(s.last_seen)}</span>
          </div>

          {open === s.actor && (
            <div className="session-timeline" style={{ marginTop: 10, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
              {(timeline[s.actor] || []).map((e) => (
                <div key={e.finding_id} style={{ display: "flex", gap: 10, padding: "4px 0",
                       alignItems: "baseline", flexWrap: "wrap" }}>
                  <span className="muted" style={{ minWidth: 150 }}>{fmtWhen(e.ts)}</span>
                  <span className="chip">{e.vendor}</span>
                  <span className={`chip ${SEV[e.severity] || ""}`}>{e.severity}</span>
                  <span>{e.action}</span>
                  {e.stages.length > 0 && <span className="muted">· {e.stages.join(", ")}</span>}
                  {e.is_chain && <span className="chip sev-critical">chain</span>}
                </div>
              ))}
              {!(timeline[s.actor] || []).length && <div className="muted">Loading timeline...</div>}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
