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


// The flight recorder: one actor's window as steps on a scrubber, and the same window replayed
// against a policy that was not in force. "Which step would this policy have stopped" is the
// question incident review and policy tuning share; this is the one screen for both.
const KIND_LABEL = { prompt: "prompt", response: "reply", tool: "tool call", inbound: "inbound content",
                     chain: "attack chain", contain: "contained", release: "released", commit: "commit" };
function FlightRecorder({ actor, days, onClose }) {
  const [rec, setRec] = useState(null);
  const [i, setI] = useState(0);
  const [err, setErr] = useState(null);
  const [policy, setPolicy] = useState({ block_severity: "high", mcp_block_severity: "high", enforce: true, enforce_secrets: true, disabled_checks: "" });
  const [rp, setRp] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setRec(null); setRp(null); setErr(null);
    api.replayRecording(actor, days).then((r) => { setRec(r); setI(0); }).catch((e) => setErr(String(e.message || e)));
  }, [actor, days]);
  async function run() {
    setBusy(true); setErr(null);
    try {
      const pol = { ...policy, disabled_checks: policy.disabled_checks.split(/[,\s]+/).filter(Boolean) };
      setRp(await api.replayPolicy(actor, days, pol));
    } catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  }
  const steps = (rp || rec)?.steps || [];
  const cur = steps[i];
  const act = (s) => s?.replayed_action ?? s?.action;
  return (
    <div className="panel settings-card flight">
      <div className="flight-head">
        <h2>Flight recorder <span className="muted">{actor}</span></h2>
        <button type="button" className="link-btn" onClick={onClose}>close</button>
      </div>
      {err && <div className="error">{err}</div>}
      {!rec && !err && <p className="muted">Loading…</p>}
      {rec && (
        <>
          <p className="muted" style={{ marginTop: 0 }}>
            {rec.summary.steps} steps, {rec.summary.findings} findings, {rec.summary.stopped} stopped
            {rec.summary.planted ? `, ${rec.summary.planted} acted on a planted instruction` : ""}
            {rec.summary.canary_obeyed ? `, ${rec.summary.canary_obeyed} canary obeyed` : ""}
            {rec.summary.exposures ? `, ${rec.summary.exposures} exposure${rec.summary.exposures === 1 ? "" : "s"}` : ""}
            {rec.summary.commits ? `, ${rec.summary.commits} attested commit${rec.summary.commits === 1 ? "" : "s"}` : ""}.
          </p>
          {steps.length > 0 && (
            <>
              <div className="flight-track">
                {steps.map((s, k) => (
                  <button key={k} type="button" title={`${fmtWhen(s.t)} ${KIND_LABEL[s.kind] || s.kind}`}
                          className={`flight-tick ${SEV[s.severity] || ""} ${act(s) === "block" ? "is-block" : ""} ${k === i ? "is-cur" : ""} ${s.changed ? "is-changed" : ""}`}
                          onClick={() => setI(k)} />
                ))}
              </div>
              <input type="range" min={0} max={steps.length - 1} value={i} onChange={(e) => setI(Number(e.target.value))}
                     aria-label="Step" style={{ width: "100%" }} />
              {cur && (
                <div className="flight-step">
                  <div className="flight-step-head">
                    <span className="chip">{KIND_LABEL[cur.kind] || cur.kind}</span>
                    <span className={`chip ${SEV[cur.severity] || ""}`}>{cur.severity}</span>
                    <span className="chip">{cur.action}</span>
                    {rp && cur.finding_id && (
                      <span className={`chip ${cur.changed ? "sev-high" : ""}`}>replay: {cur.replayed_action}{cur.replayed_outcome && cur.replayed_outcome !== cur.replayed_action ? ` (${cur.replayed_outcome})` : ""}</span>
                    )}
                    <span className="muted nowrap">{fmtWhen(cur.t)}</span>
                    {cur.finding_id && <a className="link-btn" href={`/app/findings/${cur.finding_id}`}>#{cur.finding_id}</a>}
                  </div>
                  <div><strong>{cur.subject || cur.kind}</strong>{cur.channel ? <span className="muted"> · {cur.channel}</span> : null}</div>
                  {cur.tainted_source && <div className="muted">Tainted: an instruction arrived from {cur.tainted_source}.</div>}
                  {cur.acted_on_planted && <div style={{ color: "var(--crit)" }}>Acted on an instruction nobody typed{cur.planted_source ? ` (${cur.planted_source})` : ""}.</div>}
                  {cur.canary && <div className="muted">Canary instruction {cur.canary}.</div>}
                  {cur.exposure && <div className="muted">Opened exposure #{cur.exposure.id} ({cur.exposure.classes}, {cur.exposure.regime}), {cur.exposure.status}.</div>}
                  {cur.kind === "commit" && <div className="muted">{cur.tool_calls} tool calls, {cur.files} files, {cur.blocked} blocked, {cur.findings} findings in the window.</div>}
                  {cur.signals?.length > 0 && (
                    <ul className="flight-signals">
                      {cur.signals.map((g, k) => (
                        <li key={k} className={rp && cur.dropped_checks?.includes(g.check) ? "muted" : ""}>
                          <span className="chip">{g.check || g.category}</span> {g.title}{g.evidence ? <code> {g.evidence}</code> : null}
                          {rp && cur.dropped_checks?.includes(g.check) ? <span className="muted"> (dropped by the policy)</span> : null}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </>
          )}
          <div className="flight-policy">
            <h3>Replay against a policy</h3>
            <div className="field-grid">
              <label>Block prompts and replies at
                <select value={policy.block_severity} onChange={(e) => setPolicy((p) => ({ ...p, block_severity: e.target.value }))}>
                  {["suspicious", "high", "critical"].map((v) => <option key={v} value={v}>{v}</option>)}
                </select></label>
              <label>Block tool calls at
                <select value={policy.mcp_block_severity} onChange={(e) => setPolicy((p) => ({ ...p, mcp_block_severity: e.target.value }))}>
                  {["suspicious", "high", "critical"].map((v) => <option key={v} value={v}>{v}</option>)}
                </select></label>
              <label className="check"><input type="checkbox" checked={policy.enforce} onChange={(e) => setPolicy((p) => ({ ...p, enforce: e.target.checked }))} /> Enforce (otherwise record only)</label>
              <label className="check"><input type="checkbox" checked={policy.enforce_secrets} onChange={(e) => setPolicy((p) => ({ ...p, enforce_secrets: e.target.checked }))} /> Confirmed leaks always block</label>
              <label className="field-wide">Checks switched off (comma-separated)
                <input placeholder="e.g. source_code_leak, unsanctioned_ai" value={policy.disabled_checks} onChange={(e) => setPolicy((p) => ({ ...p, disabled_checks: e.target.value }))} /></label>
            </div>
            <div className="form-row" style={{ gap: 10 }}>
              <button type="button" className="primary-btn slim" onClick={run} disabled={busy}>{busy ? "Replaying…" : "Replay"}</button>
              {rp && (
                <span className="muted">
                  Stopped then: {rp.summary.stopped_then}. Stopped under this policy: {rp.summary.stopped_now}. Changed: {rp.summary.changed}.
                  {rp.summary.first_stop != null ? ` First stop at step ${rp.summary.first_stop + 1}.` : " Nothing stopped."}
                </span>
              )}
            </div>
            {rp && <p className="muted" style={{ fontSize: 12 }}>{rp.summary.note}</p>}
          </div>
        </>
      )}
    </div>
  );
}

export default function Sessions() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [days, setDays] = useState(7);
  const [open, setOpen] = useState(null);      // actor whose timeline is expanded
  const [timeline, setTimeline] = useState({}); // actor -> events
  const [flight, setFlight] = useState(null);     // actor in the flight recorder

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

      {flight && <FlightRecorder actor={flight} days={days} onClose={() => setFlight(null)} />}

      {sessions.length > 0 && (
        <div className="panel settings-card">
          <h2>Actors <span className="count-pill">{sessions.length}</span></h2>
          <div className="table-scroll">
            <table className="data-table session-table">
              <thead>
                <tr><th>Peak</th><th>Actor</th><th>Events</th><th>Tools</th><th>Kill-chain stages</th><th>Last seen</th><th></th></tr>
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
                      <td className="nowrap">
                        <button type="button" className="link-btn" title="This actor's window as a recording, replayed against any policy"
                                onClick={(e) => { e.stopPropagation(); setFlight(s.actor); }}>Flight recorder</button>
                      </td>
                    </tr>
                    {open === s.actor && (
                      <tr className="session-timeline-row">
                        <td colSpan={7}>
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
