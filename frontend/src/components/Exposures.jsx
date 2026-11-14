// The exposure register: regulated data that reached an AI provider, with the regulatory
// clock running (72 hours under GDPR Art. 33). Opened by the gateway at the moment of
// transmission, worked here, closed by a review that says it was not a breach.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconRefresh } from "./icons.jsx";

const CLASS_LABEL = { pii_exposure: "personal data", phi_exposure: "health data" };
const STATUS_LABEL = { open: "open", acknowledged: "acknowledged", notified: "notified", closed: "closed" };

function when(ts) {
  if (!ts) return "-";
  const d = new Date(ts.endsWith("Z") ? ts : ts + "Z");
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function clock(e) {
  if (e.status === "closed") return <span className="muted">closed{e.closed_reason ? ` (${e.closed_reason.replace("_", " ")})` : ""}</span>;
  if (e.status === "notified") return <span className="muted">notified {when(e.notified_at)}</span>;
  if (e.hours_left === null) return "-";
  if (e.hours_left < 0) return <span className="badge sev-critical">{Math.abs(Math.round(e.hours_left))}h overdue</span>;
  const cls = e.hours_left < 12 ? "sev-critical" : e.hours_left < 36 ? "sev-suspicious" : "sev-low";
  return <span className={`badge ${cls}`}>{Math.round(e.hours_left)}h left</span>;
}

export default function Exposures() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [open, setOpen] = useState(null);
  const [copied, setCopied] = useState(null);

  const load = useCallback(async () => {
    setErr(null); setBusy(true);
    try { setData(await api.exposures(showClosed)); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }, [showClosed]);
  useEffect(() => { load(); }, [load]);

  async function setStatus(e, status) {
    try { await api.setExposureStatus(e.id, { status }); await load(); }
    catch (x) { setErr(String(x.message || x).replace(/^\d+:\s*/, "")); }
  }

  async function ticket(e) {
    setErr(null);
    try { await api.exposureTicket(e.id); await load(); }
    catch (x) { setErr(String(x.message || x).replace(/^\d+:\s*/, "")); }
  }
  async function copy(e) {
    try { await navigator.clipboard.writeText(e.draft); setCopied(e.id); setTimeout(() => setCopied(null), 2000); }
    catch { setOpen(e.id); }
  }

  const rows = data?.exposures || [];
  const openCount = rows.filter((e) => e.status !== "closed").length;
  const overdue = rows.filter((e) => e.overdue).length;

  return (
    <div className="connect page-wide">
      <div className="content-head">
        <div>
          <h1 className="page-title">Exposures</h1>
          <p className="page-sub">Regulated data that reached an AI provider, with the regulatory clock
             running from the moment it left. Each row is a finding where personal or health data went
             out and was not stopped. Work it here; a review that says the detector was wrong closes it.</p>
        </div>
        <div className="head-actions">
          <label className="muted" style={{ fontSize: 12 }}>
            <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> show closed
          </label>
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
              <div><span className="usage-n">{openCount}</span><span className="usage-l">open</span></div>
              <div><span className="usage-n" style={overdue ? { color: "var(--crit)" } : undefined}>{overdue}</span><span className="usage-l">overdue</span></div>
              <div><span className="usage-n">{rows.filter((e) => e.status === "notified").length}</span><span className="usage-l">notified</span></div>
            </div>
          </div>

          <div className="panel settings-card">
            {rows.length === 0 ? (
              <p className="muted">{showClosed ? "No exposures on record." : "Nothing open. Regulated data that leaves for a provider will appear here with its clock."}</p>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>Clock</th><th>What</th><th>Who</th><th>Where</th><th>Left at</th><th>Regime</th><th>Status</th><th>Ticket</th><th></th></tr>
                  </thead>
                  <tbody>
                    {rows.map((e) => [
                      <tr key={e.id} className={e.overdue ? "row-quiet" : undefined}>
                        <td>{clock(e)}</td>
                        <td>{e.classes.map((c) => CLASS_LABEL[c] || c).join(", ")}
                          <div className="pr-sub muted"><a className="link-btn" href={`/app/findings/${e.finding_id}`}>finding #{e.finding_id}</a>
                            {e.finding?.severity && <> · {e.finding.severity}</>}</div>
                        </td>
                        <td>{e.actor || "-"}</td>
                        <td className="muted">{e.destination || e.surface}</td>
                        <td className="muted">{when(e.opened_at)}</td>
                        <td className="muted">{e.regime}</td>
                        <td>
                          {e.status === "closed" && e.closed_reason === "false_positive" ? (
                            <span className="muted">not a breach</span>
                          ) : (
                            <select value={e.status} onChange={(ev) => setStatus(e, ev.target.value)} aria-label={`Status of exposure ${e.id}`}>
                              {Object.entries(STATUS_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
                            </select>
                          )}
                        </td>
                        <td>
                          {e.ticket ? <a href={e.ticket.url} target="_blank" rel="noreferrer">{e.ticket.key}</a>
                                    : <button type="button" className="link-btn" onClick={() => ticket(e)} disabled={busy}>create</button>}
                        </td>
                        <td>
                          <button type="button" className="link-btn" onClick={() => copy(e)}>{copied === e.id ? "copied" : "copy draft"}</button>
                          {" "}
                          <button type="button" className="link-btn" onClick={() => setOpen(open === e.id ? null : e.id)}>{open === e.id ? "hide" : "draft"}</button>
                        </td>
                      </tr>,
                      open === e.id && (
                        <tr key={`${e.id}|draft`}>
                          <td colSpan={9}>
                            <pre style={{ whiteSpace: "pre-wrap", fontSize: 12.5, margin: 0 }}>{e.draft}</pre>
                          </td>
                        </tr>
                      ),
                    ])}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
      {!data && !err && <p className="muted">Loading exposures...</p>}
    </div>
  );
}
