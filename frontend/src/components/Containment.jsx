// Containment: the admin's "stop this now". One action stops a person, a device, a registered
// agent or the whole org on every plane: the hooks deny every tool call and prompt, the proxy and
// extension block AI sites, the gateway refuses model calls. A contained device keeps blocking
// while it cannot reach Palivane (it fails closed), so cutting the machine off is not a way out.
// Every containment ends, at its expiry or on release; both are audited and listed here.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { IconLock } from "./icons.jsx";

export const SCOPE_LABEL = { user: "person", device: "device", agent: "agent", org: "whole org" };
const DURATIONS = [[1, "1 hour"], [4, "4 hours"], [24, "24 hours"], [72, "3 days"], [168, "7 days"]];

function fmtWhen(ts) {
  if (!ts) return "-";
  const d = new Date(ts.endsWith("Z") ? ts : ts + "Z");
  return Number.isNaN(d.getTime()) ? String(ts)
    : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

/** The confirm-and-reason form. `scope`/`target` are fixed by the caller (a finding's sender, a
 *  device row) or chosen here when `pick` is true (the Fleet panel's "Contain…" button). */
export function ContainDialog({ scope: fixedScope, target: fixedTarget, label, pick = false, onDone, onCancel }) {
  const [scope, setScope] = useState(fixedScope || "user");
  const [target, setTarget] = useState(fixedTarget || "");
  const [hours, setHours] = useState(24);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function go() {
    setBusy(true); setErr("");
    try {
      const row = await api.contain({ scope, target: scope === "org" ? "" : target.trim(), hours, reason });
      onDone?.(row);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }
  const what = scope === "org" ? "everything in this organization" : (label || target || `this ${SCOPE_LABEL[scope]}`);

  return (
    <div className="contain-dialog" onClick={(e) => e.stopPropagation()}>
      <h4><IconLock /> Contain {what}</h4>
      {pick && (
        <div className="contain-pick">
          <select value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="user">a person (email)</option>
            <option value="device">a device (key id)</option>
            <option value="agent">an agent (name)</option>
            <option value="org">the whole org</option>
          </select>
          {scope !== "org" && (
            <input value={target} onChange={(e) => setTarget(e.target.value)}
                   placeholder={scope === "user" ? "person@company.com" : scope === "device" ? "device key id (Connections)" : "agent name"} />
          )}
        </div>
      )}
      <p className="muted contain-what">
        Stops AI tools and agents on every plane now: prompts and tool calls are denied, AI sites
        blocked, model calls refused. Holds even if the device goes offline. The person is told they
        were paused by security, not why.
      </p>
      <div className="contain-row">
        <label>For <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          {DURATIONS.map(([h, l]) => <option key={h} value={h}>{l}</option>)}
        </select></label>
        <input className="contain-reason" value={reason} onChange={(e) => setReason(e.target.value)}
               placeholder="Reason, for the record (optional)" maxLength={500} />
      </div>
      {err && <p className="mine-err">{err}</p>}
      <div className="contain-actions">
        <button type="button" className="danger-btn slim" disabled={busy || (scope !== "org" && !target.trim())}
                onClick={go}>{busy ? "Containing…" : scope === "org" ? "Contain the whole org" : "Contain now"}</button>
        <button type="button" className="ghost-btn slim" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

/** Fleet panel: active containments (and the ended ones on request), release, start a new one. */
export default function ContainmentPanel() {
  const [rows, setRows] = useState(null);
  const [all, setAll] = useState(false);
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(() => api.containments(all)
    .then((r) => setRows(r.containments)).catch((e) => setErr(String(e.message || e))), [all]);
  useEffect(() => { load(); }, [load]);

  async function release(id) {
    try { await api.releaseContainment(id); await load(); }
    catch (e) { setErr(String(e.message || e)); }
  }
  async function ticket(id) {
    try { await api.containmentTicket(id); await load(); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }
  const active = (rows || []).filter((r) => r.active);
  const quiet = active.filter((r) => r.quiet);

  return (
    <div className={`panel settings-card contain-panel${active.length ? " on" : ""}`}>
      <h2>
        Containment {active.length > 0 && <span className="count-pill">{active.length}</span>}
        <span className="head-actions" style={{ marginLeft: "auto" }}>
          <label className="muted" style={{ fontSize: 12 }}>
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> show ended
          </label>
          <button type="button" className="danger-btn slim" onClick={() => setOpen(true)}><IconLock /> Contain…</button>
        </span>
      </h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Stop a person, a device, an agent or the whole org on every plane in one action, for a set
        time, pending review. Each one is audited; release it here when the review is done.
      </p>
      {open && <ContainDialog pick onDone={() => { setOpen(false); load(); }} onCancel={() => setOpen(false)} />}
      {err && <div className="error">{err}</div>}
      {quiet.length > 0 && (
        <div className="contain-quiet">
          {quiet.length === 1 ? "A contained target has gone quiet" : `${quiet.length} contained targets have gone quiet`}:
          nothing stopped since containment began and no check-in since, at an hour they are
          usually active. The device may have been cut off from Palivane, or had its hooks
          removed. Worth a look.
        </div>
      )}
      {rows && rows.length === 0 && <p className="muted">Nothing is contained.</p>}
      {rows && rows.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>Who / what</th><th>Scope</th><th>Since</th><th>Until</th><th>Stopped</th><th>By</th><th>Reason</th><th>Ticket</th><th></th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={r.active ? (r.quiet ? "row-quiet" : "row-on") : "row-ended"}>
                  <td><strong>{r.label || r.target}</strong>{r.quiet && <span className="badge sev-suspicious" style={{ marginLeft: 8 }}>quiet</span>}</td>
                  <td className="muted">{SCOPE_LABEL[r.scope] || r.scope}</td>
                  <td className="muted nowrap">{fmtWhen(r.created_at)}</td>
                  <td className="muted nowrap">{r.released_at ? `released ${fmtWhen(r.released_at)}` : fmtWhen(r.expires_at)}</td>
                  <td title={r.last_blocked_at ? `last ${fmtWhen(r.last_blocked_at)}` : undefined}>{r.blocked}</td>
                  <td className="muted">{r.released_by || r.created_by}</td>
                  <td className="muted cell-clip" title={r.reason}>{r.reason || "-"}</td>
                  <td>{r.ticket ? <a href={r.ticket.url} target="_blank" rel="noreferrer">{r.ticket.key}</a>
                                : <button type="button" className="link-btn" onClick={() => ticket(r.id)}>create</button>}</td>
                  <td>{r.active && <button type="button" className="link-btn" onClick={() => release(r.id)}>Release</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
