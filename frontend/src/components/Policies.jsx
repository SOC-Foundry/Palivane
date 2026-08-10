// Policies — enable/disable each detection check per tenant, grouped by area, with presets.
// Toggling writes tenant.disabled_checks (PATCH /api/tenant); the engine drops signals for
// disabled checks on the next scan. Changes apply immediately.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

// Preset -> the set of checks it DISABLES. "Strict" = everything on. "Balanced" mirrors the
// common default. "Monitor" keeps every check recording (blocking is governed by mode, not
// by turning checks off), so it also disables nothing — presets are a quick reset to "all on"
// plus room to grow per-preset later.
const PRESET_DISABLED = { strict: [], balanced: [], monitor: [] };

const BLANK = { scope: "group", match: "", channel: "", label: "", disabled_checks: [], enforce: "inherit" };

// How long ago an ISO timestamp was, coarsely — for the exceptions queue.
function age(ts) {
  if (!ts) return "—";
  const ms = Date.now() - new Date(ts).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

export default function Policies({ tenant, onTenant }) {
  const [cat, setCat] = useState(null);
  const [saving, setSaving] = useState("");
  const [err, setErr] = useState(null);
  const [flash, setFlash] = useState(null);
  const [draft, setDraft] = useState(BLANK);   // new-override form
  const [exceptions, setExceptions] = useState(null);
  const [showResolved, setShowResolved] = useState(false);
  const [note, setNote] = useState("");        // shared approve/deny note
  const [analytics, setAnalytics] = useState(null);

  const load = useCallback(async () => {
    try { setCat(await api.policies()); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const loadExceptions = useCallback(async () => {
    try {
      const r = await api.exceptions(showResolved ? "all" : "pending");
      setExceptions(r.exceptions || []);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, [showResolved]);
  useEffect(() => { loadExceptions(); }, [loadExceptions]);

  useEffect(() => {
    api.policyAnalytics(30).then(setAnalytics).catch(() => setAnalytics(null));
  }, []);

  async function resolveException(id, action) {
    setErr(null); setSaving(`exc:${id}`);
    try {
      const payload = { action };
      if (note.trim()) payload.note = note.trim();
      await api.exceptionResolve(id, payload);
      setNote("");
      await loadExceptions();
      if (action === "approve") await load();   // approval creates an override — refresh the list
      setFlash(action === "approve" ? "Exception approved — override created." : "Exception denied.");
      setTimeout(() => setFlash(null), 2500);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setSaving(""); }
  }

  const disabledSet = () => new Set((cat?.checks || []).filter((c) => !c.enabled).map((c) => c.key));

  async function persist(nextDisabled, label) {
    setErr(null); setSaving(label || "…");
    try {
      const t = await api.updateTenant({ disabled_checks: [...nextDisabled] });
      onTenant?.(t);
      await load();
      setFlash("Saved — applies to new scans immediately.");
      setTimeout(() => setFlash(null), 2500);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setSaving(""); }
  }

  function toggle(key) {
    const d = disabledSet();
    d.has(key) ? d.delete(key) : d.add(key);
    persist(d, key);
  }

  async function downloadCompliance() {
    setErr(null);
    try {
      const csv = await api.complianceCsv();
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      const a = document.createElement("a");
      a.href = url; a.download = "palivane-compliance.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setErr("Couldn't build the compliance report: " + String(e.message || e)); }
  }
  function applyPreset(name) {
    persist(new Set(PRESET_DISABLED[name] || []), `preset:${name}`);
  }

  async function addOverride() {
    setErr(null);
    if (!draft.match.trim()) { setErr("Enter an email (user) or a pattern (group)."); return; }
    setSaving("override");
    try {
      await api.policyOverrideUpsert({ ...draft, match: draft.match.trim() });
      setDraft(BLANK);
      await load();
      setFlash("Override saved.");
      setTimeout(() => setFlash(null), 2500);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setSaving(""); }
  }
  async function delOverride(id) {
    try { await api.policyOverrideDelete(id); await load(); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }
  function toggleDraftCheck(key) {
    setDraft((d) => ({ ...d, disabled_checks: d.disabled_checks.includes(key)
      ? d.disabled_checks.filter((k) => k !== key) : [...d.disabled_checks, key] }));
  }
  const checkLabel = (key) => (cat?.checks.find((c) => c.key === key)?.label || key);

  if (!cat) return <div className="connect"><p className="muted">Loading policies…</p></div>;

  const total = cat.checks.length;
  const on = cat.checks.filter((c) => c.enabled).length;

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Policies</h1>
          <p className="page-sub">Choose which detection checks run for your organization.
             <strong> {on} of {total}</strong> enabled — changes apply immediately to new scans.</p>
        </div>
        <div className="head-actions">
          {["strict", "balanced", "monitor"].map((p) => (
            <button key={p} className="ghost-btn" disabled={!!saving}
                    onClick={() => applyPreset(p)} style={{ textTransform: "capitalize" }}>
              {p}
            </button>
          ))}
          <button className="ghost-btn" onClick={downloadCompliance}
                  title="OWASP LLM Top 10, OWASP Agentic, NIST AI RMF, EU AI Act — coverage from your live policy">
            Compliance report (CSV)
          </button>
        </div>
      </div>

      {err && <div className="error">{err}</div>}
      {flash && <div className="hint" style={{ color: "var(--benign)" }}>{flash}</div>}

      {cat.groups.map((group) => (
        <div key={group} className="panel settings-card">
          <h2>{group}</h2>
          <div className="policy-list">
            {cat.checks.filter((c) => c.group === group).map((c) => (
              <div className="policy-row" key={c.key}>
                <div className="policy-text">
                  <div className="policy-name">
                    {c.label}
                    <span className={`policy-state ${c.enabled ? "on" : "off"}`}>
                      {c.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                  <div className="policy-desc">{c.desc}</div>
                  {c.frameworks && Object.keys(c.frameworks).length > 0 && (
                    <div className="policy-frameworks">
                      {(c.frameworks.owasp_llm || []).map((code) => (
                        <span key={code} className="fw-chip fw-owasp" title="OWASP Top 10 for LLM Applications">{code}</span>
                      ))}
                      {(c.frameworks.owasp_agentic || []).map((code) => (
                        <span key={code} className="fw-chip fw-agentic" title="OWASP Agentic AI: Threats & Mitigations">Agentic {code}</span>
                      ))}
                      {(c.frameworks.nist_ai_rmf || []).map((code) => (
                        <span key={code} className="fw-chip fw-nist" title="NIST AI RMF 1.0">NIST {code}</span>
                      ))}
                      {(c.frameworks.eu_ai_act || []).map((code) => (
                        <span key={code} className="fw-chip fw-eu" title="EU AI Act (high-risk obligations)">EU {code}</span>
                      ))}
                    </div>
                  )}
                </div>
                <button
                  role="switch" aria-checked={c.enabled} aria-label={`Toggle ${c.label}`}
                  className={`toggle ${c.enabled ? "toggle-on" : ""}`}
                  disabled={saving === c.key}
                  onClick={() => toggle(c.key)}>
                  <span className="toggle-knob" />
                </button>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Per-user / per-group overrides */}
      <div className="panel settings-card">
        <h2>Per-user &amp; per-group overrides</h2>
        <p className="muted" style={{ marginTop: 0 }}>Give a specific user or group its own check
           set — it <strong>replaces</strong> the org default for matched people. A user match is
           an exact email; a group match is a pattern like <code>*@contractors.acme.com</code>,
           <code> *intern*</code>, or <code>svc-*@acme.com</code>. User beats group; the most
           specific group wins. Optionally scope an override to one tool
           (e.g. <code>claude-code</code>, <code>claude-*</code>) — it then applies only to
           captures on that tool, and beats an any-tool override for the same person.</p>

        {(cat.overrides || []).length > 0 && (
          <table className="data-table" style={{ marginBottom: 16 }}>
            <thead><tr><th>Scope</th><th>Match</th><th>Tool</th><th>Enforcement</th><th>Label</th><th>Disabled checks</th><th></th></tr></thead>
            <tbody>
              {cat.overrides.map((o) => (
                <tr key={o.id}>
                  <td><span className={`cat ${o.scope === "user" ? "cat-secret_leak" : "cat-unsanctioned_ai"}`}>{o.scope}</span></td>
                  <td><code>{o.match}</code></td>
                  <td className="muted">{o.channel ? <code>{o.channel}</code> : "any"}</td>
                  <td className="muted">{o.enforce === true ? "enforce" : o.enforce === false ? "monitor" : "—"}</td>
                  <td className="muted">{o.label || "—"}</td>
                  <td className="muted">{o.disabled_checks.length
                    ? o.disabled_checks.map(checkLabel).join(", ")
                    : <span style={{ color: "var(--benign)" }}>all checks on</span>}</td>
                  <td><button className="link-btn" onClick={() => delOverride(o.id)}>Remove</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="override-form">
          <div className="override-row">
            <select value={draft.scope} onChange={(e) => setDraft((d) => ({ ...d, scope: e.target.value }))}>
              <option value="group">Group</option>
              <option value="user">User</option>
            </select>
            <input placeholder={draft.scope === "user" ? "alice@acme.com" : "*@contractors.acme.com"}
                   value={draft.match} onChange={(e) => setDraft((d) => ({ ...d, match: e.target.value }))} />
            <input placeholder="Tool (optional, e.g. claude-code)" value={draft.channel}
                   onChange={(e) => setDraft((d) => ({ ...d, channel: e.target.value }))} />
            <select value={draft.enforce} aria-label="Enforcement"
                    onChange={(e) => setDraft((d) => ({ ...d, enforce: e.target.value }))}>
              <option value="inherit">Enforcement: inherit</option>
              <option value="on">Enforcement: enforce</option>
              <option value="off">Enforcement: monitor</option>
            </select>
            <input placeholder="Label (optional)" value={draft.label}
                   onChange={(e) => setDraft((d) => ({ ...d, label: e.target.value }))} />
          </div>
          <div className="override-checks">
            <span className="muted" style={{ fontSize: 12.5 }}>Disable for this {draft.scope}:</span>
            {cat.checks.map((c) => (
              <button key={c.key} type="button"
                      className={`chip-toggle ${draft.disabled_checks.includes(c.key) ? "on" : ""}`}
                      onClick={() => toggleDraftCheck(c.key)}>{c.label}</button>
            ))}
          </div>
          <button className="primary-btn slim" onClick={addOverride} disabled={saving === "override"}>
            {saving === "override" ? "…" : "Add override"}
          </button>
        </div>
      </div>

      {/* Exception requests — users asking to allow a blocked destination/category. */}
      <div className="panel settings-card">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
          <h2 style={{ margin: 0 }}>Exceptions</h2>
          <label className="muted" style={{ fontSize: 12.5, display: "flex", alignItems: "center", gap: 6 }}>
            <input type="checkbox" checked={showResolved}
                   onChange={(e) => setShowResolved(e.target.checked)} />
            Show resolved
          </label>
        </div>
        <p className="muted" style={{ marginTop: 6 }}>Requests from users to allow something the
           policy flagged. Approving creates a scoped override for the requesting user.</p>

        {exceptions === null ? (
          <p className="muted">Loading exceptions…</p>
        ) : exceptions.length === 0 ? (
          <p className="muted">{showResolved ? "No exception requests." : "No pending exception requests."}</p>
        ) : (
          <>
            <table className="data-table">
              <thead><tr><th>Actor</th><th>Destination</th><th>Categories</th><th>Reason</th><th>Age</th><th>Status</th><th></th></tr></thead>
              <tbody>
                {exceptions.map((x) => (
                  <tr key={x.id}>
                    <td>{x.actor}</td>
                    <td className="muted">{x.destination ? <code>{x.destination}</code> : "—"}</td>
                    <td className="muted">{(x.categories || []).join(", ") || "—"}</td>
                    <td className="muted">{x.reason || "—"}</td>
                    <td className="muted">{age(x.created_at)}</td>
                    <td>
                      {x.status === "pending"
                        ? <span className="badge sev-suspicious">pending</span>
                        : x.status === "approved"
                          ? <span className="badge sev-benign">approved</span>
                          : <span className="badge sev-critical">denied</span>}
                    </td>
                    <td>
                      {x.status === "pending" && (
                        <span style={{ display: "flex", gap: 8 }}>
                          <button className="link-btn" disabled={saving === `exc:${x.id}`}
                                  onClick={() => resolveException(x.id, "approve")}>Approve</button>
                          <button className="link-btn" disabled={saving === `exc:${x.id}`}
                                  onClick={() => resolveException(x.id, "deny")}>Deny</button>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {exceptions.some((x) => x.status === "pending") && (
              <input style={{ marginTop: 10, width: "100%" }} value={note}
                     placeholder="Optional note — attached to the next approve/deny"
                     onChange={(e) => setNote(e.target.value)} />
            )}
          </>
        )}
      </div>

      {/* Check activity — findings vs. dismissals per check over the last 30 days. */}
      <div className="panel settings-card">
        <h2>Check activity (30d)</h2>
        <p className="muted" style={{ marginTop: 6 }}>A high dismiss rate means the check is
           mostly generating noise for your org — a candidate to tune or disable.</p>
        {analytics === null ? (
          <p className="muted">No activity data available.</p>
        ) : (analytics.checks || []).length === 0 ? (
          <p className="muted">No check activity in the last {analytics.days} days.</p>
        ) : (
          <table className="data-table">
            <thead><tr><th>Check</th><th>Findings</th><th>Dismissed</th><th>Dismiss rate</th></tr></thead>
            <tbody>
              {analytics.checks.map((c) => (
                <tr key={c.check}>
                  <td><code>{c.check}</code></td>
                  <td>{c.findings}</td>
                  <td>{c.dismissed}</td>
                  <td className={c.dismiss_rate >= 0.5 ? "" : "muted"}
                      style={c.dismiss_rate >= 0.5 ? { color: "var(--susp)" } : undefined}>
                    {Math.round((c.dismiss_rate || 0) * 100)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
