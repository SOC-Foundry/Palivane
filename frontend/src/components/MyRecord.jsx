// Your record: what Palivane holds about the signed-in person, told to them. The one view
// in the product that faces the employee rather than the security team: what was captured,
// what was stopped, whether their text is stored and for how long, which sensors report from
// their machines, whether they are contained, what regulated data of theirs left, and a
// one-click export that answers a data-subject request. Nothing here grants anything.
import { useEffect, useState } from "react";
import { api } from "../api.js";
import { IconShield } from "./icons.jsx";

function when(iso) {
  if (!iso) return "never";
  const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  const m = Math.round((Date.now() - d.getTime()) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return d.toLocaleDateString();
}

const CAT = {
  secret_leak: "a credential", pii_exposure: "personal data", phi_exposure: "health data",
  source_code_leak: "source code", confidential_data: "confidential content",
  unsanctioned_ai: "an unapproved AI tool", dangerous_command: "a dangerous command",
  prompt_injection: "a prompt injection", jailbreak: "a jailbreak attempt",
  sensitive_resource_access: "a sensitive file", dependency_risk: "a risky package",
  data_exfiltration: "data extraction", tool_poisoning: "a poisoned tool",
};

export default function MyRecord() {
  const [r, setR] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.myRecord().then(setR).catch((e) => setErr(String(e.message || e))); }, []);

  async function download() {
    setBusy(true);
    try {
      const { blob, name } = await api.exportMyRecord();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    } catch (e) { setErr(String(e.message || e)); }
    finally { setBusy(false); }
  }

  const c = r?.captured;
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Your record</h1>
          <p className="page-sub">What Palivane holds about you: what it captured, what it stopped, what it stores,
             and what left the organisation. Export it any time.</p>
        </div>
        <div className="head-actions">
          <button type="button" className="primary-btn slim" onClick={download} disabled={busy || !r}>
            {busy ? "Preparing…" : "Download my record (JSON)"}
          </button>
        </div>
      </div>
      {err && <div className="error">{err}</div>}
      {!r && !err && <p className="muted">Loading…</p>}
      {r && (
        <>
          <div className="panel mine-section">
            <h2><IconShield /> In the last {r.window_days} days</h2>
            <div className="usage-stats">
              <div><span className="usage-n">{c.findings}</span><span className="usage-l">findings about you</span></div>
              <div><span className="usage-n">{c.stopped}</span><span className="usage-l">stopped before leaving</span></div>
              <div><span className="usage-n">{c.recorded}</span><span className="usage-l">recorded, not stopped</span></div>
              <div><span className="usage-n">{c.answered_by_you}</span><span className="usage-l">answered by you</span></div>
            </div>
            {c.findings === 0 ? (
              <p className="muted">Nothing was flagged in your AI use in this window{c.all_time ? ` (${c.all_time} earlier, all time)` : ""}.</p>
            ) : (
              <p className="muted">
                What they were about: {Object.entries(c.by_category).map(([k, n]) => `${CAT[k] || k} (${n})`).join(", ")}.
                {" "}Through: {Object.entries(c.by_tool).map(([k, n]) => `${k} (${n})`).join(", ") || "-"}.
                {" "}First {when(c.first_seen)}, latest {when(c.last_seen)}.
              </p>
            )}
          </div>

          <div className="panel mine-section">
            <h2>What is stored about you</h2>
            <p>{r.stored.what}</p>
            <p className="muted">{r.stored.how_long}{r.stored.evidence_context ? " A short excerpt around each match is kept for context." : ""}</p>
          </div>

          <div className="panel mine-section">
            <h2>Where the sensors are</h2>
            {r.sensors.length === 0 ? (
              <p className="muted">No sensor has reported under your address. Either nothing is installed on your machines, or they report under a device name.</p>
            ) : (
              <table className="data-table">
                <thead><tr><th>Plane</th><th>Sensor</th><th>Tool</th><th>Last seen</th></tr></thead>
                <tbody>
                  {r.sensors.map((s, i) => (
                    <tr key={i}><td>{s.plane}</td><td className="muted">{s.client}</td><td className="muted">{s.tool || "-"}</td><td className="muted">{when(s.last_seen)}</td></tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="panel mine-section">
            <h2>Right now</h2>
            {r.contained ? (
              <p className="mine-err">You are contained: your AI use is paused on every plane until {when(r.contained.expires_at)}{r.contained.reason ? ` (${r.contained.reason})` : ""}. Contact your security team.</p>
            ) : (
              <p className="muted">You are not contained. Your AI use is subject to the organisation's policy like everyone else's.</p>
            )}
          </div>

          <div className="panel mine-section">
            <h2>What left the organisation</h2>
            {r.left_the_org.total === 0 ? (
              <p className="muted">No regulated data of yours is recorded as having reached an AI provider.</p>
            ) : (
              <>
                <p className="muted">{r.left_the_org.open} open of {r.left_the_org.total}. Each is on the organisation's exposure register with its regulatory clock.</p>
                <table className="data-table">
                  <thead><tr><th>What</th><th>Where</th><th>When</th><th>Regime</th><th>Status</th></tr></thead>
                  <tbody>
                    {r.left_the_org.items.map((e) => (
                      <tr key={e.id}><td>{e.classes.map((k) => CAT[k] || k).join(", ")}</td><td className="muted">{e.destination}</td><td className="muted">{when(e.opened_at)}</td><td className="muted">{e.regime}</td><td>{e.status}</td></tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>

          <div className="panel mine-section">
            <h2>Your rights</h2>
            <p className="muted">{r.rights.answer}</p>
            <p className="muted">The export is the full record in machine-readable form, suitable for a data-subject
               access request. Questions about this record go to your organisation's administrator; about Palivane
               itself, to {r.rights.contact}.</p>
          </div>
        </>
      )}
    </div>
  );
}
