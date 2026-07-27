// Simulator — dry-run content through the real detection pipeline with the org's live
// policy (overrides, disabled checks, enforcement stance). Nothing is persisted.
import { useState } from "react";
import { api } from "../api.js";

const PLANES = [
  { value: "prompt", label: "Prompt" },
  { value: "tool", label: "Tool call" },
  { value: "desktop", label: "Desktop app" },
  { value: "browser", label: "Browser" },
];

// block=red, warn=amber, allow=green, log=gray.
function outcomeClass(o) {
  if (o === "block") return "sev-critical";
  if (o === "warn") return "sev-suspicious";
  if (o === "allow") return "sev-benign";
  return "sev-low";
}
const outcomeStyle = (o) =>
  o === "log" ? { background: "rgba(140,150,165,0.15)", color: "var(--muted-2, #8a93a5)" } : undefined;

export default function Simulator() {
  const [content, setContent] = useState("");
  const [plane, setPlane] = useState("prompt");
  const [actor, setActor] = useState("");
  const [tool, setTool] = useState("");
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setErr(null); setRes(null);
    if (!content.trim()) { setErr("Paste some content to simulate."); return; }
    setBusy(true);
    try {
      const payload = { content, plane };
      if (actor.trim()) payload.actor = actor.trim();
      if (tool.trim()) payload.tool = tool.trim();
      setRes(await api.simulate(payload));
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Policy simulator</h1>
          <p className="page-sub">Test what Warden would do with a prompt, tool call, or paste —
             using your org's live policy and overrides.</p>
        </div>
      </div>

      <div className="panel settings-card">
        <label className="field-wide" style={{ display: "block" }}>
          Content
          <textarea rows={7} style={{ width: "100%", marginTop: 6 }}
            placeholder="Paste a prompt, command, or snippet to test…"
            value={content} onChange={(e) => setContent(e.target.value)} />
        </label>
        <div className="override-row" style={{ marginTop: 10 }}>
          <select value={plane} onChange={(e) => setPlane(e.target.value)} aria-label="Plane">
            {PLANES.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
          <input placeholder="Actor (optional, e.g. alice@acme.com)" value={actor}
                 onChange={(e) => setActor(e.target.value)} />
          <input placeholder="Tool (optional, e.g. claude-code)" value={tool}
                 onChange={(e) => setTool(e.target.value)} />
        </div>
        {err && <div className="error">{err}</div>}
        <button className="primary-btn slim" onClick={run} disabled={busy} style={{ marginTop: 10 }}>
          {busy ? "…" : "Run"}
        </button>
        <p className="muted" style={{ fontSize: 12.5, marginBottom: 0 }}>
          Runs the real pipeline with your org's policy — nothing is recorded.
        </p>
      </div>

      {res && (
        <div className="panel settings-card">
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
            <span className={`badge ${outcomeClass(res.outcome_monitor)}`}
                  style={{ ...outcomeStyle(res.outcome_monitor), fontSize: 13, padding: "8px 14px" }}>
              Monitor mode: {res.outcome_monitor}
            </span>
            <span className={`badge ${outcomeClass(res.outcome_enforce)}`}
                  style={{ ...outcomeStyle(res.outcome_enforce), fontSize: 13, padding: "8px 14px" }}>
              Enforce mode: {res.outcome_enforce}
            </span>
          </div>

          <p className="muted" style={{ marginBottom: 4 }}>
            Current stance for this actor/tool: <strong>{res.enforce_stance ? "enforce" : "monitor"}</strong>
            {res.matched_override && (
              <> — override: {res.matched_override.scope} <code>{res.matched_override.match}</code>
                 {res.matched_override.channel ? <> on <code>{res.matched_override.channel}</code></> : null}</>
            )}
          </p>
          <p className="muted" style={{ marginTop: 0 }}>
            Risk score: <strong>{res.risk_score}</strong> · severity:{" "}
            <span className={`badge sev-${res.severity}`}>{res.severity}</span>
            {res.force_block ? <> · <span style={{ color: "var(--crit)" }}>force block</span></> : null}
          </p>

          <h2 style={{ marginTop: 14 }}>Signals</h2>
          {(res.signals || []).length ? (
            <table className="data-table">
              <thead><tr><th>Signal</th><th>Evidence</th><th>Check</th></tr></thead>
              <tbody>
                {res.signals.map((sig, i) => (
                  <tr key={i}>
                    <td>
                      <div>{sig.title}</div>
                      {sig.detail && <div className="muted" style={{ fontSize: 12.5 }}>{sig.detail}</div>}
                    </td>
                    <td className="muted">{sig.evidence ? <code>{sig.evidence}</code> : "—"}</td>
                    <td className="muted"><code>{sig.check}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">No signals fired.</p>}

          {(res.remediation || []).length > 0 && (
            <>
              <h2 style={{ marginTop: 14 }}>Remediation</h2>
              <ul>
                {res.remediation.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}
