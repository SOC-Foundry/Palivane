// Coverage, find unmanaged/shadow AI use by comparing an IdP/CASB "who used AI" list to
// the actors Palivane actually captured. The gap = the shadow set. (Agentless: you can't
// monitor a device you don't manage, so you find it by what's missing.)
import { useState } from "react";
import { api } from "../api.js";

// Parse "actor,tool" CSV lines OR a JSON array of {actor,tool}.
function parseEvents(text) {
  const t = text.trim();
  if (!t) return [];
  if (t.startsWith("[")) {
    try { return JSON.parse(t).filter((e) => e && e.actor); } catch { return null; }
  }
  return t.split("\n").map((line) => {
    const [actor, tool] = line.split(",").map((s) => (s || "").trim());
    return actor ? { actor, tool: tool || "" } : null;
  }).filter(Boolean);
}

export default function Coverage() {
  const [text, setText] = useState("");
  const [res, setRes] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setErr(null); setRes(null);
    const events = parseEvents(text);
    if (events === null) { setErr("Couldn't parse, use CSV lines `actor,tool` or a JSON array."); return; }
    if (!events.length) { setErr("Paste at least one `actor,tool` line."); return; }
    setBusy(true);
    try { setRes(await api.coverageReconcile(events)); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Coverage reconciliation</h1>
          <p className="page-sub">Paste your IdP/CASB record of who used AI tools. Palivane subtracts the
             actors it captured and returns the rest, the unmanaged / shadow set.</p>
        </div>
      </div>

      <div className="panel settings-card">
        <label className="field-wide" style={{ display: "block" }}>
          Access events, one <code>actor,tool</code> per line, or a JSON array
          <textarea rows={8} style={{ width: "100%", marginTop: 6 }}
            placeholder={"alice@acme.com,ChatGPT\nmallory@acme.com,ChatGPT"}
            value={text} onChange={(e) => setText(e.target.value)} />
        </label>
        {err && <div className="error">{err}</div>}
        <button className="primary-btn slim" onClick={run} disabled={busy}>
          {busy ? "..." : "Reconcile"}
        </button>
      </div>

      {res && (
        <div className="panel settings-card">
          <div className="usage-stats">
            <div><span className="usage-n">{res.covered}</span><span className="usage-l">covered</span></div>
            <div><span className="usage-n">{res.uncovered_count}</span><span className="usage-l">uncovered</span></div>
            <div><span className="usage-n">{res.coverage_rate != null ? Math.round(res.coverage_rate * 100) + "%" : "-"}</span>
              <span className="usage-l">coverage</span></div>
          </div>
          <h2 style={{ marginTop: 14 }}>Uncovered actors</h2>
          {res.uncovered?.length ? (
            <table className="data-table">
              <thead><tr><th>Actor</th><th>Tools</th></tr></thead>
              <tbody>
                {res.uncovered.map((u) => (
                  <tr key={u.actor}><td>{u.actor}</td><td className="muted">{(u.tools || []).join(", ")}</td></tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">Everyone in the list is covered. 🎉</p>}
        </div>
      )}
    </div>
  );
}
