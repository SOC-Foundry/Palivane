// Agents — verifiable AI-agent identities (Phase 0). Register an agent to mint its ag_
// token; the agent presents it on capture requests so its actions are attributed to it.
// (Least-privilege role enforcement is a later phase; role is captured but not yet enforced.)
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

export default function Agents() {
  const [agents, setAgents] = useState(null);
  const [draft, setDraft] = useState({ name: "", kind: "service" });
  const [token, setToken] = useState(null);   // freshly minted/rotated token, shown once
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try { setAgents((await api.agents()).agents); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function create() {
    setErr(null);
    if (!draft.name.trim()) { setErr("Give the agent a name."); return; }
    setBusy(true);
    try {
      const r = await api.agentCreate({ name: draft.name.trim(), kind: draft.kind });
      setToken({ name: r.name, token: r.token });
      setDraft({ name: "", kind: "service" });
      await load();
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
    finally { setBusy(false); }
  }
  async function rotate(a) {
    if (!window.confirm(`Rotate ${a.name}'s token? The current token stops working immediately.`)) return;
    try { const r = await api.agentRotate(a.id); setToken({ name: r.name, token: r.token }); await load(); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }
  async function disable(a) {
    if (!window.confirm(`Disable ${a.name}? Its token will be rejected.`)) return;
    try { await api.agentDelete(a.id); await load(); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Agents</h1>
          <p className="page-sub">Verifiable identities for your AI agents. An agent presents its
             <code> ag_</code> token on capture requests (as <code>X-Warden-Token</code>, or an
             <code> X-Warden-Agent</code> header alongside a shared key) and its actions are
             attributed to it across Findings and the Scan log.</p>
        </div>
      </div>

      {err && <div className="error">{err}</div>}
      {token && (
        <div className="panel settings-card" style={{ borderColor: "rgba(124,108,255,.5)" }}>
          <h2>Token for {token.name}</h2>
          <p className="muted" style={{ marginTop: 0 }}>Copy it now — it's shown <strong>once</strong> and only its hash is stored.</p>
          <code style={{ display: "block", padding: "10px 12px", background: "var(--panel-2)",
                         border: "1px solid var(--border)", borderRadius: 8, wordBreak: "break-all" }}>{token.token}</code>
          <button className="ghost-btn" style={{ marginTop: 10 }} onClick={() => setToken(null)}>Done</button>
        </div>
      )}

      <div className="panel settings-card">
        <h2>Register an agent</h2>
        <div className="override-row">
          <input placeholder="agent name (e.g. billing-bot)" value={draft.name}
                 onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))} />
          <select value={draft.kind} onChange={(e) => setDraft((d) => ({ ...d, kind: e.target.value }))}>
            <option value="service">service (autonomous)</option>
            <option value="interactive">interactive (human-in-the-loop)</option>
          </select>
          <button className="primary-btn slim" onClick={create} disabled={busy}>{busy ? "…" : "Create agent"}</button>
        </div>
      </div>

      <div className="panel settings-card">
        <h2>Agents</h2>
        {agents && agents.length ? (
          <table className="data-table">
            <thead><tr><th>Name</th><th>Kind</th><th>Prefix</th><th>Status</th><th>Last seen</th><th></th></tr></thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.id} style={{ opacity: a.active ? 1 : 0.5 }}>
                  <td><strong>{a.name}</strong></td>
                  <td className="muted">{a.kind}</td>
                  <td><code>{a.prefix}…</code></td>
                  <td>{a.active
                    ? <span className="cat cat-unsanctioned_ai">active</span>
                    : <span className="cat cat-secret_leak">disabled</span>}</td>
                  <td className="muted">{a.last_seen ? a.last_seen.slice(0, 16).replace("T", " ") : "—"}</td>
                  <td>
                    <button className="link-btn" onClick={() => rotate(a)}>Rotate</button>
                    {a.active && <button className="link-btn" style={{ marginLeft: 12, color: "var(--crit)" }}
                                         onClick={() => disable(a)}>Disable</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="muted">No agents yet. Register one to give an AI agent a verifiable identity.</p>}
      </div>
    </div>
  );
}
