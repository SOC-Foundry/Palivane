// Agents — verifiable AI-agent identities (Phase 0). Register an agent to mint its ag_
// token; the agent presents it on capture requests so its actions are attributed to it.
// (Least-privilege role enforcement is a later phase; role is captured but not yet enforced.)
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const BLANK_ROLE = { name: "", allow_tools: "", allow_servers: "", deny: "", default_allow: false, enforce: false };
const _csv = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);

export default function Agents() {
  const [agents, setAgents] = useState(null);
  const [roles, setRoles] = useState([]);
  const [draft, setDraft] = useState({ name: "", kind: "service" });
  const [roleDraft, setRoleDraft] = useState(BLANK_ROLE);
  const [token, setToken] = useState(null);   // freshly minted/rotated token, shown once
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [a, r] = await Promise.all([api.agents(), api.agentRoles()]);
      setAgents(a.agents); setRoles(r.roles);
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function setAgentRole(a, role) {
    try { await api.agentUpdate(a.id, { role }); await load(); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }
  async function saveRole() {
    setErr(null);
    if (!roleDraft.name.trim()) { setErr("Give the role a name."); return; }
    try {
      await api.agentRoleUpsert({
        name: roleDraft.name.trim(),
        allow_tools: _csv(roleDraft.allow_tools), allow_servers: _csv(roleDraft.allow_servers),
        deny: _csv(roleDraft.deny), default_allow: roleDraft.default_allow, enforce: roleDraft.enforce });
      setRoleDraft(BLANK_ROLE); await load();
    } catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }
  async function delRole(r) {
    if (!window.confirm(`Delete role ${r.name}? Agents using it become unconstrained.`)) return;
    try { await api.agentRoleDelete(r.id); await load(); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }

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
            <thead><tr><th>Name</th><th>Kind</th><th>Role</th><th>Status</th><th>Last seen</th><th></th></tr></thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.id} style={{ opacity: a.active ? 1 : 0.5 }}>
                  <td><strong>{a.name}</strong><div className="muted" style={{ fontSize: 11 }}>{a.prefix}…</div></td>
                  <td className="muted">{a.kind}</td>
                  <td>
                    <select value={a.role || ""} onChange={(e) => setAgentRole(a, e.target.value)}>
                      <option value="">— none —</option>
                      {roles.map((r) => <option key={r.id} value={r.name}>{r.name}{r.enforce ? " (enforce)" : ""}</option>)}
                    </select>
                  </td>
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

      {/* Least-privilege roles */}
      <div className="panel settings-card">
        <h2>Roles (least-privilege)</h2>
        <p className="muted" style={{ marginTop: 0 }}>Limit which MCP tools/servers an agent may
           call. Allow-lists are globs (<code>invoices.*</code>, <code>mcp.acme.*</code>);
           <code> deny</code> wins. <strong>Monitor</strong> logs an out-of-role call as a finding;
           <strong> enforce</strong> blocks it.</p>

        {roles.length > 0 && (
          <table className="data-table" style={{ marginBottom: 16 }}>
            <thead><tr><th>Role</th><th>Allow tools</th><th>Allow servers</th><th>Deny</th><th>Mode</th><th></th></tr></thead>
            <tbody>
              {roles.map((r) => (
                <tr key={r.id}>
                  <td><strong>{r.name}</strong>{r.default_allow && <span className="muted" style={{ fontSize: 11 }}> · default-allow</span>}</td>
                  <td className="muted">{r.allow_tools.join(", ") || "—"}</td>
                  <td className="muted">{r.allow_servers.join(", ") || "—"}</td>
                  <td className="muted">{r.deny.join(", ") || "—"}</td>
                  <td>{r.enforce
                    ? <span className="cat cat-secret_leak">enforce</span>
                    : <span className="cat cat-dangerous_command">monitor</span>}</td>
                  <td><button className="link-btn" style={{ color: "var(--crit)" }} onClick={() => delRole(r)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <div className="override-form">
          <div className="override-row">
            <input placeholder="role name (e.g. billing)" value={roleDraft.name}
                   onChange={(e) => setRoleDraft((d) => ({ ...d, name: e.target.value }))} />
          </div>
          <div className="override-row">
            <input placeholder="allow tools (invoices.*, read.*)" value={roleDraft.allow_tools}
                   onChange={(e) => setRoleDraft((d) => ({ ...d, allow_tools: e.target.value }))} />
            <input placeholder="allow servers (mcp.acme.*)" value={roleDraft.allow_servers}
                   onChange={(e) => setRoleDraft((d) => ({ ...d, allow_servers: e.target.value }))} />
            <input placeholder="deny (*delete*, *.prod)" value={roleDraft.deny}
                   onChange={(e) => setRoleDraft((d) => ({ ...d, deny: e.target.value }))} />
          </div>
          <div className="override-checks">
            <button type="button" className={`chip-toggle ${roleDraft.default_allow ? "on" : ""}`}
                    onClick={() => setRoleDraft((d) => ({ ...d, default_allow: !d.default_allow }))}>
              {roleDraft.default_allow ? "default-allow" : "default-deny"}
            </button>
            <button type="button" className={`chip-toggle ${roleDraft.enforce ? "on" : ""}`}
                    onClick={() => setRoleDraft((d) => ({ ...d, enforce: !d.enforce }))}>
              {roleDraft.enforce ? "enforce (block)" : "monitor (log only)"}
            </button>
          </div>
          <button className="primary-btn slim" onClick={saveRole}>Save role</button>
        </div>
      </div>
    </div>
  );
}
