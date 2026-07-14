import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

export default function Users({ currentUser }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [busyId, setBusyId] = useState(null);

  // add-user form
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [adding, setAdding] = useState(false);

  // domain capture
  const [domains, setDomains] = useState([]);
  const [joinReqs, setJoinReqs] = useState([]);
  const [newDomain, setNewDomain] = useState("");
  const [domErr, setDomErr] = useState(null);
  const [domBusy, setDomBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.users();
      setUsers(r.users);
      const [d, j] = await Promise.all([api.domains(), api.joinRequests()]);
      setDomains(d.domains);
      setJoinReqs(j.requests);
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function addUser(e) {
    e.preventDefault();
    setAdding(true); setErr(null);
    try {
      await api.createUser({ email: email.trim(), password, role });
      setEmail(""); setPassword(""); setRole("analyst");
      await load();
    } catch (e) {
      const msg = String(e.message || e);
      setErr(msg.includes("409") ? "A user with that email already exists." : msg);
    } finally {
      setAdding(false);
    }
  }

  async function patch(u, payload) {
    setBusyId(u.id); setErr(null);
    try {
      await api.updateUser(u.id, payload);
      await load();
    } catch (e) {
      // Surface the backend's guardrail message (last-admin, self-lockout, …).
      const msg = String(e.message || e).replace(/^\d+:\s*/, "");
      try { setErr(JSON.parse(msg.slice(msg.indexOf("{"))).detail || msg); }
      catch { setErr(msg); }
    } finally {
      setBusyId(null);
    }
  }

  async function domAction(fn) {
    setDomBusy(true); setDomErr(null);
    try {
      await fn();
      await load();
    } catch (e) {
      const msg = String(e.message || e).replace(/^\d+:\s*/, "");
      try { setDomErr(JSON.parse(msg.slice(msg.indexOf("{"))).detail || msg); }
      catch { setDomErr(msg); }
    } finally {
      setDomBusy(false);
    }
  }

  const activeAdmins = users.filter((u) => u.role === "admin" && u.active).length;

  return (
    <div className="users-page">
      <div className="users-head">
        <div>
          <h2 className="users-title">Team &amp; access</h2>
          <p className="users-sub">Only people you add here can sign in. Admins manage users
            and capture keys; analysts triage findings.</p>
        </div>
      </div>

      <form className="add-user panel" onSubmit={addUser}>
        <h3>Add a user</h3>
        <div className="add-user-row">
          <input type="email" placeholder="email" value={email}
                 onChange={(e) => setEmail(e.target.value)} required />
          <input type="password" placeholder="temporary password (min 8)" value={password}
                 onChange={(e) => setPassword(e.target.value)} minLength={8} required />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
          <button className="primary-btn slim" disabled={adding || !email || password.length < 8}>
            {adding ? "…" : "Add user"}
          </button>
        </div>
      </form>

      {err && <div className="error users-error">{err}</div>}

      {joinReqs.length > 0 && (
        <div className="panel">
          <h3>Join requests</h3>
          <p className="muted" style={{ fontSize: 12 }}>
            People who signed up with an email on one of your verified domains. Approving
            creates an analyst account with the password they chose — confirm out-of-band
            that the person actually made the request (mailbox ownership isn't verified).
          </p>
          <table className="users-table">
            <tbody>
              {joinReqs.map((r) => (
                <tr key={r.id}>
                  <td className="ut-email">{r.email}</td>
                  <td className="muted">{r.created_at?.slice(0, 10)}</td>
                  <td className="ta-right ut-actions">
                    <button className="mini-btn" disabled={domBusy}
                            onClick={() => domAction(() => api.approveJoin(r.id))}>
                      Approve
                    </button>
                    <button className="mini-btn danger" disabled={domBusy}
                            onClick={() => domAction(() => api.denyJoin(r.id))}>
                      Deny
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="panel">
        <h3>Claimed email domains</h3>
        <p className="muted" style={{ fontSize: 12 }}>
          Claim your company's email domain so a teammate signing up with a matching address
          is routed here as a join request instead of accidentally creating a separate
          organization. Verify ownership by adding the DNS TXT record shown below.
        </p>
        <form className="add-user-row" style={{ marginBottom: 8 }}
              onSubmit={(e) => { e.preventDefault();
                                 domAction(async () => { await api.claimDomain(newDomain.trim());
                                                         setNewDomain(""); }); }}>
          <input placeholder="example.com" value={newDomain}
                 onChange={(e) => setNewDomain(e.target.value)} />
          <button className="primary-btn slim" disabled={domBusy || !newDomain.trim()}>
            {domBusy ? "…" : "Claim domain"}
          </button>
        </form>
        {domErr && <div className="error">{domErr}</div>}
        {domains.map((d) => (
          <div key={d.id} style={{ padding: "8px 0", borderTop: "1px solid var(--border, #333)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <strong>{d.domain}</strong>
              <span className={`access-dot ${d.verified ? "on" : "off"}`} />
              <span className="muted">{d.verified ? "Verified" : "Unverified"}</span>
              <span style={{ flex: 1 }} />
              {!d.verified && (
                <button className="mini-btn" disabled={domBusy}
                        onClick={() => domAction(() => api.verifyDomain(d.id))}>
                  Verify now
                </button>
              )}
              {d.verified && (
                <label className="muted" style={{ fontSize: 12, display: "flex", gap: 4 }}>
                  <input type="checkbox" checked={d.auto_approve} disabled={domBusy}
                         onChange={(e) => domAction(() =>
                           api.updateDomain(d.id, { auto_approve: e.target.checked }))} />
                  auto-approve joins
                </label>
              )}
              <button className="mini-btn danger" disabled={domBusy}
                      onClick={() => domAction(() => api.deleteDomain(d.id))}>
                Remove
              </button>
            </div>
            {!d.verified && d.txt && (
              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                Add a TXT record — name: <code>{d.txt.name}</code>, value:{" "}
                <code>{d.txt.value}</code>, then click Verify now.
              </div>
            )}
          </div>
        ))}
        {domains.length === 0 && <div className="muted" style={{ fontSize: 12 }}>No claimed domains yet.</div>}
      </div>

      <div className="panel users-list">
        {loading ? (
          <div className="empty">Loading…</div>
        ) : (
          <table className="users-table">
            <thead>
              <tr><th>Email</th><th>Role</th><th>Access</th><th className="ta-right">Actions</th></tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.id === currentUser?.id;
                const lastAdmin = u.role === "admin" && u.active && activeAdmins <= 1;
                const busy = busyId === u.id;
                return (
                  <tr key={u.id} className={u.active ? "" : "row-inactive"}>
                    <td className="ut-email">{u.email}{isSelf && <span className="you-tag">you</span>}</td>
                    <td><span className={`role-pill role-${u.role}`}>{u.role}</span></td>
                    <td>
                      <span className={`access-dot ${u.active ? "on" : "off"}`} />
                      {u.active ? "Active" : "Disabled"}
                    </td>
                    <td className="ta-right ut-actions">
                      {u.role === "admin" ? (
                        <button className="mini-btn" disabled={busy || isSelf || lastAdmin}
                                title={isSelf ? "You can't change your own role" : lastAdmin ? "Can't demote the last admin" : ""}
                                onClick={() => patch(u, { role: "analyst" })}>
                          Make analyst
                        </button>
                      ) : (
                        <button className="mini-btn" disabled={busy}
                                onClick={() => patch(u, { role: "admin" })}>
                          Make admin
                        </button>
                      )}
                      {u.active ? (
                        <button className="mini-btn danger" disabled={busy || isSelf || lastAdmin}
                                title={isSelf ? "You can't disable yourself" : lastAdmin ? "Can't disable the last admin" : ""}
                                onClick={() => patch(u, { active: false })}>
                          Disable login
                        </button>
                      ) : (
                        <button className="mini-btn" disabled={busy}
                                onClick={() => patch(u, { active: true })}>
                          Enable login
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
