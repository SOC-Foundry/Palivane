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

  const load = useCallback(async () => {
    try {
      const r = await api.users();
      setUsers(r.users);
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
