import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

// Okta and Entra groups, from SCIM or from an OIDC/SAML groups claim, mapped to a
// console role and a Discovery team. Shared by Settings and Users so both stay the
// same list.
export default function GroupMappings() {
  const [rows, setRows] = useState([]);
  const [group, setGroup] = useState("");
  const [role, setRole] = useState("member");
  const [team, setTeam] = useState("");
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.groupMappings();
      setRows(r.mappings || []);
    } catch (e) {
      setErr(String(e.message || e).replace(/^\d+:\s*/, ""));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function save(e) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      await api.saveGroupMapping({ group: group.trim(), role, team: team.trim() });
      setGroup(""); setTeam(""); setRole("member");
      await load();
    } catch (e2) {
      setErr(String(e2.message || e2).replace(/^\d+:\s*/, ""));
    } finally {
      setBusy(false);
    }
  }

  async function remove(id) {
    setBusy(true); setErr(null);
    try {
      await api.deleteGroupMapping(id);
      await load();
    } catch (e) {
      setErr(String(e.message || e).replace(/^\d+:\s*/, ""));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel settings-card">
      <div className="settings-head"><h2>Group mappings</h2></div>
      <p className="muted">Map an Okta or Entra group to a console role and a team. Use the
        group name or id your identity provider sends — an Okta group name, or an Entra
        display name or object id — whether it arrives over SCIM or in the OIDC / SAML
        groups claim. Someone in several mapped groups gets the highest role: admin, then
        analyst, then auditor, then member. A mapping without a role stays member. The team
        is stamped on that person and on their Discovery rows, so the inventory can filter
        and group by team. A console role is replaced on the next sign-in or SCIM sync
        when a mapped group matches.</p>
      <form className="add-user-row" onSubmit={save}>
        <input placeholder="Group name or id" value={group}
               onChange={(e) => setGroup(e.target.value)} required />
        <select value={role} onChange={(e) => setRole(e.target.value)} aria-label="Role">
          <option value="member">Member</option>
          <option value="analyst">Analyst</option>
          <option value="auditor">Auditor</option>
          <option value="admin">Admin</option>
        </select>
        <input placeholder="Team (optional)" value={team}
               onChange={(e) => setTeam(e.target.value)} />
        <button className="primary-btn slim" disabled={busy || !group.trim()}>
          {busy ? "..." : "Save mapping"}
        </button>
      </form>
      {err && <div className="error" style={{ marginTop: 8 }}>{err}</div>}
      {rows.length > 0 && (
        <div className="table-scroll" style={{ marginTop: 12 }}>
          <table className="users-table">
            <thead>
              <tr><th>Group</th><th>Role</th><th>Team</th><th></th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="ut-email">{r.group}</td>
                  <td><span className={`role-pill role-${r.role}`}>{r.role}</span></td>
                  <td>{r.team || <span className="muted">—</span>}</td>
                  <td className="ta-right">
                    <button type="button" className="mini-btn danger" disabled={busy}
                            onClick={() => remove(r.id)}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rows.length === 0 && <p className="muted" style={{ marginBottom: 0 }}>No mappings yet.
        Until one matches, directory accounts stay members and Discovery leaves their team
        as the log reported it.</p>}
    </div>
  );
}
