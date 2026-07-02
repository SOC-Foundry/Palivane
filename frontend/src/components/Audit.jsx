import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

function when(iso) {
  if (!iso) return "";
  const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  return d.toLocaleString();
}

function summarize(detail) {
  if (!detail || Object.keys(detail).length === 0) return "";
  return Object.entries(detail).map(([k, v]) => `${k}: ${v}`).join(", ");
}

export default function Audit() {
  const [entries, setEntries] = useState([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    api.audit({ action: filter, limit: 200 })
      .then((r) => setEntries(r.entries))
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, [filter]);

  useEffect(() => { load(); }, [load]);

  const actions = [...new Set(entries.map((e) => e.action))].sort();

  return (
    <div className="settings">
      <div className="content-head">
        <div>
          <h1 className="page-title">Audit log</h1>
          <p className="page-sub">Security-relevant admin actions in your organization, newest first.</p>
        </div>
        <button type="button" className="ghost-btn" onClick={load}>Refresh</button>
      </div>

      <div className="panel">
        <div className="findings-head">
          <h2>Activity <span className="count-pill">{entries.length}</span></h2>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">all actions</option>
            {(filter && !actions.includes(filter) ? [filter, ...actions] : actions).map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
        {loading ? (
          <div className="empty">Loading…</div>
        ) : entries.length === 0 ? (
          <div className="empty">No admin activity recorded yet.</div>
        ) : (
          <table className="users-table audit-table">
            <thead>
              <tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="audit-when">{when(e.created_at)}</td>
                  <td>{e.actor}</td>
                  <td><span className="role-pill role-analyst">{e.action}</span></td>
                  <td className="ut-email">{e.target || "—"}</td>
                  <td className="audit-detail">{summarize(e.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
