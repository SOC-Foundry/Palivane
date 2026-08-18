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

// Readable labels for the raw audit action keys (e.g. "apikey.revoke"). Anything not listed
// falls back to a humanized form so new actions still read cleanly instead of "Foo.Bar_baz".
const ACTION_LABELS = {
  "apikey.create": "API key created", "apikey.revoke": "API key revoked",
  "enroll_token.create": "Enrollment token created", "enroll_token.revoke": "Enrollment token revoked",
  "device.enroll": "Device enrolled",
  "extension.connect": "Extension connected", "extension.reconnect": "Extension reconnected",
  "finding.status": "Finding updated", "finding.bulk_status": "Findings updated",
  "user.invite": "User invited", "user.update": "User updated", "user.role": "Role changed",
  "login.success": "Signed in", "login.failed": "Sign-in failed",
  "tenant.update": "Settings changed",
};

function actionLabel(action) {
  if (!action) return "—";
  if (ACTION_LABELS[action]) return ACTION_LABELS[action];
  const words = action.replace(/[._]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// Colour the pill by intent so a destructive revoke doesn't read the same as a status change.
function actionKind(action) {
  const a = (action || "").toLowerCase();
  if (/(revoke|delete|remove|disable|suspend|deauth|block|fail)/.test(a)) return "danger";
  if (/(create|connect|enroll|invite|add|signup|success)/.test(a)) return "ok";
  return "neutral";
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
              <option key={a} value={a}>{actionLabel(a)}</option>
            ))}
          </select>
        </div>
        {loading ? (
          <div className="empty">Loading…</div>
        ) : entries.length === 0 ? (
          <div className="empty">No admin activity recorded yet.</div>
        ) : (
          <div className="audit-scroll">
          <table className="users-table audit-table">
            <thead>
              <tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="audit-when">{when(e.created_at)}</td>
                  <td>{e.actor}</td>
                  <td><span className={`audit-act audit-act-${actionKind(e.action)}`}
                            title={e.action}>{actionLabel(e.action)}</span></td>
                  <td className="ut-email">{e.target || "—"}</td>
                  <td className="audit-detail">{summarize(e.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>
    </div>
  );
}
