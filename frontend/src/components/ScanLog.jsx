// Scan Log, per-registered-user activity. Who is tripping what, how often, and how risky.
// Reuses the findings store (grouped by actor server-side); click a user to see their findings.
import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const RISK_CLASS = (r) => (r >= 80 ? "critical" : r >= 60 ? "high" : r >= 35 ? "suspicious" : r >= 15 ? "low" : "benign");
const CAT_LABEL = {
  secret_leak: "secrets", pii_exposure: "PII", phi_exposure: "PHI", source_code_leak: "source", confidential_data: "confidential",
  unsanctioned_ai: "unsanctioned AI", prompt_injection: "injection", jailbreak: "jailbreak",
  data_exfiltration: "exfiltration", dangerous_command: "dangerous cmd", unsafe_autonomy: "YOLO",
  data_oversharing: "oversharing", credential_at_rest: "creds at rest", dependency_risk: "deps",
  ci_workflow_risk: "CI workflow",
};

export default function ScanLog() {
  const [users, setUsers] = useState(null);
  const [sel, setSel] = useState(null);
  const [findings, setFindings] = useState([]);
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    try { setUsers((await api.activityUsers()).users); }
    catch (e) { setErr(String(e.message || e).replace(/^\d+:\s*/, "")); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function openUser(actor) {
    setSel(actor);
    try { setFindings((await api.findings({ actor })).findings); }
    catch { setFindings([]); }
  }

  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Scan log</h1>
          <p className="page-sub">Activity per registered user, what each person is tripping, how
             often, and how risky. Click a user to see their findings.</p>
        </div>
      </div>

      {err && <div className="error">{err}</div>}

      <div className="panel settings-card">
        <h2>Users</h2>
        {users && users.length ? (
          <table className="data-table">
            <thead><tr><th>User</th><th>Findings</th><th>High+</th><th>Top categories</th><th>Peak risk</th><th>Last seen</th></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.actor} className={sel === u.actor ? "row-on" : ""}
                    style={{ cursor: "pointer" }} onClick={() => openUser(u.actor)}>
                  <td><strong>{u.actor}</strong></td>
                  <td>{u.findings}</td>
                  <td>{u.high
                    ? <span style={{ color: u.critical ? "var(--crit)" : "var(--high)", fontWeight: 700 }}>{u.high}{u.critical ? ` (${u.critical} crit)` : ""}</span>
                    : <span className="muted">0</span>}</td>
                  <td className="muted">{u.categories.map((c) => `${CAT_LABEL[c.category] || c.category} ${c.count}`).join(", ") || "-"}</td>
                  <td><span className={`sev sev-${RISK_CLASS(u.max_risk)}`}>{u.max_risk}</span></td>
                  <td className="muted">{u.last_seen ? u.last_seen.slice(0, 10) : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="muted">No user activity yet, findings attributed to a user will appear here.</p>}
      </div>

      {sel && (
        <div className="panel settings-card">
          <h2>{sel}, recent findings</h2>
          {findings.length ? (
            <table className="data-table">
              <thead><tr><th>When</th><th>Surface</th><th>Severity</th><th>Risk</th><th>Subject</th></tr></thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td className="muted">{(f.created_at || "").slice(0, 16).replace("T", " ")}</td>
                    <td className="muted">{f.surface}</td>
                    <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                    <td>{f.risk_score}</td>
                    <td className="muted">{f.subject || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="muted">No findings for this user.</p>}
        </div>
      )}
    </div>
  );
}
