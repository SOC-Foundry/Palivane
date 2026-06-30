function RiskBadge({ severity, score }) {
  return (
    <span className={`badge sev-${severity}`}>
      {score} · {severity}
    </span>
  );
}

function timeAgo(iso) {
  if (!iso) return "";
  const then = new Date(iso.endsWith("Z") ? iso : iso + "Z").getTime();
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

const SURFACE = {
  llm_io: { label: "protect-ai", cls: "atk" },
  ai_usage: { label: "shadow-ai", cls: "ai" },
};

export default function FindingsList({ findings, selectedId, onSelect, filter, onFilter }) {
  const severities = ["", "critical", "high", "suspicious", "low", "benign"];
  return (
    <div className="findings panel">
      <div className="findings-head">
        <h2>Findings <span className="count-pill">{findings.length}</span></h2>
        <select value={filter} onChange={(e) => onFilter(e.target.value)}>
          {severities.map((s) => (
            <option key={s} value={s}>
              {s === "" ? "all severities" : s}
            </option>
          ))}
        </select>
      </div>
      {findings.length === 0 && (
        <div className="empty">No findings match this filter yet.</div>
      )}
      <ul className="finding-rows">
        {findings.map((f) => {
          const surf = SURFACE[f.surface];
          return (
            <li
              key={f.id}
              className={`finding-row ${f.id === selectedId ? "active" : ""}`}
              onClick={() => onSelect(f.id)}
            >
              <RiskBadge severity={f.severity} score={f.risk_score} />
              <div className="finding-main">
                <div className="finding-subject">{f.subject || "(no subject)"}</div>
                <div className="finding-meta">
                  {surf && <span className={`tag tag-${surf.cls}`}>{surf.label}</span>}
                  <span className="chan">{f.channel}</span>
                  {f.sender && <span className="sender">{f.sender}</span>}
                  {f.ai_generated && <span className="tag tag-ai">AI-generated</span>}
                  {f.attack_intent && <span className="tag tag-atk">attack intent</span>}
                  <span className="finding-age">{timeAgo(f.created_at)}</span>
                </div>
              </div>
              <div className={`status status-${f.status}`}>{f.status}</div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
