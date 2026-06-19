function RiskBadge({ severity, score }) {
  return (
    <span className={`badge sev-${severity}`}>
      {score} · {severity}
    </span>
  );
}

export default function FindingsList({ findings, selectedId, onSelect, filter, onFilter }) {
  const severities = ["", "critical", "high", "suspicious", "low", "benign"];
  return (
    <div className="findings">
      <div className="findings-head">
        <h2>Findings</h2>
        <select value={filter} onChange={(e) => onFilter(e.target.value)}>
          {severities.map((s) => (
            <option key={s} value={s}>
              {s === "" ? "all severities" : s}
            </option>
          ))}
        </select>
      </div>
      {findings.length === 0 && <div className="empty">No findings yet.</div>}
      <ul className="finding-rows">
        {findings.map((f) => (
          <li
            key={f.id}
            className={`finding-row ${f.id === selectedId ? "active" : ""}`}
            onClick={() => onSelect(f.id)}
          >
            <RiskBadge severity={f.severity} score={f.risk_score} />
            <div className="finding-main">
              <div className="finding-subject">{f.subject || "(no subject)"}</div>
              <div className="finding-meta">
                <span className="chan">{f.channel}</span>
                {f.sender && <span className="sender">{f.sender}</span>}
                {f.ai_generated && <span className="tag tag-ai">AI-generated</span>}
                {f.attack_intent && <span className="tag tag-atk">attack intent</span>}
              </div>
            </div>
            <div className={`status status-${f.status}`}>{f.status}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}
