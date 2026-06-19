import { api } from "../api.js";

const CAT_LABEL = {
  ai_generated: "AI-generated",
  phishing: "Phishing",
  social_engineering: "Social engineering",
  malicious_url: "Malicious URL",
  malware: "Malware",
  impersonation: "Impersonation",
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak",
  data_exfiltration: "Data exfiltration",
  secret_leak: "Secret leak",
  pii_exposure: "PII exposure",
  source_code_leak: "Source/IP leak",
  unsanctioned_ai: "Unsanctioned AI",
};

export default function FindingDetail({ finding, onClose, onStatusChange }) {
  if (!finding) return null;

  async function setStatus(status) {
    await api.setStatus(finding.id, status);
    onStatusChange();
  }

  return (
    <div className="detail-drawer">
      <div className="detail-head">
        <div>
          <span className={`badge sev-${finding.severity}`}>
            {finding.risk_score} · {finding.severity}
          </span>
          <span className="rec-action">recommend: {finding.recommended_action}</span>
        </div>
        <button className="link-btn" onClick={onClose}>
          close
        </button>
      </div>

      <h3>{finding.subject || "(no subject)"}</h3>
      <div className="detail-meta">
        <span>{finding.channel}</span>
        {finding.sender && <span>· {finding.sender}</span>}
        {finding.ai_generated && <span className="tag tag-ai">AI-generated</span>}
        {finding.attack_intent && <span className="tag tag-atk">attack intent</span>}
      </div>

      <div className="detail-section">
        <h4>Content</h4>
        <pre className="content-block">{finding.content}</pre>
      </div>

      <div className="detail-section">
        <h4>Signals ({(finding.signals || []).length})</h4>
        <ul className="signal-list">
          {(finding.signals || []).map((s, i) => (
            <li key={i} className="signal">
              <div className="signal-top">
                <span className={`cat cat-${s.category}`}>{CAT_LABEL[s.category] || s.category}</span>
                <span className="signal-title">{s.title}</span>
                <span className="signal-score">
                  {Math.round(s.weight * s.confidence * 100)}
                </span>
              </div>
              <div className="signal-detail">{s.detail}</div>
              {s.evidence && <code className="signal-evidence">{s.evidence}</code>}
              <div className="signal-src">via {s.detector}</div>
            </li>
          ))}
        </ul>
      </div>

      <div className="detail-actions">
        <button onClick={() => setStatus("triaged")}>Mark triaged</button>
        <button onClick={() => setStatus("dismissed")}>Dismiss</button>
        <button onClick={() => setStatus("open")}>Reopen</button>
      </div>
    </div>
  );
}
