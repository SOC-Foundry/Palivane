import { useState } from "react";
import { api } from "../api.js";

const CAT_LABEL = {
  ai_generated: "AI-generated",
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak",
  data_exfiltration: "Data exfiltration",
  secret_leak: "Secret leak",
  pii_exposure: "PII exposure",
  source_code_leak: "Source/IP leak",
  confidential_data: "Confidential data",
  unsanctioned_ai: "Unsanctioned AI",
  mcp_untrusted_server: "Untrusted MCP server",
  sensitive_resource_access: "Sensitive resource access",
  dangerous_command: "Dangerous command",
  tool_poisoning: "Tool poisoning",
  unsafe_autonomy: "Unsafe agent autonomy",
  dependency_risk: "Dependency risk",
  credential_at_rest: "Credential at rest",
  data_oversharing: "Data oversharing",
  agent_authz: "Agent least-privilege",
  ci_workflow_risk: "CI workflow risk",
};

// Concrete "what do I do now" steps, derived from the finding's signals + evidence — mirrors
// the backend remediation guidance so the security team can close the loop from the console.
function remediationFor(finding) {
  const cats = new Set((finding.signals || []).map((s) => s.category));
  // Look across evidence + title + detail (the type, "VERIFIED LIVE", "world-readable" all
  // live in the title/detail, not just the evidence) so the steps can be specific.
  const ev = ((finding.signals || [])
    .flatMap((s) => [s.evidence, s.title, s.detail]).filter(Boolean).join(" ") + " " +
    (finding.subject || "")).toLowerCase();
  const steps = [];

  if (cats.has("credential_at_rest") || cats.has("secret_leak")) {
    if (ev.includes("private key"))
      steps.push("Rotate the key pair and delete the private key from disk; use an SSH agent or the OS keychain, not a plaintext file.");
    if (ev.includes("github"))
      steps.push("Revoke the token at github.com/settings/tokens and re-issue a fine-grained, expiring PAT.");
    if (ev.includes("aws"))
      steps.push("Deactivate the access key in IAM and switch to short-lived creds (SSO/STS).");
    if (ev.includes("verified live"))
      steps.push("This credential is CONFIRMED LIVE — rotate it now; assume it may already be compromised.");
    if (!steps.length)
      steps.push("Rotate the credential, revoke the old one, and move it into a secret manager or the OS keychain.");
    if (ev.includes("world/group-readable"))
      steps.push("Tighten file permissions (chmod 600) — it is readable by other local users.");
  }
  if (cats.has("pii_exposure"))
    steps.push("Remove the personal data; for regulated data use only an approved, contracted tool.");
  if (cats.has("source_code_leak") || cats.has("unsanctioned_ai") || cats.has("confidential_data"))
    steps.push("Redirect the user to a sanctioned AI tool; for confidential/classified material, use only an approved, contracted tool.");
  if (cats.has("dangerous_command") || cats.has("sensitive_resource_access") || cats.has("tool_poisoning"))
    steps.push("Review the agent's tool call; restrict the MCP server or command, and confirm nothing ran.");
  if (cats.has("unsafe_autonomy"))
    steps.push("Turn off the agent's auto-run / auto-apply (YOLO) setting and require confirmation before it executes commands or edits.");
  if (cats.has("data_oversharing"))
    steps.push("Restrict the source data's permissions at the origin (SharePoint/Drive/index) so the LLM can't surface it to unauthorized users; verify the need-to-know rule matches your access policy.");
  if (cats.has("agent_authz"))
    steps.push("This agent acted outside its role. Add the tool/server to the role's allow-list if legitimate, otherwise investigate — the agent may be compromised or misconfigured.");
  if (cats.has("mcp_untrusted_server"))
    steps.push("Add the server to the per-tenant MCP allowlist if trusted, otherwise block it.");
  if (cats.has("dependency_risk"))
    steps.push("Pin or replace the dependency and review its install scripts before it ships.");
  if (cats.has("prompt_injection") || cats.has("jailbreak") || cats.has("data_exfiltration"))
    steps.push("Treat as an attack on your LLM: confirm the model didn't comply, and consider blocking the actor.");
  return steps;
}

const STATUSES = [
  { key: "open", label: "Open" },
  { key: "triaged", label: "Triaged" },
  { key: "dismissed", label: "Dismissed" },
];

// The distinct policy checks this finding's signals belong to — what a suppression targets.
const NOT_A_CHECK = new Set(["ai_generated"]);  // verdict signals with no policy toggle

function checksOf(finding) {
  const seen = new Map();
  for (const s of finding.signals || []) {
    const key = s.check || s.category;
    if (key && !NOT_A_CHECK.has(key) && !seen.has(key)) {
      seen.set(key, CAT_LABEL[s.category] || s.title || key);
    }
  }
  return [...seen.entries()];
}

export default function FindingDetail({ finding, isAdmin, onClose, onStatusChange }) {
  const [suppressed, setSuppressed] = useState(null);
  if (!finding) return null;
  const status = finding.status || "open";
  const steps = remediationFor(finding);
  const checks = isAdmin && finding.sender ? checksOf(finding) : [];

  async function setStatus(s) {
    await api.setStatus(finding.id, s);
    onStatusChange();
  }

  // One-click policy tuning: merge this check into the actor's per-user override, so
  // expected behavior (e.g. a security engineer whose work trips the scanners) stops
  // generating findings at the source instead of being re-dismissed forever. Scoped to
  // this finding's tool by default (safer); "everywhere" covers all tools.
  async function suppress(check, label, channel) {
    const who = finding.sender;
    const where = channel ? `via ${channel}` : "on every tool";
    if (!window.confirm(`Stop flagging "${label}" for ${who} ${where}?\n\nThis adds a per-user policy override (Policies page) — Warden will no longer record ${label} findings for this user ${where}.`)) return;
    const ch = (channel || "").toLowerCase();
    const pol = await api.policies();
    const existing = (pol.overrides || []).find(
      (o) => o.scope === "user" && o.match === who.toLowerCase() && (o.channel || "") === ch);
    const disabled = [...new Set([...(existing?.disabled_checks || []), check])];
    try {
      await api.policyOverrideUpsert({
        scope: "user", match: who, channel: ch, label: existing?.label || "",
        disabled_checks: disabled });
      setSuppressed(`${label} (${where})`);
    } catch (e) {
      window.alert(`Couldn't add the override: ${e.message}`);
    }
  }

  return (
    <div className="detail-drawer">
      <div className="detail-head">
        <div>
          <span className={`badge sev-${finding.severity}`}>
            {finding.risk_score} · {finding.severity}
          </span>
          <span className={`status-chip status-${status}`}>{status}</span>
          <span className="rec-action">recommend: {finding.recommended_action}</span>
        </div>
        <button className="link-btn" onClick={onClose}>close</button>
      </div>

      <h3>{finding.subject || "(no subject)"}</h3>
      <div className="detail-meta">
        <span>{finding.channel}</span>
        {finding.sender && <span>· {finding.sender}</span>}
        {finding.agent && <span className="tag tag-ai">🤖 {finding.agent}</span>}
        {finding.ai_generated && <span className="tag tag-ai">AI-generated</span>}
        {finding.attack_intent && <span className="tag tag-atk">attack intent</span>}
      </div>

      {steps.length > 0 && (
        <div className="detail-section remediation">
          <h4>How to fix</h4>
          <ol className="remediation-list">
            {steps.map((s, i) => <li key={i}>{s}</li>)}
          </ol>
        </div>
      )}

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
                <span className="signal-score">{Math.round(s.weight * s.confidence * 100)}</span>
              </div>
              <div className="signal-detail">{s.detail}</div>
              {s.evidence && <code className="signal-evidence">{s.evidence}</code>}
              <div className="signal-src">via {s.detector}</div>
            </li>
          ))}
        </ul>
      </div>

      {checks.length > 0 && (
        <div className="detail-section">
          <h4>Tune policy</h4>
          <p className="tune-hint">Expected behavior for this user? Suppress the check for
            {" "}<strong>{finding.sender}</strong> only (admins can review/undo on the Policies page).</p>
          <div className="tune-actions">
            {checks.map(([check, label]) => (
              <span key={check} className="tune-pair">
                {finding.channel ? (
                  <>
                    <button className="ghost-btn slim"
                            onClick={() => suppress(check, label, finding.channel)}>
                      stop flagging “{label}” via {finding.channel}
                    </button>
                    <button className="link-btn tune-everywhere" title="Suppress on every tool, not just this one"
                            onClick={() => suppress(check, label, "")}>everywhere</button>
                  </>
                ) : (
                  <button className="ghost-btn slim" onClick={() => suppress(check, label, "")}>
                    stop flagging “{label}”
                  </button>
                )}
              </span>
            ))}
          </div>
          {suppressed && (
            <p className="tune-done">✓ {suppressed} suppressed for {finding.sender} — takes
              effect on their next capture.</p>
          )}
        </div>
      )}

      <div className="detail-actions">
        <span className="detail-actions-label">Set status:</span>
        {STATUSES.map((s) => (
          <button key={s.key} onClick={() => setStatus(s.key)}
                  className={status === s.key ? "active" : ""} disabled={status === s.key}>
            {s.label}
          </button>
        ))}
      </div>
    </div>
  );
}
