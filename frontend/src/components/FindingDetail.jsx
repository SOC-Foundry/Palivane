import { useEffect, useState } from "react";
import { api } from "../api.js";
import { cleanError, expiryChoices } from "./Allowlist.jsx";

const CAT_LABEL = {
  ai_generated: "AI-generated",
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak",
  data_exfiltration: "Data exfiltration",
  secret_leak: "Secret leak",
  pii_exposure: "PII exposure",
  phi_exposure: "PHI exposure (HIPAA)",
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

// What a finding can offer to put on the allowlist. A command rule quotes the statement it matched
// in `detail`; a path rule only recorded the FILE NAME fragment unless evidence context kept the
// whole path (a file tool's `where: "path"` excerpt), so a partial suggestion says so.
function allowSuggestion(s) {
  if (s.category === "dangerous_command") {
    const m = /pattern: ([\s\S]+)$/.exec(s.detail || "");
    return { kind: "command", pattern: m ? m[1].trim() : "", partial: false };
  }
  if (s.category === "sensitive_resource_access") {
    if (s.context && s.context.where === "path") return { kind: "path", pattern: s.context.text, partial: false };
    const m = /path=(\S+)/.exec(s.evidence || "");
    return { kind: "path", pattern: m ? m[1] : "", partial: true };
  }
  return null;
}

// Inline "allow this" form under a signal. Prefilled, editable, and explicit about what it does:
// future calls like this stop flagging; THIS finding stays open until someone dismisses it.
function AllowThis({ finding, signal }) {
  const sug = allowSuggestion(signal);
  const [open, setOpen] = useState(false);
  const [pattern, setPattern] = useState(sug?.pattern || "");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(30);
  const [scope, setScope] = useState("person");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState(null);
  const [covered, setCovered] = useState(null);
  const [looked, setLooked] = useState(!sug);
  // An active entry for this very command or path (or made from this finding) already covers it.
  // Only an exact match is recognised; a wider pattern that also covers it is not looked for.
  useEffect(() => {
    if (!sug) return undefined;
    let live = true;
    api.allowlist("active")
      .then((r) => {
        if (!live) return;
        setCovered((r.entries || []).find((e) => e.kind === sug.kind
          && ((sug.pattern && e.pattern === sug.pattern) || e.finding_id === finding.id)) || null);
      })
      .catch(() => {})
      .finally(() => { if (live) setLooked(true); });
    return () => { live = false; };
  }, [finding.id, sug?.kind, sug?.pattern]);
  if (!sug || !looked) return null;
  if (covered && !done) {
    return (
      <p className="tune-done">
        Already allowed until {new Date(covered.expires_at + "Z").toLocaleDateString()}. Manage it
        under Policies → Allowlist.
      </p>
    );
  }
  const who = finding.sender || "";

  async function save() {
    setBusy(true); setErr("");
    try {
      const e = await api.allowlistAdd({
        kind: sug.kind, pattern, reason, expires_in_days: Number(days), finding_id: finding.id,
        actor: scope === "everyone" ? "" : who,
        tool: scope === "person_tool" ? (finding.channel || "") : "",
      });
      setDone(e);
    } catch (e) { setErr(cleanError(e)); }
    finally { setBusy(false); }
  }

  if (done) {
    return (
      <p className="tune-done">
        ✓ Allowed until {new Date(done.expires_at + "Z").toLocaleDateString()}. Calls like this stop
        flagging; this finding stays open until you dismiss it. Manage it under Policies → Allowlist.
      </p>
    );
  }
  if (!open) {
    return (
      <button className="link-btn signal-allow" onClick={() => setOpen(true)}>
        Allow this {sug.kind}…
      </button>
    );
  }
  return (
    <div className="allow-inline">
      <label className="allow-field">
        {sug.kind === "command" ? "The command, exactly as written" : "The path or pattern"}
        <input value={pattern} onChange={(e) => setPattern(e.target.value)} />
      </label>
      {sug.partial && (
        <p className="field-note" style={{ margin: "0 0 6px" }}>
          The finding only recorded the file name. Enter the full path, or a pattern such as
          {" "}<code>/srv/app/fixtures/**</code>. (Turning on Evidence context in Settings keeps the
          whole path for new findings.)
        </p>
      )}
      {sug.kind === "command" && /«redacted/.test(pattern) && (
        <p className="field-note" style={{ margin: "0 0 6px" }}>
          Part of this was masked in the finding. Replace it with <code>*</code>.
        </p>
      )}
      <label className="allow-field">
        Why (required)
        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. our own installer" />
      </label>
      <div className="allow-two">
        <label className="allow-field">
          Applies to
          <select value={scope} onChange={(e) => setScope(e.target.value)}>
            <option value="person">Only {who || "this person"}</option>
            {finding.channel && <option value="person_tool">Only {who || "this person"} on {finding.channel}</option>}
            <option value="everyone">Everyone</option>
          </select>
        </label>
        <label className="allow-field">
          Expires
          <select value={days} onChange={(e) => setDays(e.target.value)}>
            {expiryChoices(365).map(([d, label]) => <option key={d} value={d}>in {label}</option>)}
          </select>
        </label>
      </div>
      {err && <div className="error" style={{ margin: "6px 0" }}>{err}</div>}
      <div className="tune-actions">
        <button className="ghost-btn slim" onClick={save}
                disabled={busy || !pattern.trim() || reason.trim().length < 3}>
          {busy ? "…" : "Allow for a limited time"}
        </button>
        <button className="link-btn" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </div>
  );
}

// What an evidence excerpt is an excerpt OF. The server says (`context.where`).
const CONTEXT_LABEL = {
  prompt: "In the prompt", response: "In the response", message: "In the message",
  content: "In the content", command: "Command", path: "Path", call: "Tool call",
};

// Categories an excerpt can exist for (mirrors app/excerpts.py). A finding made only of other
// signals (an unsanctioned destination, a device-posture gap) has no "words around the match", so
// it gets no hint about turning excerpts on.
const EXCERPTABLE = new Set([
  "secret_leak", "credential_at_rest", "pii_exposure", "phi_exposure", "dangerous_command",
  "sensitive_resource_access", "prompt_injection", "jailbreak", "data_exfiltration",
  "confidential_data", "source_code_leak",
]);

// The excerpt is masked on the server: every secret and identifier is already a «redacted:…»
// marker by the time it reaches the browser. Marking the markers makes them read as "something
// was here" instead of as stray text.
function Marked({ text }) {
  return String(text).split(/(«[^»]*»)/).map((part, i) =>
    part.startsWith("«")
      ? <mark key={i} className="redacted">{part}</mark>
      : <span key={i}>{part}</span>);
}

// Concrete "what do I do now" steps, derived from the finding's signals + evidence, mirrors
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
      steps.push("This credential is CONFIRMED LIVE, rotate it now; assume it may already be compromised.");
    if (!steps.length)
      steps.push("Rotate the credential, revoke the old one, and move it into a secret manager or the OS keychain.");
    if (ev.includes("world/group-readable"))
      steps.push("Tighten file permissions (chmod 600), it is readable by other local users.");
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
    steps.push("This agent acted outside its role. Add the tool/server to the role's allow-list if legitimate, otherwise investigate, the agent may be compromised or misconfigured.");
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

// Why a finding was dismissed. Optional, and it is what lets the precision readout tell a false
// positive (the detector was wrong) from something the org expects (allow it instead).
const DISMISS_REASONS = [
  ["", "No reason"],
  ["false_positive", "False positive: the detector was wrong"],
  ["expected", "Expected: it happened, and that is fine"],
  ["accepted_risk", "Accepted risk"],
  ["duplicate", "Duplicate"],
];
// One click, one judgement: what the review queue offers. Each records who decided and why, which is
// what the precision readout is built from; "Real" is a triage (the detection was right), the rest
// are dismissals with their reason, so none of them lands in "No reason given".
const QUICK_VERDICTS = [
  ["Real, handle it", "triaged", "", "The detection was right and someone should act on it."],
  ["Expected", "dismissed", "expected", "It happened and that is fine. Allow it instead of tuning the check."],
  ["False positive", "dismissed", "false_positive", "The detector was wrong."],
  ["Accepted risk", "dismissed", "accepted_risk", "Known, and the org accepts it."],
];
const REASON_WORD = { false_positive: "a false positive", expected: "expected", accepted_risk: "an accepted risk", duplicate: "a duplicate" };

// The distinct policy checks this finding's signals belong to, what a suppression targets.
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

export default function FindingDetail({ finding, isAdmin, analystEnabled, onClose, onStatusChange, onReviewed, reviewing }) {
  const [suppressed, setSuppressed] = useState(null);
  const [report, setReport] = useState(finding?.investigation || null);   // persisted or fresh
  const [investigating, setInvestigating] = useState(false);
  const [investigateErr, setInvestigateErr] = useState("");
  const [reason, setReason] = useState("");                  // why, if the next click is Dismissed
  useEffect(() => { setReason(""); }, [finding?.id]);
  if (!finding) return null;
  const status = finding.status || "open";
  const steps = remediationFor(finding);
  const checks = isAdmin && finding.sender ? checksOf(finding) : [];

  async function setStatus(s) {
    await api.setStatus(finding.id, s, "", s === "dismissed" ? reason : "");
    onStatusChange();
  }

  async function quickVerdict(s, why) {
    await api.setStatus(finding.id, s, "", why);
    onStatusChange();
    if (onReviewed) onReviewed(finding.id);
  }

  // Read-only AI analyst: it investigates and RECOMMENDS an action; a human still applies it
  // via the status buttons. Never mutates the finding on its own.
  async function investigate() {
    setInvestigating(true); setInvestigateErr("");
    try {
      setReport(await api.investigateFinding(finding.id));
    } catch (e) {
      setInvestigateErr(e.message || String(e));
    } finally {
      setInvestigating(false);
    }
  }

  // Approval-gated: the human applies the analyst's recommendation with one click; it's
  // recorded (via="analyst") as an AI recommendation a person approved. Dismiss stays
  // admin-only server-side. "quarantine"/"block" are enforcement recs with no finding-status
  // equivalent, so they apply as "triaged" (acknowledged, being handled).
  const APPLY = { dismiss: "dismissed", triage: "triaged", keep_open: "open" };

  async function applyRecommendation() {
    const target = APPLY[report.recommended_action] || "triaged";
    if (!window.confirm(`Apply the analyst's recommendation and mark this finding "${target}"?`)) return;
    try {
      await api.setStatus(finding.id, target, "analyst");
      onStatusChange();
    } catch (e) {
      setInvestigateErr(e.message || String(e));
    }
  }

  // One-click policy tuning: merge this check into the actor's per-user override, so
  // expected behavior (e.g. a security engineer whose work trips the scanners) stops
  // generating findings at the source instead of being re-dismissed forever. Scoped to
  // this finding's tool by default (safer); "everywhere" covers all tools.
  async function suppress(check, label, channel) {
    const who = finding.sender;
    const where = channel ? `via ${channel}` : "on every tool";
    if (!window.confirm(`Stop flagging "${label}" for ${who} ${where}?\n\nThis adds a per-user policy override (Policies page). Palivane will no longer record ${label} findings for this user ${where}.`)) return;
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

      <div className="detail-section analyst">
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <button className="primary-btn slim" onClick={investigate}
                  disabled={investigating || !analystEnabled}
                  title={analystEnabled ? undefined : "Turn on the AI analyst in Settings first"}>
            {investigating ? "Investigating…" : report ? "🔎 Re-investigate" : "🔎 Investigate (AI analyst)"}
          </button>
          <span className="muted" style={{ fontSize: 12 }}>
            {analystEnabled
              ? "Reads the finding + this actor's history and recommends an action. It never applies it. Runs on your org's own LLM key."
              : "Off by default. An admin can enable the AI analyst in Settings — it sends the finding's redacted context to your org's own LLM provider (your key, never ours)."}
          </span>
        </div>
        {investigateErr && <div className="error" style={{ marginTop: 10 }}>{investigateErr}</div>}
        {report && (
          <div className="analyst-report" style={{ marginTop: 12 }}>
            <p><strong>Summary.</strong> {report.summary}</p>
            <p><strong>Assessment.</strong> {report.assessment}</p>
            <p><strong>Related activity.</strong> {report.related_activity}</p>
            <p><strong>Recommended:</strong>{" "}
              <span className={`status-chip status-${report.recommended_action}`}>
                {report.recommended_action}</span>{" "}
              <span className="muted" style={{ fontSize: 12 }}>
                ({Math.round((report.confidence || 0) * 100)}% confidence · {report.by})</span>
            </p>
            <p className="muted" style={{ fontSize: 13 }}>{report.rationale}</p>
            <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 10 }}>
              <button className="primary-btn slim" onClick={applyRecommendation}>
                Apply: mark {APPLY[report.recommended_action] || "triaged"}
              </button>
              <span className="muted" style={{ fontSize: 12 }}>You approve. The analyst never applies it.</span>
            </div>
          </div>
        )}
      </div>

      <h3>{finding.subject || "(no subject)"}</h3>
      <div className="detail-meta">
        <span>{finding.channel}</span>
        {finding.sender && <span>· {finding.sender}</span>}
        {finding.agent && <span className="tag tag-ai">🤖 {finding.agent}</span>}
        {finding.ai_generated && <span className="tag tag-ai">AI-generated</span>}
        {finding.attack_intent && <span className="tag tag-atk">attack intent</span>}
      </div>

      {finding.origin && (
        <div className="detail-section origin">
          <h4>Where it came from{finding.origin.sensitive && <span className="origin-badge">sensitive source</span>}</h4>
          <p className="origin-line">
            This content matches <strong>{finding.origin.title || finding.origin.ref}</strong>
            {finding.origin.owner && <> · owned by {finding.origin.owner}</>}
            {" "}in <span className="origin-source">{finding.origin.source}</span>
            {" "}<span className="origin-conf">{Math.round((finding.origin.containment || 0) * 100)}% overlap</span>
          </p>
          <p className="origin-note">
            {finding.origin.sensitive
              ? "This source document itself holds sensitive data, so severity was raised because a known-confidential file reached an AI tool. "
              : "Confirmed as real organizational data (not just sensitive-looking text), so severity was raised. "}
            Restrict access at the source to stop the leak at its root.</p>
        </div>
      )}

      {finding.owner_response && (
        <div className="detail-section">
          <h4>
            {finding.owner_response.action === "justified"
              ? "Owner justification (proceeded)" : "Owner response"}
          </h4>
          <p style={{ margin: "4px 0" }}>
            {finding.owner_response.note || <em>(no note)</em>}
          </p>
          <p className="muted" style={{ fontSize: 12 }}>
            {finding.owner_response.action} · {finding.owner_response.by}
            {finding.owner_response.at && <> · {new Date(finding.owner_response.at).toLocaleString()}</>}
          </p>
        </div>
      )}

      {steps.length > 0 && (
        <div className="detail-section remediation">
          <h4>How to fix</h4>
          <ol className="remediation-list">
            {steps.map((s, i) => <li key={i}>{s}</li>)}
          </ol>
        </div>
      )}

      {/* An empty box reads as a bug. It is a policy: prompt prose is not persisted by
          default (config.store_content) — the verdict, the signals, redacted evidence and
          the attribution are, and those are what triage actually needs. Saying so turns a
          hole into the privacy posture the landing page already claims. */}
      <div className="detail-section">
        <h4>Content</h4>
        {finding.content
          ? <pre className="content-block">{finding.content}</pre>
          : (
            <p className="content-empty">
              Prompt text is not stored. Palivane keeps the verdict, the matched signals,
              redacted evidence and who sent it, never the prose itself, which cannot be
              redacted for concepts or IP and would make this store worth stealing.
              An admin who wants full text for their own triage can turn it on under
              Settings → Store prompt content.
            </p>
          )}
      </div>

      <div className="detail-section">
        <h4>Signals ({(finding.signals || []).length})</h4>
        {/* Saying why a finding has no excerpt turns a hole into a setting. It is a policy:
            the excerpt is a few words of the prompt, so it is kept only when the org asks. */}
        {!finding.context_retained && (finding.signals || []).some((s) => EXCERPTABLE.has(s.category)) && (
          <p className="context-hint">
            Palivane recorded what matched, not the words around it. An admin can turn on
            {" "}<strong>Settings → Organization → Evidence context</strong> to keep a short,
            masked excerpt around each match on new findings.
          </p>
        )}
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
              {s.context && (
                <div className="signal-context">
                  <div className="signal-context-label">
                    {CONTEXT_LABEL[s.context.where] || "Context"}
                    <span className="signal-context-mask"> · secrets and identifiers masked</span>
                  </div>
                  <pre className="signal-context-text">
                    {s.context.cut?.[0] && <span className="cut">…</span>}
                    <Marked text={s.context.text} />
                    {s.context.cut?.[1] && <span className="cut">…</span>}
                  </pre>
                </div>
              )}
              {isAdmin && finding.sender && (
                <AllowThis key={`${finding.id}:${i}`} finding={finding} signal={s} />
              )}
              <div className="signal-src">via {s.detector}{s.via ? ` · captured from the request to ${s.via}` : ""}</div>
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
                      stop flagging '{label}' via {finding.channel}
                    </button>
                    <button className="link-btn tune-everywhere" title="Suppress on every tool, not just this one"
                            onClick={() => suppress(check, label, "")}>everywhere</button>
                  </>
                ) : (
                  <button className="ghost-btn slim" onClick={() => suppress(check, label, "")}>
                    stop flagging '{label}'
                  </button>
                )}
              </span>
            ))}
          </div>
          {suppressed && (
            <p className="tune-done">✓ {suppressed} suppressed for {finding.sender}, takes
              effect on their next capture.</p>
          )}
        </div>
      )}

      {isAdmin && status === "open" && (
        <div className={`detail-actions quick-review${reviewing ? " pinned" : ""}`}>
          <span className="detail-actions-label">{reviewing ? "Review: is this right?" : "Is this right?"}</span>
          {QUICK_VERDICTS.map(([label, s, why, tip]) => (
            <button key={label} title={tip} onClick={() => quickVerdict(s, why)}>{label}</button>
          ))}
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
      <div className="review-line">
        <label className="review-reason">If dismissing, why?
          <select value={reason} onChange={(e) => setReason(e.target.value)}>
            {DISMISS_REASONS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </select>
        </label>
        {finding.review && (
          <span className="muted">
            {status === "dismissed" ? "Dismissed" : "Triaged"} by {finding.review.by || "someone"}
            {finding.review.reason ? ` as ${REASON_WORD[finding.review.reason] || finding.review.reason}` : ""}
            {finding.review.via === "bulk" ? " (in bulk)" : finding.review.via === "analyst" ? " (the analyst's recommendation)" : ""}
            , {new Date(finding.review.at + "Z").toLocaleDateString()}.
          </span>
        )}
      </div>
    </div>
  );
}
