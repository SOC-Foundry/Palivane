import { useEffect, useState } from "react";

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
  mcp: { label: "mcp", cls: "atk" },
  deps: { label: "deps", cls: "ai" },
  ide: { label: "ide", cls: "ai" },
  secrets: { label: "secrets", cls: "atk" },
  collab: { label: "collab", cls: "ai" },
};

const CAT_LABEL = {
  prompt_injection: "Prompt injection", jailbreak: "Jailbreak",
  data_exfiltration: "Data exfiltration", secret_leak: "Secret leak",
  pii_exposure: "PII exposure", phi_exposure: "PHI (HIPAA)", source_code_leak: "Source/IP leak",
  confidential_data: "Confidential data", unsanctioned_ai: "Unsanctioned AI",
  mcp_untrusted_server: "Untrusted MCP server", sensitive_resource_access: "Sensitive resource",
  dangerous_command: "Dangerous command", tool_poisoning: "Tool poisoning",
  unsafe_autonomy: "Unsafe autonomy", dependency_risk: "Dependency risk",
  credential_at_rest: "Credential at rest", data_oversharing: "Data oversharing",
  agent_authz: "Least-privilege", ai_generated: "AI-generated",
  ci_workflow_risk: "CI workflow risk",
};

const SEV_RANK = { benign: 0, low: 1, suspicious: 2, high: 3, critical: 4 };
const ACTIONABLE = new Set(["suspicious", "high", "critical"]);

// One incident = same actor, same surface, same signal-category set. Repeats of the exact
// same event already fold server-side (seen_count); this collapses the *variations* one
// noisy actor/session produces into a single triageable row.
function groupFindings(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = [f.sender || "", f.surface, (f.categories || []).join(",")].join("|");
    let g = groups.get(key);
    if (!g) {
      g = { key, sender: f.sender, surface: f.surface, categories: f.categories || [],
            items: [], events: 0, worst: f, latest: f };
      groups.set(key, g);
    }
    g.items.push(f);
    g.events += f.seen_count || 1;
    if ((SEV_RANK[f.severity] ?? 0) > (SEV_RANK[g.worst.severity] ?? 0) ||
        ((SEV_RANK[f.severity] ?? 0) === (SEV_RANK[g.worst.severity] ?? 0) &&
         f.risk_score > g.worst.risk_score)) g.worst = f;
    if ((f.last_seen || f.created_at) > (g.latest.last_seen || g.latest.created_at)) g.latest = f;
  }
  return [...groups.values()].sort((a, b) =>
    (b.latest.last_seen || b.latest.created_at || "").localeCompare(
      a.latest.last_seen || a.latest.created_at || ""));
}

function FindingRow({ f, selectedId, onSelect }) {
  const surf = SURFACE[f.surface];
  return (
    <li
      className={`finding-row ${f.id === selectedId ? "active" : ""}`}
      onClick={() => onSelect(f.id)}
    >
      <RiskBadge severity={f.severity} score={f.risk_score} />
      <div className="finding-main">
        <div className="finding-subject">
          {f.subject || "(no subject)"}
          {(f.seen_count || 1) > 1 && (
            <span className="seen-badge" title={`seen ${f.seen_count} times`}>×{f.seen_count}</span>
          )}
        </div>
        {f.top_signals?.[0] && (
          <div className="finding-what">
            {f.top_signals[0].title}
            {f.top_signals[0].evidence && <code>{f.top_signals[0].evidence}</code>}
          </div>
        )}
        <div className="finding-meta">
          {surf && <span className={`tag tag-${surf.cls}`}>{surf.label}</span>}
          <span className="chan">{f.channel}</span>
          {f.sender && <span className="sender">{f.sender}</span>}
          {f.ai_generated && <span className="tag tag-ai">AI-generated</span>}
          {f.attack_intent && <span className="tag tag-atk">attack intent</span>}
          <span className="finding-age">{timeAgo(f.last_seen || f.created_at)}</span>
        </div>
      </div>
      <div className={`status status-${f.status}`}>{f.status}</div>
    </li>
  );
}

function GroupRow({ g, expanded, onToggle, selectedId, onSelect, onBulkStatus }) {
  const surf = SURFACE[g.surface];
  const label = (g.categories.length
    ? g.categories.map((c) => CAT_LABEL[c] || c).join(" · ")
    : g.worst.subject || "(no signals)");
  const openIds = g.items.filter((f) => f.status === "open").map((f) => f.id);
  return (
    <>
      <li className={`finding-row group-row ${expanded ? "expanded" : ""}`} onClick={onToggle}>
        <RiskBadge severity={g.worst.severity} score={g.worst.risk_score} />
        <div className="finding-main">
          <div className="finding-subject">
            {label}
            <span className="count-pill group-count" title={`${g.events} events across ${g.items.length} findings`}>
              {g.events > g.items.length ? `${g.items.length} · ${g.events} events` : g.items.length}
            </span>
          </div>
          {g.worst.top_signals?.[0] && (
            <div className="finding-what">
              {g.worst.top_signals[0].title}
              {g.worst.top_signals[0].evidence && <code>{g.worst.top_signals[0].evidence}</code>}
            </div>
          )}
          <div className="finding-meta">
            {surf && <span className={`tag tag-${surf.cls}`}>{surf.label}</span>}
            {g.sender && <span className="sender">{g.sender}</span>}
            <span className="finding-age">{timeAgo(g.latest.last_seen || g.latest.created_at)}</span>
          </div>
        </div>
        {onBulkStatus && openIds.length > 0 && (
          <div className="group-actions" onClick={(e) => e.stopPropagation()}>
            <button className="ghost-btn slim" title="Mark every open finding in this group triaged"
                    onClick={() => onBulkStatus(openIds, "triaged")}>triage all</button>
            <button className="ghost-btn slim" title="Dismiss every open finding in this group"
                    onClick={() => onBulkStatus(openIds, "dismissed")}>dismiss all</button>
          </div>
        )}
        <span className="group-chevron">{expanded ? "▾" : "▸"}</span>
      </li>
      {expanded && g.items.map((f) => (
        <FindingRow key={f.id} f={f} selectedId={selectedId} onSelect={onSelect} />
      ))}
    </>
  );
}

export default function FindingsList({ findings, selectedId, onSelect, filter, onFilter,
                                       status, onStatus, onConnect, onBulkStatus }) {
  const severities = ["actionable", "", "critical", "high", "suspicious", "low", "benign"];
  const surfaces = ["", "llm_io", "ai_usage", "mcp", "deps", "ide", "secrets", "collab"];
  const [surface, setSurface] = useState("");
  const [grouped, setGrouped] = useState(true);
  const [expanded, setExpanded] = useState(() => new Set());

  let shown = surface ? findings.filter((f) => f.surface === surface) : findings;
  if (filter === "actionable") shown = shown.filter((f) => ACTIONABLE.has(f.severity));
  else if (filter) shown = shown.filter((f) => f.severity === filter);

  const groups = grouped ? groupFindings(shown) : null;

  // A finding opened by URL (/app/findings/:id) can sit inside a collapsed group, where
  // its row is never rendered at all — the detail pane opens but the list shows nothing
  // selected, which reads as a broken link. Open its group once on arrival. Deliberately
  // not derived-on-every-render: seeding the set instead means the chevron still collapses
  // the group afterwards, rather than fighting a value recomputed under it.
  useEffect(() => {
    if (selectedId == null || !groups) return;
    const g = groups.find((x) => x.items.some((f) => f.id === selectedId));
    if (g) setExpanded((prev) => (prev.has(g.key) ? prev : new Set(prev).add(g.key)));
    // `groups` is derived from these; depending on it directly would re-run every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, grouped, findings]);

  function toggle(key) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  return (
    <div className="findings panel">
      <div className="findings-head">
        <h2>Findings <span className="count-pill">{grouped ? groups.length : shown.length}</span></h2>
        <div className="findings-filters">
          <label className="group-toggle" title="Collapse similar findings (same user, surface, and signal types) into one incident row">
            <input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />
            group
          </label>
          <select value={surface} onChange={(e) => setSurface(e.target.value)}>
            {surfaces.map((s) => (
              <option key={s} value={s}>{s === "" ? "all surfaces" : (SURFACE[s]?.label || s)}</option>
            ))}
          </select>
          <select value={filter} onChange={(e) => onFilter(e.target.value)}>
            {severities.map((s) => (
              <option key={s} value={s}>
                {s === "actionable" ? "actionable (warn+)" : s === "" ? "all severities" : s}
              </option>
            ))}
          </select>
          <select value={status} onChange={(e) => onStatus(e.target.value)}>
            <option value="open">open</option>
            <option value="">any status</option>
            <option value="triaged">triaged</option>
            <option value="dismissed">dismissed</option>
          </select>
        </div>
      </div>
      {shown.length === 0 && findings.length === 0 && (
        <div className="empty empty-onboard">
          <p><strong>Nothing in the queue.</strong></p>
          <p>New findings land here as capture sources see risky activity, or loosen the
             status / severity filters to see everything recorded.</p>
          {onConnect && <button className="primary-btn slim" onClick={onConnect}>Connect a source →</button>}
        </div>
      )}
      {shown.length === 0 && findings.length > 0 && (
        <div className="empty">No findings match this filter.</div>
      )}
      <ul className="finding-rows">
        {grouped
          ? groups.map((g) => (
              <GroupRow key={g.key} g={g} expanded={expanded.has(g.key)}
                        onToggle={() => toggle(g.key)} selectedId={selectedId}
                        onSelect={onSelect} onBulkStatus={onBulkStatus} />
            ))
          : shown.map((f) => (
              <FindingRow key={f.id} f={f} selectedId={selectedId} onSelect={onSelect} />
            ))}
      </ul>
    </div>
  );
}
