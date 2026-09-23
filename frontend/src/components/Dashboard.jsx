import { useEffect, useState } from "react";
import { api } from "../api.js";
import { IconInbox, IconList, IconAlert, IconTarget } from "./icons.jsx";

function SetupHealth() {
  const [s, setS] = useState(null);
  useEffect(() => { api.setupStatus().then(setS).catch(() => {}); }, []);
  if (!s) return null;
  const planes = [
    ["Gateway, your LLMs", s.planes.gateway],
    ["Shadow-AI, extension / proxy", s.planes.shadow_ai],
    ["Agentic, MCP", s.planes.mcp],
    ["Credentials at rest", s.planes.secrets],
  ];
  return (
    <div className="panel chart-panel setup-health">
      <h2>Coverage &amp; enforcement</h2>
      <ul className="plane-list">
        {planes.map(([label, n]) => (
          <li key={label} className="plane-row">
            <span className={`plane-dot ${n > 0 ? "on" : "off"}`} />
            <span className="plane-label">{label}</span>
            <span className="plane-count">{n > 0 ? `${n} in 24h` : "no activity"}</span>
          </li>
        ))}
      </ul>
      <div className="plane-flags">
        <span className={`chip ${s.gateway_enforce ? "chip-on" : "chip-off"}`}>
          {s.gateway_enforce ? "Enforcing" : "Monitor only"}</span>
        <span className={`chip ${s.mcp_enforce ? "chip-on" : "chip-off"}`}>
          {s.mcp_enforce ? "MCP enforce" : "MCP monitor"}</span>
        <span className={`chip ${s.judge_enabled ? "chip-on" : "chip-off"}`}>
          {s.judge_enabled ? "LLM judge on" : "Offline detection"}</span>
      </div>
    </div>
  );
}

const SEV_ORDER = ["critical", "high", "suspicious", "low", "benign"];
const SEV_LABEL = {
  critical: "Critical", high: "High", suspicious: "Suspicious", low: "Low", benign: "Benign",
};

function StatCard({ icon, value, label, tone, sub = "" }) {
  return (
    <div className={`stat-card stat-${tone}`}>
      <span className="stat-icon">{icon}</span>
      <div>
        <div className="stat-value">{value ?? 0}</div>
        <div className="stat-label">{label}</div>
        {sub && <div className="stat-sub">{sub}</div>}
      </div>
    </div>
  );
}

function RiskDistribution({ bySeverity, total }) {
  const segs = SEV_ORDER.map((s) => ({ s, n: bySeverity?.[s] || 0 })).filter((x) => x.n > 0);
  const sum = segs.reduce((a, x) => a + x.n, 0);
  return (
    <div className="panel chart-panel risk-panel">
      <h2>Risk distribution</h2>
      {sum === 0 ? (
        <p className="chart-empty">No findings yet.</p>
      ) : (
        <>
          <div className="dist-bar">
            {segs.map(({ s, n }) => (
              <span key={s} className={`dist-seg sev-bg-${s}`}
                    style={{ width: `${(n / sum) * 100}%` }} title={`${SEV_LABEL[s]}: ${n}`} />
            ))}
          </div>
          <ul className="dist-legend">
            {SEV_ORDER.map((s) => (
              <li key={s}>
                <span className={`dot sev-bg-${s}`} />
                <span className="dist-name">{SEV_LABEL[s]}</span>
                <span className="dist-count">{bySeverity?.[s] || 0}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

// Every surface the engine can label a finding with, in a fixed order. Two product fronts
// first, then the agentic planes, then the endpoint/supply-chain ones. Declared rather than
// derived so the rows keep their position as counts move, and so a surface at zero still
// says "nothing here" instead of vanishing.
const SURFACES = [
  ["llm_io", "Protect our AI", "prompt injection · jailbreak · exfiltration"],
  ["ai_usage", "Shadow-AI governance", "secrets · PII · source code"],
  ["agent_tools", "Assistant tool-use", "Bash · Edit · Read — the agent's own tools"],
  ["mcp", "MCP", "agentic tool calls, local stdio or remote"],
  ["agent_rules", "Agent rules files", "CLAUDE.md · .cursorrules · SKILL.md"],
  ["session", "Session correlation", "attack chains across an actor's activity"],
  ["a2a", "Agent-to-agent", "one agent's output feeding another"],
  ["oversharing", "Need-to-know", "an LLM answering outside the allowed group"],
  ["collab", "Collaboration content", "Slack and other AI-readable messages"],
  ["deps", "Dependencies", "supply-chain risk in package manifests"],
  ["ide", "IDE extensions", "unapproved or known-bad editor plugins"],
  ["ci", "CI runners", "workflow posture and AI agents in CI"],
  ["secrets", "Credentials at rest", "secrets on the device itself"],
  ["device", "Device health", "capture-plane collisions and coverage gaps"],
];
const HEADLINE = new Set(["llm_io", "ai_usage"]);   // the two fronts: shown even at zero

function SurfaceSplit({ bySurface }) {
  const counts = bySurface || {};
  // Share of ALL findings, not of the largest row. Normalizing to the max meant whichever
  // surface led was pinned at 100% whatever its count — with only two rows that bar could
  // never move, which is exactly how it read.
  const total = Object.values(counts).reduce((a, b) => a + (b || 0), 0);
  const known = new Set(SURFACES.map(([k]) => k));
  const other = Object.entries(counts)
    .filter(([k, n]) => !known.has(k) && n > 0)
    .reduce((a, [, n]) => a + n, 0);

  // Sorted by count, so the panel reads top-down like the bar chart it is and an empty
  // headline surface sits at the bottom instead of leading with a zero. Safe to sort here
  // because every bar shares one hue — nothing about the colour is tied to row position.
  const rows = SURFACES
    .filter(([k]) => HEADLINE.has(k) || (counts[k] || 0) > 0)
    .map(([key, label, sub]) => ({ key, label, sub, n: counts[key] || 0 }))
    .sort((a, b) => b.n - a.n);
  // A surface the engine grows and this list has not caught up with lands here rather than
  // disappearing from a panel that claims to break down the whole.
  if (other > 0) rows.push({ key: "other", label: "Other", sub: "surfaces not broken out above", n: other });

  return (
    <div className="panel chart-panel surface-panel">
      <h2>By surface</h2>
      <ul className="surface-list">
        {rows.map((r) => {
          const pct = total ? (r.n / total) * 100 : 0;
          return (
            <li key={r.key} className={`surface-row${r.n === 0 ? " is-zero" : ""}`}
                title={`${r.label}: ${r.n} of ${total} (${pct.toFixed(pct < 10 ? 1 : 0)}%)`}>
              <div className="surface-head">
                <span className="surface-label">{r.label}</span>
                <span className="surface-count">{r.n}</span>
              </div>
              {/* One hue for every bar. Surfaces are nominal categories of a single measure,
                  so length and label already carry identity — a hue per row would re-encode
                  that, and would collide with the severity palette in the panel beside it,
                  where the same red means "critical". */}
              <div className="surface-track">
                <span className="surface-fill" style={{ width: `${pct}%` }} />
              </div>
              <div className="surface-sub">{r.sub}</div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export default function Dashboard({ stats }) {
  if (!stats) {
    return (
      <div className="dashboard">
        {[0, 1, 2, 3].map((i) => <div key={i} className="stat-card stat-skeleton" />)}
      </div>
    );
  }
  return (
    <>
      <div className="dashboard">
        <StatCard icon={<IconInbox />} value={stats.analyzed_total ?? stats.total} label="Total analyzed" tone="neutral" />
        {/* "Open" means unreviewed, which is a workflow fact and includes benign rows
            nobody needs to act on. The sub-line appears only when those two numbers differ,
            so it explains a gap when there is one and stays quiet when there is not. */}
        <StatCard icon={<IconList />} value={stats.open} label="Open" tone="neutral"
                  sub={typeof stats.open_needs_review === "number"
                       && stats.open_needs_review !== stats.open
                       ? `${stats.open_needs_review} need review`
                       : ""} />
        <StatCard icon={<IconAlert />} value={stats.high_risk} label="High / critical" tone="danger" />
        <StatCard icon={<IconTarget />} value={stats.ai_weaponized} label="AI-weaponized" tone="warn" />
      </div>
      {/* Two short panels stacked beside one tall one. Nested rather than a three-cell
          grid: with grid rows the short pair gets spaced to the tall panel's row heights
          and drifts apart, and squaring them up by stretching instead strands each
          heading above a floating body. A flex column just lets them sit. */}
      <div className="charts-grid">
        <div className="charts-col">
          <RiskDistribution bySeverity={stats.by_severity} total={stats.total} />
          <SetupHealth />
        </div>
        <SurfaceSplit bySurface={stats.by_surface} />
      </div>
    </>
  );
}
