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

function StatCard({ icon, value, label, tone }) {
  return (
    <div className={`stat-card stat-${tone}`}>
      <span className="stat-icon">{icon}</span>
      <div>
        <div className="stat-value">{value ?? 0}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  );
}

function RiskDistribution({ bySeverity, total }) {
  const segs = SEV_ORDER.map((s) => ({ s, n: bySeverity?.[s] || 0 })).filter((x) => x.n > 0);
  const sum = segs.reduce((a, x) => a + x.n, 0);
  return (
    <div className="panel chart-panel">
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

function SurfaceSplit({ bySurface }) {
  const llm = bySurface?.llm_io || 0;
  const ai = bySurface?.ai_usage || 0;
  const max = Math.max(llm, ai, 1);
  const rows = [
    { key: "llm_io", label: "Protect our AI", sub: "prompt injection · jailbreak · exfiltration", n: llm, cls: "atk" },
    { key: "ai_usage", label: "Shadow-AI governance", sub: "secrets · PII · source code", n: ai, cls: "ai" },
  ];
  return (
    <div className="panel chart-panel">
      <h2>By surface</h2>
      <ul className="surface-list">
        {rows.map((r) => (
          <li key={r.key} className="surface-row">
            <div className="surface-head">
              <span className="surface-label">{r.label}</span>
              <span className="surface-count">{r.n}</span>
            </div>
            <div className="surface-track">
              <span className={`surface-fill fill-${r.cls}`} style={{ width: `${(r.n / max) * 100}%` }} />
            </div>
            <div className="surface-sub">{r.sub}</div>
          </li>
        ))}
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
        <StatCard icon={<IconList />} value={stats.open} label="Open" tone="neutral" />
        <StatCard icon={<IconAlert />} value={stats.high_risk} label="High / critical" tone="danger" />
        <StatCard icon={<IconTarget />} value={stats.ai_weaponized} label="AI-weaponized" tone="warn" />
      </div>
      <div className="charts-grid">
        <RiskDistribution bySeverity={stats.by_severity} total={stats.total} />
        <SurfaceSplit bySurface={stats.by_surface} />
        <SetupHealth />
      </div>
    </>
  );
}
