// Help — an in-app guide so an admin who logs into the console (and may never see the
// repo) can understand what Palivane does, connect their sources, and read a finding. Content
// is curated from the repo docs (README / docs/overview / git+cli READMEs) and links out to
// them for the deep dives. All copy lives here — no backend call, works offline.

const PLANES = [
  ["Browser extension", "Chrome/Edge extension that scans prompts in web AI tools (ChatGPT, Claude.ai, Gemini, Copilot) before they're sent — warns or blocks in place."],
  ["Gateway", "A drop-in API endpoint your CLIs and apps point at instead of the provider (OpenAI, Anthropic, Gemini). Scans every request — and, optionally, the model's response — in monitor or enforce mode."],
  ["Egress proxy", "A forward proxy for traffic you can't reconfigure per-app; inspects AI-bound requests at the network edge."],
  ["Git plane", "A pre-commit hook + CI check (and history sweep) that stops secrets and PII from reaching your repos."],
  ["Endpoint sensors", "Lightweight CLIs (palivane-connect, palivane-secrets, palivane-posture, palivane-mcp) that scan for credentials at rest, MCP config, and AI-tool posture on managed machines."],
];

const CATEGORIES = [
  ["secret_leak", "Secret leak", "API keys, tokens, private keys, DB URLs — anything that authenticates. Verified-live credentials escalate to critical."],
  ["pii_exposure", "PII exposure", "SSNs (with or without dashes), cards, IBANs, passports, national IDs, and single-record combinations (name+DOB, etc.)."],
  ["phi_exposure", "PHI exposure (HIPAA)", "Protected health information: MRNs, Medicare/insurance member IDs, NPI/DEA numbers, diagnosis codes, and patient identity in clinical context."],
  ["source_code_leak", "Source / IP leak", "Proprietary source code. Suppressed for sanctioned coding tools (Claude Code, Cursor, Copilot…) where code is expected."],
  ["confidential_data", "Confidential data", "Business-sensitive material — financials, contracts, roadmaps, M&A, HR — including content carrying a classification label (TLP, Purview/MIP banners)."],
  ["unsanctioned_ai", "Unsanctioned AI", "Use of an AI tool that isn't on your approved list. The block screen offers your sanctioned alternatives."],
  ["credential_at_rest", "Credential at rest", "Secrets found sitting on an endpoint (cloud keys, .npmrc, .git-credentials, key files) by palivane-secrets."],
  ["dangerous_command", "Dangerous command", "Destructive or high-risk shell/tool actions surfaced from agent/MCP traffic."],
];

const SEVERITIES = [
  ["benign", "0", "No risk signals."],
  ["low", "1–34", "Minor / low-confidence signal."],
  ["suspicious", "35–59", "Worth a look; often a warn in monitor mode."],
  ["high", "60–79", "Strong signal; blocked in enforce mode."],
  ["critical", "80–100", "Verified secret or multiple strong signals."],
];

function Card({ title, sub, children }) {
  return (
    <div className="panel settings-card" style={{ marginTop: 16 }}>
      <h2 style={{ margin: "0 0 4px" }}>{title}</h2>
      {sub && <p className="muted" style={{ marginTop: 0 }}>{sub}</p>}
      {children}
    </div>
  );
}

export default function Help({ isAdmin = false, onNavigate }) {
  return (
    <div className="connect">
      <div className="content-head">
        <div>
          <h1 className="page-title">Help &amp; documentation</h1>
          <p className="page-sub">What Palivane does, how to connect your sources, and how to read a finding.
             The full reference lives in the repository docs, linked at the bottom.</p>
        </div>
      </div>

      <Card title="What Palivane is"
            sub="An AI security gateway that keeps sensitive data — secrets, PII, source code, and confidential business content — from leaving your org through AI tools, and gives you one console for every path AI data can take.">
        <p style={{ marginBottom: 0 }}>Palivane captures AI-bound traffic across several <strong>planes</strong>. You don't
           need all of them — start with one and add coverage over time. Each finding you
           see in the console came from one of these:</p>
        <ul className="help-list">
          {PLANES.map(([n, d]) => (
            <li key={n}><strong>{n}.</strong> {d}</li>
          ))}
        </ul>
      </Card>

      <Card title="Getting started"
            sub="Fastest path to your first finding.">
        <ol className="help-list">
          <li>{isAdmin
            ? <>Open <button className="link-btn" onClick={() => onNavigate?.("connect")}>Connect</button> and
               follow the Quick Start — mint a capture key and pick a source (extension, gateway, or an MDM pack for a whole fleet).</>
            : <>Ask an admin to open the <strong>Connect</strong> page and enroll a source (extension, gateway, or MDM pack).</>}
          </li>
          <li>Send a test prompt through it (the Connect page's readiness panel confirms data is flowing).</li>
          <li>Watch it land in <strong>Findings</strong> — click any finding for its signals, evidence, and how to fix it.</li>
          {isAdmin && <li>Tune policy in <button className="link-btn" onClick={() => onNavigate?.("settings")}>Settings</button> — alert digests, SIEM export, custom detection patterns.</li>}
        </ol>
      </Card>

      <Card title="Reading a finding"
            sub="Every finding is scored 0–100 and tagged with one or more categories.">
        <h3 className="help-h3">Categories</h3>
        <table className="data-table">
          <thead><tr><th>Category</th><th>Meaning</th></tr></thead>
          <tbody>
            {CATEGORIES.map(([key, label, desc]) => (
              <tr key={key}>
                <td><span className={`cat cat-${key}`}>{label}</span></td>
                <td className="muted">{desc}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <h3 className="help-h3">Severity</h3>
        <table className="data-table">
          <thead><tr><th>Severity</th><th>Risk score</th><th>What it means</th></tr></thead>
          <tbody>
            {SEVERITIES.map(([sev, range, desc]) => (
              <tr key={sev}>
                <td><span className={`sev sev-${sev}`}>{sev}</span></td>
                <td><code>{range}</code></td>
                <td className="muted">{desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card title="Monitor vs. enforce"
            sub="Each capture point runs in one of two modes.">
        <ul className="help-list">
          <li><strong>Monitor</strong> — nothing is blocked; requests pass through and findings are recorded. Best for a rollout's first phase, so you see what would trip before you enforce.</li>
          <li><strong>Enforce</strong> — high/critical findings are blocked at the source: the extension shows a block modal, the gateway returns an error, the git hook fails the commit.</li>
        </ul>
        <p className="muted" style={{ marginBottom: 0 }}>Source-code detection is automatically suppressed for sanctioned coding tools, so
           Claude Code / Cursor / Copilot keep working — but a <em>secret</em> inside that code still blocks.</p>
      </Card>

      {isAdmin && (
        <Card title="Alerts, SIEM & customization"
              sub="Configured in Settings.">
          <ul className="help-list">
            <li><strong>Alert digests</strong> — real-time, hourly, or daily Slack/webhook rollups to cut noise.</li>
            <li><strong>SIEM export</strong> — forward findings to Splunk HEC, generic JSON, or CEF.</li>
            <li><strong>Custom patterns</strong> — add your own secret/PII regexes; they run alongside the built-ins across every plane.</li>
            <li><strong>Sanctioned tools</strong> — list your approved AI tools so block screens can offer them as alternatives.</li>
          </ul>
        </Card>
      )}

      <Card title="Full reference"
            sub="The deep-dive docs in the repository.">
        <ul className="help-list">
          <li><strong>Overview & architecture</strong> — <code>docs/overview.md</code></li>
          <li><strong>Fleet rollout (MDM pack)</strong> — Connect page → “Deploy to a fleet”, and <code>docs/</code></li>
          <li><strong>Git capture plane</strong> — <code>git/README.md</code> (pre-commit, CI, history sweep)</li>
          <li><strong>Endpoint CLIs</strong> — <code>cli/README.md</code> (palivane-secrets, palivane-import, palivane-posture)</li>
        </ul>
        <p className="muted" style={{ marginBottom: 0 }}>Need something that isn't here? Contact your Palivane administrator or the security team.</p>
      </Card>
    </div>
  );
}
