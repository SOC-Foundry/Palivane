// Public technical deep-dive at /how-it-works. A visual, sectioned walkthrough (pipeline
// diagram, surface chips, detector cards, tiered secret stack, scoring formula + severity
// table, monitor/enforce split) rather than a wall of prose. Content mirrors README
// "How detection works", kept accurate for a security-minded reader evaluating the engine.
import { SiteNav, SiteFooter, Shot, Clip } from "./SiteChrome.jsx";
import { signInUrl } from "../deployment.js";
import { IconAlert, IconInbox, IconList, IconShield, IconTarget } from "./icons.jsx";
import { DuoEye, DuoGhost, DuoKey, DuoMessageAlert, DuoNodes, DuoPackage, DuoTerminal, DuoTool } from "./duoicons.jsx";

const PIPELINE = [
  { icon: <IconInbox />, label: "Capture", sub: "from the browser, desktop apps, coding tools, or GitHub Actions" },
  { icon: <IconShield />, label: "Route by surface", sub: "run only the checks that fit this kind of content" },
  { icon: <IconList />, label: "Signals", sub: "what matched, and how strong each match is" },
  { icon: <IconTarget />, label: "Score", sub: "signals combined into one 0-100 risk score" },
  { icon: <IconAlert />, label: "Verdict", sub: "allow, warn, or block" },
];

const DETECTORS = [
  { icon: <DuoMessageAlert />, title: "Prompt threats", surface: "llm_io", body: "Injection, jailbreak and system-prompt exfiltration, matched on text with look-alike and zero-width tricks folded and encoded blobs decoded." },
  { icon: <DuoGhost />, title: "Shadow-AI", surface: "ai_usage · mcp · collab", body: "Secrets, PII and PHI, proprietary source code, and confidential content including TLP and Purview labels." },
  { icon: <DuoTool />, title: "Agentic (MCP) guard", surface: "mcp", body: "Sensitive-file access, dangerous commands, tool poisoning and untrusted servers, read off the agent's tool use, local stdio MCP included." },
  { icon: <DuoPackage />, title: "Supply-chain & IDE", surface: "deps · ide", body: "Risky dependencies (install scripts, non-registry sources, known-bad packages, CVEs) and unapproved editor extensions." },
  { icon: <DuoKey />, title: "Credentials at rest", surface: "secrets", body: "Keys on laptops, in buckets, repositories and databases, found where they sit; only masked findings leave." },
  { icon: <DuoEye />, title: "Agent safety & oversharing", surface: "ide · oversharing", body: "Coding agents running with approvals off, dangerous commands in AI chats, and an LLM returning restricted data to the wrong person." },
  { icon: <DuoNodes />, title: "ML classifiers", surface: "ai_usage · llm_io · collab", body: "Two on-box models: one finds code the keyword rules read past, one finds paraphrased injection. CPU-only, sub-millisecond." },
  { icon: <DuoTerminal />, title: "CI runners", surface: "ci", body: "Agents in pipelines handed credentials or approvals turned off, plus runner posture: pwn-request triggers, unpinned actions, write-all tokens." },
];

const TIERS = [
  { cls: "t-crit", badge: "Tier 1", title: "Known formats", action: "hard block", body: "Distinctive prefixes: OpenAI, Anthropic, AWS, GitHub, GitLab, Stripe, Slack, Google, npm, PyPI, PEM keys, JWTs." },
  { cls: "t-high", badge: "Tier 1b", title: "Disguised keys", action: "hard block", body: "The same keys with separators stripped, spaced out, written in look-alike characters, or base64/hex-encoded." },
  { cls: "t-susp", badge: "Tier 2", title: "High-entropy heuristic", action: "warn", body: "Novel tokens with no known prefix, by entropy and character mix, excluding hashes and UUIDs." },
  { cls: "t-ai", badge: "Custom", title: "Your own patterns", action: "your call", body: "Per-org patterns (customer IDs, account numbers, codenames) applied on every plane." },
];

const SEVERITIES = [
  ["critical", "80-100", "block", "A verified secret, or several strong signals at once."],
  ["high", "60-79", "quarantine", "A strong data-loss or attack signal."],
  ["suspicious", "35-59", "quarantine", "Worth review, often a warn in monitor mode."],
  ["low", "15-34", "monitor", "A minor or low-confidence signal."],
  ["benign", "0-14", "allow", "No meaningful risk signal."],
];

export default function HowItWorks() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">HOW IT WORKS</div>
        <h1>How Palivane works</h1>
        <p>Every piece of AI-bound content ends up as one verdict, reached by deterministic
           rules and on-box models in milliseconds, with no third-party AI call unless you turn
           on the optional LLM judge.</p>
      </section>

      {/* Pipeline */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Everything runs through the same five steps</h2>
          <p className="lp-sub">A prompt, a paste into ChatGPT, an agent's next action, a commit:
             one pipeline, one policy, one console. Each item runs only the detectors for its
             surface, and one that errors can never sink the analysis.</p>
          <div className="hiw-pipeline">
            {PIPELINE.map((s, i) => (
              <div className="hiw-pipe-cell" key={s.label}>
                <div className="hiw-pipe">
                  <span className="hiw-pipe-ic">{s.icon}</span>
                  <b>{s.label}</b>
                  <span>{s.sub}</span>
                </div>
                {i < PIPELINE.length - 1 && <span className="hiw-arrow">→</span>}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Detectors */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">The offline detectors</h2>
          <p className="lp-sub">Each emits <strong>signals</strong>, evidence with a weight and a
             confidence.</p>
          <div className="lp-cards">
            {DETECTORS.map((d) => (
              <div className="lp-card" key={d.title}>
                <span className="lp-card-icon">{d.icon}</span>
                <h3>{d.title}</h3>
                <code className="hiw-surface-tag">{d.surface}</code>
                <p style={{ marginTop: 8 }}>{d.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Two-tier secrets */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Secret detection is layered</h2>
          <p className="lp-sub">A leaked credential is the highest-stakes finding, so it's caught four ways.</p>
          <div className="hiw-tiers">
            {TIERS.map((t) => (
              <div className={`hiw-tier ${t.cls}`} key={t.badge}>
                <span className="hiw-tier-badge">{t.badge}</span>
                <div className="hiw-tier-body">
                  <h3>{t.title}</h3>
                  <p>{t.body}</p>
                </div>
                <span className="hiw-tier-action">{t.action}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Scoring */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Scoring fuses signals into one verdict</h2>
          <p className="lp-sub">A <strong>saturating OR</strong>: a few strong signals escalate,
             many weak ones can't max the score.</p>
          <div className="hiw-formula">
            <code>risk = 1 − Π ( 1 − weightᵢ × confidenceᵢ )</code>
            <span>combined, mapped to 0-100 → a severity and a recommended action</span>
          </div>
          <table className="hiw-table">
            <thead><tr><th>Severity</th><th>Risk</th><th>Action</th><th>Meaning</th></tr></thead>
            <tbody>
              {SEVERITIES.map(([sev, range, action, desc]) => (
                <tr key={sev}>
                  <td><span className={`sev sev-${sev}`}>{sev}</span></td>
                  <td><code>{range}</code></td>
                  <td>{action}</td>
                  <td>{desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Latency */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">What inline inspection costs</h2>
          <table className="hiw-table">
            <thead><tr><th>Input</th><th>p50</th><th>p95</th></tr></thead>
            <tbody>
              <tr><td>Typical prompt (&lt;1&nbsp;KB)</td><td><code>0.2&nbsp;ms</code></td><td><code>0.3&nbsp;ms</code></td></tr>
              <tr><td>Code paste (~2&nbsp;KB)</td><td><code>5&nbsp;ms</code></td><td><code>8&nbsp;ms</code></td></tr>
              <tr><td>Document paste (~18&nbsp;KB)</td><td><code>44&nbsp;ms</code></td><td><code>65&nbsp;ms</code></td></tr>
            </tbody>
          </table>
          <p className="lp-sub" style={{ fontSize: 13, opacity: 0.8 }}>Scoring time on the rules
             path, measured in-process. Streaming responses pass through live in monitor mode.</p>
        </div>
      </section>

      {/* Monitor vs enforce */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Monitor or enforce</h2>
          <p className="lp-sub">Every capture point runs in one of two modes, roll out on monitor, then flip to enforce.</p>
          <div className="hiw-modes">
            <div className="hiw-mode">
              <h3><span className="hiw-dot dot-monitor" /> Monitor</h3>
              <p>Findings are recorded and traffic passes, except confirmed secret and personal-data
                 leaks, which are blocked. See what would trip before you enforce.</p>
            </div>
            <div className="hiw-mode hiw-mode-enforce">
              <h3><span className="hiw-dot dot-enforce" /> Enforce</h3>
              <p>Findings at your block severity are stopped at the source: a block in the browser,
                 an error from the gateway, a failed commit or pull request.</p>
            </div>
          </div>
          <p className="lp-sub" style={{ marginTop: 18 }}>Source-code detection is auto-suppressed for
             sanctioned coding tools (Claude Code, Cursor, Copilot), but a <em>secret</em> inside that
             code still blocks.</p>
        </div>
      </section>

      {/* Everything lands in one console */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">...into one console</h2>
          <p className="lp-sub">Every verdict, across every plane, scored and triageable in one place.</p>
          {/* Real console, real seeded data — findings, discovery, policies, a live
              simulator block, and fleet health, recorded end to end. */}
          <Clip lead src="/shots/console-tour2.mp4" poster="/shots/console-poster2.png"
                caption="Thirty seconds through the console: findings and their evidence, the shadow-AI inventory, the policy catalog, and the simulator blocking a live injection + credential paste." />
        </div>
      </section>

      {/* ...or skip the console — govern it from your assistant over MCP */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">…or skip the console entirely</h2>
          <p className="lp-sub">The console is also a hosted <strong>MCP server</strong>. Add{" "}
             <code>app.palivane.io/api/mcp/</code> to Claude or any MCP client, approve it once, and
             ask what leaked today, work the triage queue, or check shadow-AI usage.</p>
          <figure className="lp-shot lp-shot-lead">
            <video src="/shots/mcp-demo.mp4?v=2" poster="/shots/mcp-demo-poster.png" controls playsInline
                   preload="metadata"
                   style={{ display: "block", width: "100%", borderRadius: 12, border: "1px solid #22271F" }} />
            <figcaption>Four questions, four MCP tool calls: findings, shadow-AI inventory, a triage
               action, and OWASP Top-10 coverage.</figcaption>
          </figure>
          <p className="lp-sub" style={{ textAlign: "center" }}>
            <a className="lp-textlink" href="/docs/mcp">Connect your assistant →</a>
          </p>
        </div>
      </section>

      {/* Built for agents that act */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Built for agents that act</h2>
          <p className="lp-sub">An <strong>analyst</strong> that investigates findings and
             recommends, <strong>identity attestation</strong> that blocks unattested tool calls, and
             an <strong>agent-to-agent flow graph</strong> that shows where risk crossed a hop.</p>
          <figure className="lp-shot lp-shot-lead">
            <video src="/shots/agent-demo.mp4?v=2" poster="/shots/agent-demo-poster.png" controls playsInline
                   preload="metadata"
                   style={{ display: "block", width: "100%", borderRadius: 12, border: "1px solid #22271F" }} />
            <figcaption>The analyst investigating a credential-leak finding and recommending an
               action, attestation allowing an OIDC agent while blocking an unattested one, and the
               A2A flow graph.</figcaption>
          </figure>
        </div>
      </section>

      {/* Offline-first CTA band */}
      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>No external LLM dependency.</strong> Everything above runs with no API key and
              no outbound call. The optional LLM judge (Claude, GPT or Gemini, on your key) adds a
              second opinion for the cases rules miss.
            </div>
            <a className="primary-btn slim" href={signInUrl()} style={{ textDecoration: "none" }}>Open the console →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
