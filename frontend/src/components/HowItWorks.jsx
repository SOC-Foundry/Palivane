// Public technical deep-dive at /how-it-works. A visual, sectioned walkthrough (pipeline
// diagram, surface chips, detector cards, tiered secret stack, scoring formula + severity
// table, monitor/enforce split) rather than a wall of prose. Content mirrors README
// "How detection works" — kept accurate for a security-minded reader evaluating the engine.
import { SiteNav, SiteFooter, Shot } from "./SiteChrome.jsx";
import { IconInbox, IconShield, IconList, IconTarget, IconAlert, IconClipboard, IconPlug } from "./icons.jsx";

const PIPELINE = [
  { icon: <IconInbox />, label: "Capture", sub: "from the browser, desktop apps, coding tools, or CI" },
  { icon: <IconShield />, label: "Route by surface", sub: "run only the checks that fit this kind of content" },
  { icon: <IconList />, label: "Signals", sub: "what matched, and how strong each match is" },
  { icon: <IconTarget />, label: "Score", sub: "signals combined into one 0–100 risk score" },
  { icon: <IconAlert />, label: "Verdict", sub: "allow, warn, or block" },
];

const SURFACES = [
  ["llm_io", "Prompts & responses on your own models"],
  ["ai_usage", "Content bound for external AI tools"],
  ["mcp", "Agent tool-use from AI assistants"],
  ["deps", "Dependency manifests (supply chain)"],
  ["ide", "Editor extensions"],
  ["secrets", "Credentials at rest on a device"],
  ["oversharing", "LLM responses returning restricted data"],
];

const DETECTORS = [
  { icon: <IconShield />, title: "Prompt threats", surface: "llm_io", body: "Instruction-override / injection, jailbreak & guardrail-evasion, and system-prompt / secret exfiltration. Matches a normalized view of the text (folds homoglyph, full-width, zero-width & spacing tricks) and decodes base64 blobs to re-scan hidden payloads." },
  { icon: <IconTarget />, title: "Shadow-AI", surface: "ai_usage · mcp", body: "Secrets, PII (SSN with/without dashes, Luhn-valid cards, IBAN / national IDs, single-record combos), proprietary source code, and confidential business content — including classification labels (TLP, Purview/MIP)." },
  { icon: <IconAlert />, title: "Agentic (MCP) guard", surface: "mcp", body: "Sensitive-file access, dangerous commands, tool-poisoning, and untrusted MCP servers — read off the agent's tool-use, even for local stdio MCP." },
  { icon: <IconClipboard />, title: "Supply-chain & IDE", surface: "deps · ide", body: "Risky dependency manifests (install-script abuse, non-registry sources, known-bad packages + OSV CVEs) and unapproved editor extensions." },
  { icon: <IconPlug />, title: "Credentials at rest", surface: "secrets", body: "Live keys on managed endpoints — cloud SA keys, .npmrc, .git-credentials, key files — optionally with TruffleHog/Gitleaks verification." },
  { icon: <IconInbox />, title: "Agent safety & oversharing", surface: "ide · oversharing", body: "Unsafe coding-agent autonomy (YOLO / auto-apply / --dangerously-skip-permissions), dangerous commands in AI chats, and need-to-know oversharing — an LLM returning restricted data to the wrong recipient." },
];

const TIERS = [
  { cls: "t-crit", badge: "Tier 1", title: "Known formats", action: "hard block", body: "Distinctive-prefix patterns — OpenAI, Anthropic, AWS, GitHub (incl. fine-grained PATs), GitLab, Stripe, Slack, Google, npm/PyPI, PEM keys, JWTs, labeled key=value. Near-certain, full weight." },
  { cls: "t-high", badge: "Tier 1b", title: "Evasion variants", action: "hard block", body: "The same prefixes with the separator stripped (ghp_… → ghp…). A real key never ships without its delimiter, so this reads as a deliberate DLP bypass." },
  { cls: "t-susp", badge: "Tier 2", title: "High-entropy heuristic", action: "warn", body: "Novel / vendor tokens with no known prefix, caught via Shannon entropy + mixed character classes — excluding hex digests (git SHAs) and UUIDs. Lower-confidence, so it warns." },
  { cls: "t-ai", badge: "Custom", title: "Your own patterns", action: "your call", body: "Per-org secret / PII / confidential regexes (customer IDs, account numbers, MRNs, codenames) — applied across every plane, no redeploy." },
];

const SEVERITIES = [
  ["critical", "80–100", "block", "A verified secret, or several strong signals at once."],
  ["high", "60–79", "quarantine", "A strong data-loss or attack signal."],
  ["suspicious", "35–59", "quarantine", "Worth review — often a warn in monitor mode."],
  ["low", "15–34", "monitor", "A minor or low-confidence signal."],
  ["benign", "0–14", "allow", "No meaningful risk signal."],
];

export default function HowItWorks() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">HOW IT WORKS</div>
        <h1>How Warden works</h1>
        <p>Every piece of AI-bound content ends up as one risk verdict. The engine is regex and
           heuristics — deterministic, millisecond-fast, and it calls no third-party AI service
           to reach a decision.</p>
      </section>

      {/* Pipeline */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Everything runs through the same five steps</h2>
          <p className="lp-sub">A prompt to your own model, a paste into ChatGPT, an action an AI
             assistant is about to take, a commit — one pipeline, one policy, one console. Each
             step is spelled out below.</p>
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

      {/* Surfaces */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Routed by surface</h2>
          <p className="lp-sub">Each submission is tagged with where it came from. The engine runs
             only the detectors that declare that surface — and one that errors can never sink the analysis.</p>
          <div className="hiw-surfaces">
            {SURFACES.map(([key, desc]) => (
              <div className="hiw-surface" key={key}>
                <code>{key}</code><span>{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Detectors */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">The offline detectors</h2>
          <p className="lp-sub">Each emits <strong>signals</strong> — pieces of evidence carrying a
             <em> weight</em> (how much it matters) and a <em>confidence</em> (how sure it is).</p>
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
          <p className="lp-sub">A <strong>saturating probabilistic OR</strong> — a few strong signals
             reliably escalate, while many weak ones can't trivially max the score. Attack / data-loss
             is the base; an "AI-generated" read only amplifies, never fires on its own.</p>
          <div className="hiw-formula">
            <code>risk = 1 − Π ( 1 − weightᵢ × confidenceᵢ )</code>
            <span>combined, mapped to 0–100 → a severity and a recommended action</span>
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

      {/* Monitor vs enforce */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Monitor or enforce</h2>
          <p className="lp-sub">Every capture point runs in one of two modes — roll out on monitor, then flip to enforce.</p>
          <div className="hiw-modes">
            <div className="hiw-mode">
              <h3><span className="hiw-dot dot-monitor" /> Monitor</h3>
              <p>Nothing is blocked — content passes through and findings are recorded. Ideal for a
                 rollout's first phase, so you see exactly what would trip before enforcing.</p>
            </div>
            <div className="hiw-mode hiw-mode-enforce">
              <h3><span className="hiw-dot dot-enforce" /> Enforce</h3>
              <p>Findings at or above your block severity are stopped at the source: the extension
                 shows a block modal, the gateway returns an error, the git hook fails the commit.</p>
            </div>
          </div>
          <p className="lp-sub" style={{ marginTop: 18 }}>Source-code detection is auto-suppressed for
             sanctioned coding tools (Claude Code, Cursor, Copilot) — but a <em>secret</em> inside that
             code still blocks.</p>
        </div>
      </section>

      {/* Everything lands in one console */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">…into one console</h2>
          <p className="lp-sub">Every verdict, across every plane, scored and triageable in one place.</p>
          <Shot lead src="/shots/dashboard.png" alt="Warden findings dashboard" />
        </div>
      </section>

      {/* Offline-first CTA band */}
      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>Offline-first — the judge is additive.</strong> Everything above runs with no API
              key and no outbound call: fast, private, deterministic. Connect a frontier model (Claude,
              GPT, or Gemini) and the LLM judge reads content like an analyst for the novel cases the
              rules miss — turn it off for data-residency and the engine still fully works.
            </div>
            <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Open the console →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
