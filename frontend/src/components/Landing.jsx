import { IconShield, IconPlug, IconTarget, IconAlert, IconInbox, IconClipboard } from "./icons.jsx";
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

const FRONTS = [
  {
    icon: <IconShield />, tag: "Protect our AI", cls: "atk",
    title: "Stop attacks on your own LLMs",
    body: "Prompt injection, jailbreaks & guardrail-evasion personas, and system-prompt or secret exfiltration — caught at the gateway before they reach your model.",
  },
  {
    icon: <IconTarget />, tag: "Shadow-AI governance", cls: "ai",
    title: "Stop sensitive data leaking into AI tools",
    body: "Secrets, PII, and proprietary source code are blocked before they leave for ChatGPT, Claude, Gemini, or any unsanctioned destination.",
  },
  {
    icon: <IconAlert />, tag: "Agentic & supply chain", cls: "mcp",
    title: "Govern AI coding agents",
    body: "Inspect MCP tool-use (sensitive-file access, dangerous commands, tool poisoning, untrusted servers) and vet dependencies, MCP configs, and IDE extensions — agentlessly.",
  },
];

const CAPTURE = [
  { icon: <IconShield />, title: "LLM gateway", body: "An OpenAI-, Anthropic- & Gemini-compatible proxy. Point your apps and Claude Code at Warden — every prompt, and every agent tool-call, is scored before it reaches the model." },
  { icon: <IconPlug />, title: "Browser extension", body: "Intercepts what employees paste into claude.ai, ChatGPT, Gemini, and Copilot in the browser — warning or blocking on secrets and PII before send." },
  { icon: <IconInbox />, title: "Egress proxy", body: "A mitmproxy addon for desktop apps, IDE assistants, and CLIs — plus remote MCP servers — that make their own HTTPS calls and never touch the browser." },
  { icon: <IconClipboard />, title: "Git & CI", body: "A pre-commit hook + GitHub Action scan commits, dependency manifests (with OSV CVEs), MCP configs, and IDE extensions before they land in a repo." },
];

const STEPS = [
  { n: "1", title: "Prompt-threat detector", body: "Instruction-override & injection, jailbreak personas, system-prompt/secret exfiltration, and smuggled payloads — fully offline, no API key." },
  { n: "2", title: "Shadow-AI detector", body: "Credentials & keys, PII (SSN, Luhn-valid cards, contact lists), proprietary source code, and unsanctioned destinations." },
  { n: "3", title: "Agentic (MCP) guard", body: "An AI coding agent's tool-use — sensitive-file access, dangerous commands, tool poisoning, untrusted MCP servers — caught over the LLM traffic, even for local stdio MCP." },
  { n: "4", title: "Supply-chain scan", body: "Dependency manifests (install-script abuse, non-registry sources, known-bad packages + OSV CVEs) and IDE extensions, in CI." },
  { n: "5", title: "LLM judge (optional)", body: "Connect a frontier model — Claude, GPT, or Gemini — and it reads the content like an analyst for the novel cases the rules miss." },
];

const ENTERPRISE = [
  { icon: <IconPlug />, title: "Self-serve or managed onboarding", body: "Users bind their tenant by signing in (SSO) from the extension or `warden connect` for Claude Code — or push config zero-touch to managed fleets via MDM." },
  { icon: <IconShield />, title: "Agentless by default", body: "No endpoint agent for the core — an MDM policy pack (editor allowlist, system proxy, force-install, CA) lets Jamf/Intune/GPO enforce it. Opt-in local sensors add stdio-level MCP & pre-tool-use depth when you want it." },
  { icon: <IconTarget />, title: "See your blind spots", body: "Coverage reconciliation compares your IdP/CASB AI-usage to what Warden captured — the unmanaged, shadow set. Alerts (Slack) + SIEM export included." },
  { icon: <IconClipboard />, title: "Compliance & data control", body: "Per-tenant policy (monitor/enforce, block severity, sanctioned tools), a signed DPA, full self-serve data export, and one-click delete-my-org." },
];

export default function Landing({ onSignIn }) {
  return (
    <div className="landing">
      <SiteNav onSignIn={onSignIn} />

      <section className="lp-hero-wrap">
        <div className="lp-hero">
          <div className="lp-tagline">DETECT · BLOCK · PROTECT</div>
          <h1>Govern how your organization uses AI.</h1>
          <p className="lp-lead">
            Warden stops attacks on your own LLMs, stops sensitive data from leaking into AI tools,
            <strong> and</strong> governs AI coding agents (MCP) &amp; their supply chain — captured
            automatically at a gateway, browser extension, egress proxy, and CI, then recorded or
            blocked inline. <strong>Agentless by default.</strong>
          </p>
          <div className="lp-cta">
            <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>
            <a className="lp-btn-ghost wide" href="/how-it-works">How it works</a>
          </div>
          <span className="lp-cta-note">Core detection runs offline · no API key required</span>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">See Warden in action</h2>
          <p className="lp-sub">One console across every plane — findings, shadow-AI discovery,
             granular policy, and agent governance.</p>
          <figure className="lp-shot lp-shot-lead">
            <img src="/shots/dashboard.png" alt="Warden findings dashboard" loading="lazy" />
            <figcaption>Live risk verdicts from the gateway, browser extension, egress proxy &amp; CI.</figcaption>
          </figure>
          <div className="lp-gallery">
            <figure className="lp-shot">
              <img src="/shots/discovery.png" alt="Shadow-AI discovery inventory" loading="lazy" />
              <figcaption>Shadow-AI discovery — every AI tool, by team, with real data exposure.</figcaption>
            </figure>
            <figure className="lp-shot">
              <img src="/shots/policies.png" alt="Policy console" loading="lazy" />
              <figcaption>Granular policy — toggle any check, presets, per-user/group overrides.</figcaption>
            </figure>
            <figure className="lp-shot">
              <img src="/shots/agents.png" alt="Agent identity &amp; least-privilege" loading="lazy" />
              <figcaption>Agent identity &amp; least-privilege roles — monitor or enforce.</figcaption>
            </figure>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Three fronts, one engine</h2>
          <p className="lp-sub">One detection engine covers every way AI can put your organization at risk.</p>
          <div className="lp-fronts">
            {FRONTS.map((f) => (
              <div key={f.tag} className={`lp-front front-${f.cls}`}>
                <span className="lp-front-icon">{f.icon}</span>
                <span className={`tag tag-${f.cls}`}>{f.tag}</span>
                <h3>{f.title}</h3>
                <p>{f.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Automatic capture — no manual paste</h2>
          <p className="lp-sub">Different usage routes need different capture points. All feed one engine.</p>
          <div className="lp-cards">
            {CAPTURE.map((c) => (
              <div key={c.title} className="lp-card">
                <span className="lp-card-icon">{c.icon}</span>
                <h3>{c.title}</h3>
                <p>{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">How detection works</h2>
          <p className="lp-sub">Each submission runs through the detectors for its surface; a scoring engine fuses the signals into one risk verdict.</p>
          <div className="lp-steps">
            {STEPS.map((s) => (
              <div key={s.n} className="lp-step">
                <span className="lp-step-n">{s.n}</span>
                <div>
                  <h3>{s.title}</h3>
                  <p>{s.body}</p>
                </div>
              </div>
            ))}
          </div>
          <p className="lp-sub" style={{ marginTop: 22 }}>
            <a className="lp-textlink" href="/how-it-works">Read the technical overview — surfaces,
            the two-tier secret engine, the scoring model, and why the core runs offline →</a>
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Agentless, and enterprise-ready</h2>
          <p className="lp-sub">Deploy in minutes — agentless by default (optional local sensors for
             stdio-level depth): bind tenants, enforce via MDM, find the coverage gaps, and stay
             compliant.</p>
          <div className="lp-cards">
            {ENTERPRISE.map((c) => (
              <div key={c.title} className="lp-card">
                <span className="lp-card-icon">{c.icon}</span>
                <h3>{c.title}</h3>
                <p>{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconAlert width={22} height={22} />
            <div>
              <strong>Monitor or enforce.</strong> Record every risky prompt and pass it through, or
              block it inline before it leaves — real prevention, not just detection.
            </div>
            <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
