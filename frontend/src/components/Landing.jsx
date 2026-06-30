import { IconShield, IconPlug, IconTarget, IconAlert, IconInbox } from "./icons.jsx";

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
];

const CAPTURE = [
  { icon: <IconShield />, title: "LLM gateway", body: "An OpenAI-, Anthropic- & Gemini-compatible proxy. Point your apps and Claude Code at Warden and every prompt is scored before it reaches the model." },
  { icon: <IconPlug />, title: "Browser extension", body: "Intercepts what employees paste into claude.ai, ChatGPT, and Gemini in the browser — warning or blocking on secrets and PII before send." },
  { icon: <IconInbox />, title: "Egress proxy", body: "A mitmproxy addon for desktop apps, IDE assistants, and CLIs that make their own HTTPS calls and never touch the browser." },
];

const STEPS = [
  { n: "1", title: "Prompt-threat detector", body: "Instruction-override & injection, jailbreak personas, system-prompt/secret exfiltration, and smuggled payloads — fully offline, no API key." },
  { n: "2", title: "Shadow-AI detector", body: "Credentials & keys, PII (SSN, Luhn-valid cards, contact lists), proprietary source code, and unsanctioned destinations." },
  { n: "3", title: "Claude judge (optional)", body: "Add an Anthropic key and claude-opus-4-8 reads the content like an analyst for the novel cases the rules miss." },
];

export default function Landing({ onSignIn }) {
  return (
    <div className="landing">
      <header className="lp-nav">
        <div className="lp-brand">
          <img src="/warden-logo.png" alt="Warden" width="34" height="34" />
          <span>Warden</span>
        </div>
        <button className="primary-btn slim" onClick={onSignIn}>Sign in</button>
      </header>

      <section className="lp-hero">
        <img className="lp-hero-logo" src="/warden-logo.png" alt="Warden" width="180" height="180" />
        <div className="lp-tagline">DETECT · BLOCK · PROTECT</div>
        <h1>Govern how your organization uses AI.</h1>
        <p className="lp-lead">
          Warden stops attacks on your own LLMs <strong>and</strong> stops sensitive data from
          leaking into AI tools — captured automatically at an LLM gateway, a browser extension,
          and a network egress proxy, then recorded or blocked inline.
        </p>
        <div className="lp-cta">
          <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>
          <span className="lp-cta-note">Runs offline · no API key required</span>
        </div>
      </section>

      <section className="lp-section">
        <h2 className="lp-h2">Two fronts, one engine</h2>
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
      </section>

      <section className="lp-section">
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
      </section>

      <section className="lp-section">
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
      </section>

      <section className="lp-banner">
        <IconAlert width={22} height={22} />
        <div>
          <strong>Monitor or enforce.</strong> Record every risky prompt and pass it through, or
          block it inline before it leaves — real prevention, not just detection.
        </div>
        <button className="primary-btn slim" onClick={onSignIn}>Sign in</button>
      </section>

      <footer className="lp-foot">
        <span>◆ Warden — AI Security Gateway</span>
        <span className="lp-foot-muted">Multi-tenant · role-based console · deployable with one command</span>
      </footer>
    </div>
  );
}
