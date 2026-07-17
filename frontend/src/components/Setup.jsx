// Public setup walkthrough at /setup. A short video plus the written steps for both the
// self-serve (one command) path and the org-wide MDM rollout. Mirrors the Connect page in
// the console — kept in sync with app/distribution.py + docs/mdm-policy-pack.md.
import { SiteNav, SiteFooter, Clip } from "./SiteChrome.jsx";

const SELF = [
  { n: "1", title: "Get your capture key",
    body: "Open the console → Connect → “Generate a capture key.” Every source authenticates with this one org key and routes its findings back here." },
  { n: "2", title: "Run one command",
    body: "On any machine, run warden-connect <your-url>. It signs you in and configures Claude Code, Cursor, and agent tool-call hooks to route through the gateway — no manual config files." },
  { n: "3", title: "Finish the browser extension",
    body: "Install the Warden extension for Chrome/Edge, then open the link the command prints to bind it to your org. Now claude.ai, ChatGPT, and Gemini are covered too." },
  { n: "4", title: "Watch findings roll in",
    body: "The Findings view shows live risk verdicts from the gateway, the browser extension, and the egress proxy — allow, warn, or block, by surface and severity." },
];

const ORG = [
  { n: "1", title: "Pick how you ship software",
    body: "Connect → Quick start. Choose an MDM policy pack (Jamf · Intune · GPO) or a per-OS setup script. Warden generates everything already pointed at your org and pre-loaded with your policy." },
  { n: "2", title: "Push the pack fleet-wide",
    body: "One pack your MDM pushes: extension force-install, egress-proxy profile, and Claude Code managed settings + hooks. Agentless — nothing to install per device." },
  { n: "3", title: "Confirm coverage",
    body: "Discovery and Coverage show every AI tool in use across teams — sanctioned or not — with the real sensitive-data exposure each one received." },
];

function Steps({ items }) {
  return (
    <div className="lp-cards">
      {items.map((s) => (
        <div key={s.n} className="lp-card">
          <span className="lp-card-icon">{s.n}</span>
          <h3>{s.title}</h3>
          <p>{s.body}</p>
        </div>
      ))}
    </div>
  );
}

export default function Setup() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">GET STARTED</div>
        <h1>Set up Warden</h1>
        <p>Cover one machine in a single command, or your whole fleet with one MDM pack.
           Here’s the whole thing end to end.</p>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <Clip lead src="/shots/setup.mp4" poster="/shots/setup-poster.png"
                caption="Self-serve in one command (Claude Code, Cursor, browser), then an agentless org-wide rollout via MDM — ending in full coverage across every team." />
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 1 — you & your team</h2>
          <p className="lp-sub">The fastest way to protect your own machine. About two minutes.</p>
          <Steps items={SELF} />
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Part 2 — your whole org (MDM)</h2>
          <p className="lp-sub">One pack, pushed to every device by your existing MDM. No agent, no per-user setup.</p>
          <Steps items={ORG} />
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-cta-wrap" style={{ textAlign: "center" }}>
          <h2 className="lp-h2">Ready to set it up?</h2>
          <p className="lp-sub">Open the console and head to Connect — everything you saw here is one click away.</p>
          <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Open the console →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
