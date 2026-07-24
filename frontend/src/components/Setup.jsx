// Public setup walkthrough at /setup. A short video plus the written steps for both the
// self-serve (one command) path and the org-wide MDM rollout. Mirrors the Connect page in
// the console — kept in sync with app/distribution.py + docs/mdm-policy-pack.md.
import { SiteNav, SiteFooter, Clip } from "./SiteChrome.jsx";

const SELF = [
  { n: "1", title: "Get your capture key",
    body: "Open the console → Connect → “Generate a capture key.” Every source authenticates with this one org key and routes its findings back here." },
  { n: "2", title: "Run one command",
    body: "On any machine, run  curl -fsSL <your-url>/install.sh | bash . It signs you in (a browser window opens), installs the governance CLI, wires prompt + tool-call hooks into Claude Code, Cursor, Codex, and Gemini CLI (prompts are scanned locally before they leave — even on subscription sign-ins no gateway ever sees), and stands up the sudo-free egress proxy for everything else — all subscription-compatible, no config files. Add  --desktop  to also cover the Claude/ChatGPT desktop apps and browsers system-wide." },
  { n: "3", title: "Finish the browser extension",
    body: "Install the Warden extension for Chrome/Edge from the Web Store, then click “Sign in to Warden” in its popup to bind it to your org. Now claude.ai, ChatGPT, and Gemini are covered too." },
  { n: "4", title: "Route through your provider account (optional · admin)",
    body: "Want a hard, unbypassable gateway instead of the local proxy? In Settings → Gateway upstreams, paste your org's Anthropic (or OpenAI / Gemini) API key and warden-connect will point Claude Code at the gateway. This bills to your API account rather than each user's subscription — leave it unset to keep the subscription-friendly proxy path above." },
  { n: "5", title: "Watch findings roll in",
    body: "The Findings view shows live risk verdicts from the gateway, the browser extension, and the egress proxy (CLIs + desktop apps) — allow, warn, or block, by surface and severity." },
];

const ORG = [
  { n: "1", title: "Pick how you ship software",
    body: "Connect → Quick start. Choose an MDM policy pack (Jamf · Intune · GPO) or a per-OS setup script. Warden generates everything already pointed at your org and pre-loaded with your policy." },
  { n: "2", title: "Push the pack fleet-wide",
    body: "One pack your MDM pushes: extension force-install, egress-proxy profile, and Claude Code managed settings + hooks. Agentless — nothing to install per device. Set your org's model key first (Part 1, step 4) so gateway-routed Claude Code keeps answering; the proxy leg also needs your root CA in the device trust store." },
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
          <Clip lead src="/shots/setup.mp4?v=2" poster="/shots/setup-poster.png"
                caption="Self-serve in one command (Claude Code, Cursor, and the AI CLIs via the sudo-free egress proxy; browsers via the extension), then an agentless org-wide rollout via MDM, ending in full coverage across every team." />
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
