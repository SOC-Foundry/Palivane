import { useState } from "react";
import { IconShield, IconPlug, IconTarget, IconAlert, IconInbox, IconClipboard } from "./icons.jsx";
import { SiteNav, SiteFooter, Shot, Clip, Lightbox } from "./SiteChrome.jsx";

const FRONTS = [
  {
    icon: <IconTarget />, tag: "Data protection", cls: "ai",
    title: "Nothing sensitive leaves by accident",
    body: "Customer records, passwords and API keys, and your own source code get caught on the way out — whether someone pastes them into ChatGPT or an AI assistant sends them for you.",
  },
  {
    icon: <IconInbox />, tag: "Visibility", cls: "mcp",
    title: "You finally know which AI tools are in use",
    body: "Every AI tool your company touches, who — or which repo — is using it, and what data went where, including the ones nobody asked permission for.",
  },
  {
    icon: <IconAlert />, tag: "AI assistants", cls: "atk",
    title: "AI coding assistants stay inside the lines",
    body: "Claude Code, Cursor, and Copilot read your files and run your commands. Warden checks each action before it happens and stops the dangerous ones.",
  },
];

const CAPTURE = [
  { icon: <IconPlug />, title: "In the browser", body: "Covers what people paste into ChatGPT, Claude, Gemini, and Copilot on the web — the most common way data walks out." },
  { icon: <IconInbox />, title: "In desktop apps", body: "Covers the AI apps that don't run in a browser: Claude and ChatGPT desktop, and the assistants built into editors." },
  { icon: <IconShield />, title: "In your AI coding tools", body: "Claude Code, Cursor, Codex, and Gemini CLI report what they're about to send or do, so it can be checked first." },
  { icon: <IconClipboard />, title: "In your code and laptops", body: "Scans commits and dependencies before they land, and finds credentials already sitting on developer machines — where info-stealing malware looks first." },
  { icon: <IconAlert />, title: "In GitHub Actions", body: "Coding agents increasingly run on CI runners, with your deploy keys in reach and nobody watching. Warden checks what they can touch — before you merge the workflow that gives it to them." },
];

const STEPS = [
  { n: "1", title: "Passwords, keys, and tokens", body: "Cloud keys, API tokens, private keys, database passwords — in prompts, in what an AI assistant sends, and sitting on laptops." },
  { n: "2", title: "Personal and customer data", body: "Social security numbers, payment cards, and customer records — tuned so everyday engineering work doesn't set off alarms." },
  { n: "3", title: "Your code and confidential documents", body: "Proprietary source code, financials, contracts, and anything already marked confidential by your own labeling tools." },
  { n: "4", title: "Risky AI behavior", body: "Attempts to hijack an AI's instructions, talk it past its rules, or get an assistant to run destructive commands or open files it shouldn't — in the tools your team uses, and in any AI feature you ship in your own product." },
  { n: "5", title: "A second opinion, if you want one", body: "Optionally add Claude, GPT, or Gemini as a reviewer for the unusual cases fixed rules miss. Everything above works without it." },
];

const ENTERPRISE = [
  { icon: <IconPlug />, title: "Onboarding that doesn't need a project plan", body: "Claim your email domain and teammates who sign up land in your org automatically. Invites, password reset, and single sign-on (Okta, Entra, Google) are built in." },
  { icon: <IconShield />, title: "Nothing to install on laptops", body: "No agent to roll out. If you use Jamf, Intune, or Group Policy, Warden hands you the config to push and you're done. Optional local helpers add depth on the machines where you want it." },
  { icon: <IconTarget />, title: "Proof it's actually working", body: "See which people and teams are covered and which aren't. Alerts land in Slack, findings flow to your SIEM or data lake, and a monthly report gives your board the numbers." },
  { icon: <IconClipboard />, title: "Your data stays yours", body: "Choose what gets recorded, export everything at any time, and delete your org in one click. Signed DPA available; content can be scanned without ever being stored." },
];

export default function Landing({ onSignIn }) {
  const [zoom, setZoom] = useState(null);   // {src, alt} when a screenshot is enlarged
  return (
    <div className="landing">
      <Lightbox src={zoom?.src} alt={zoom?.alt} onClose={() => setZoom(null)} />
      <SiteNav onSignIn={onSignIn} />

      <section className="lp-hero-wrap">
        <div className="lp-hero">
          <div className="lp-tagline">AI SECURITY FOR THE TOOLS YOUR TEAM ALREADY USES</div>
          <h1>Your secrets shouldn't leave with the prompt.</h1>
          <p className="lp-lead">
            Your team uses ChatGPT, Claude, Copilot, and AI coding assistants every day.
            Warden shows you what they send — and <strong>stops the customer data, passwords,
            and source code that shouldn't go</strong>. Set up in an afternoon, with nothing
            to install on anyone's laptop.
          </p>
          <div className="lp-cta">
            <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>
            <a className="lp-btn-ghost wide" href="/setup">Set it up</a>
            <a className="lp-btn-ghost wide" href="/how-it-works">How it works</a>
          </div>
          <span className="lp-cta-note">Start by watching only — turn on blocking when you're ready</span>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">See it stop a real leak</h2>
          <p className="lp-sub">Ninety seconds: the same customer export and AWS key stopped in
             Claude, ChatGPT and Gemini, in Claude Code, Codex and Cursor, in an S3 bucket and in
             a GitHub Actions run — then all of it in one console.</p>
          <Clip lead src="/shots/demo11.mp4" poster="/shots/demo-poster11.png"
                caption="Eight places the same secret tried to escape — and the one console it all lands in. Every verdict, risk score and fix in the video is live output from a running Warden instance." />
          <div className="lp-gallery">
            <Shot src="/shots/discovery.png?v=2" alt="Inventory of AI tools in use" onZoom={(s, a) => setZoom({ src: s, alt: a })}
                  caption="Every AI tool in use, broken down by team — and what data actually went to each one." />
            <Shot src="/shots/policies.png?v=2" alt="Policy console" onZoom={(s, a) => setZoom({ src: s, alt: a })}
                  caption="Turn individual checks on or off, org-wide or for one team." />
            <Shot src="/shots/agents.png?v=2" alt="AI assistant identity and limits" onZoom={(s, a) => setZoom({ src: s, alt: a })}
                  caption="Give each AI assistant its own identity and limits — watch first, enforce when ready." />
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">What changes on day one</h2>
          <p className="lp-sub">Three problems, one product — and one place to see all of it.</p>
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
          <h2 className="lp-h2">It works wherever your team uses AI</h2>
          <p className="lp-sub">Nobody has to remember to run anything. Warden watches the places AI is
             actually used, and everything lands in the same console.</p>
          <div className="lp-cards lp-cards-5">
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
          <h2 className="lp-h2">What Warden looks for</h2>
          <p className="lp-sub">Every check runs inside Warden in milliseconds — no third-party AI
             service ever sees your content — then one risk score decides whether to allow,
             warn, or block.</p>
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
            <a className="lp-textlink" href="/how-it-works">For the technically minded: the detection
            surfaces, the two-tier secret engine, the scoring model, and why the core runs
            offline →</a>
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Built for a small team to run</h2>
          <p className="lp-sub">You should not need a dedicated headcount to govern AI. Warden is
             designed to be set up once and then mostly leave you alone.</p>
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
              <strong>Start by watching.</strong> Run it in monitor mode to see what your team is
              really sending, then switch on blocking when you have seen enough.
            </div>
            <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
