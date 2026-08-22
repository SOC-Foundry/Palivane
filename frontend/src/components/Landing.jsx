import { useState } from "react";
import { IconShield, IconPlug, IconTarget, IconAlert, IconInbox, IconClipboard } from "./icons.jsx";
import { SiteNav, SiteFooter, Shot, Clip, Lightbox } from "./SiteChrome.jsx";

// The page alternates deliberately: a full-bleed band, then a two-column split, then the
// mirror of that split, then a card row. The previous version stacked five identical
// centred heading + subhead + grid blocks, which gave a reader no sense of progress and
// made every section feel equally weighted.

const STATS = [
  { n: "6", l: "surfaces covered", s: "browser, desktop, CLI, CI, cloud storage, MCP" },
  { n: "0", l: "content leaves your org", s: "detection runs inside your own deployment" },
  { n: "28", l: "detection checks", s: "secrets, PII, source code, prompt attacks" },
  { n: "1", l: "afternoon to set up", s: "one command, nothing to install by hand" },
];

const CAPTURE = [
  { icon: <IconPlug />, title: "In the browser", body: "What people paste into ChatGPT, Claude, Gemini, and Copilot on the web." },
  { icon: <IconInbox />, title: "In desktop apps", body: "The AI apps that never touch a browser: Claude and ChatGPT desktop." },
  { icon: <IconShield />, title: "In coding tools", body: "Claude Code, Cursor, Codex, and Gemini CLI report every prompt and tool call." },
  { icon: <IconClipboard />, title: "In code and laptops", body: "Commits and dependencies before they land, and credentials already at rest." },
  { icon: <IconAlert />, title: "In GitHub Actions", body: "Coding agents running on CI runners with your production credentials." },
];

const LOOKS_FOR = [
  { title: "Passwords, keys, and tokens", body: "Cloud keys, API tokens, private keys, and database passwords, in prompts and in what an assistant sends back." },
  { title: "Personal and customer data", body: "Social security numbers, payment cards, and customer records, tuned so ordinary engineering work does not trip it." },
  { title: "Code and confidential documents", body: "Proprietary source, financials, contracts, and material carrying a classification label." },
  { title: "Risky AI behaviour", body: "Attempts to hijack an assistant's instructions, talk it past its rules, or smuggle payloads through hidden characters." },
  { title: "Dangerous agent actions", body: "File reads and shell commands an assistant proposes, checked before they run rather than logged after." },
  { title: "A second opinion, optionally", body: "Everything above runs on the built-in engine. An LLM judge can review the ambiguous cases if you want one." },
];

const FAQ = [
  { q: "Does anything have to be installed on every laptop?",
    a: "No. The browser extension can be force-installed by policy and the CLI coverage arrives through one command that a person runs once, or through your MDM. Nothing needs a per-machine visit." },
  { q: "Do our prompts leave the company?",
    a: "No. Detection runs inside your own deployment. Content is never sent to a third-party AI service for scoring, and the default posture records metadata only, not prompt text." },
  { q: "Will it break the AI tools people already pay for?",
    a: "No. Personal Claude and ChatGPT sign-ins keep working, because the hooks score prompts locally rather than routing them through a gateway. Gateway routing is available, and optional." },
  { q: "What happens the moment we turn it on?",
    a: "Nothing is blocked. Palivane starts in monitor mode, so the first thing you get is an inventory of which AI tools are in use and what has been going to them. Enforcement is a switch you flip later." },
  { q: "What if the backend is unreachable?",
    a: "Capture fails open. A down collector never blocks a prompt or breaks a developer's tool. Confirmed secret and PII leaks are the exception and still hard-block." },
  { q: "How much of a team does this need to run?",
    a: "One person, part time. It is designed to be set up once and then mostly leave you alone: domain claim for onboarding, policy defaults that are sensible on day one, and digests rather than a queue to work." },
];

export default function Landing({ onSignIn }) {
  const [zoom, setZoom] = useState(null);   // {src, alt} when a screenshot is enlarged
  const [openQ, setOpenQ] = useState(0);
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
            Palivane shows you what they send, and <strong>stops the customer data, passwords,
            and source code that shouldn't go</strong>.
          </p>
          <div className="lp-cta">
            <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>
            <a className="lp-nav-ghost wide" href="/setup">Set it up</a>
          </div>
          <div className="lp-hero-cmd">
            <code>curl -fsSL https://app.palivane.io/install.sh | bash</code>
            <span>one command, monitor mode, nothing blocked yet</span>
          </div>
        </div>
      </section>

      <section className="lp-stats-band">
        <div className="lp-wrap lp-stats">
          {STATS.map((s) => (
            <div key={s.l} className="lp-stat">
              <span className="lp-stat-n">{s.n}</span>
              <span className="lp-stat-l">{s.l}</span>
              <span className="lp-stat-s">{s.s}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-split">
          <div className="lp-split-text">
            <span className="lp-eyebrow">See it work</span>
            <h2 className="lp-h2">The same secret, stopped eight times</h2>
            <p className="lp-sub">A hundred seconds: one customer export and one AWS key blocked in
              Claude, ChatGPT and Gemini, in Claude Code, Codex and Cursor, in an S3 bucket, and in
              a GitHub Actions run. Then a walkthrough of every screen it lands in.</p>
            <a className="lp-textlink" href="/how-it-works">How the detection works →</a>
          </div>
          <div className="lp-split-media">
            <Clip src="/shots/demo14.mp4" poster="/shots/demo-poster14.png" />
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-split lp-split-rev">
          <div className="lp-split-text">
            <span className="lp-eyebrow">Visibility</span>
            <h2 className="lp-h2">You finally know which AI tools are in use</h2>
            <p className="lp-sub">Every AI tool your company touches, who or which repo is using it,
              and what data went where, including the ones nobody asked permission for. Unlike
              log-only tools, the exposure column shows the real sensitive data each one received.</p>
            <a className="lp-textlink" href="/coverage">What each surface requires →</a>
          </div>
          <div className="lp-split-media">
            <Shot src="/shots/discovery.png?v=4" alt="Inventory of AI tools in use"
                  onZoom={(s, a) => setZoom({ src: s, alt: a })} />
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-split">
          <div className="lp-split-text">
            <span className="lp-eyebrow">Agents</span>
            <h2 className="lp-h2">AI coding assistants stay inside the lines</h2>
            <p className="lp-sub">Claude Code, Cursor, and Copilot read your files and run your
              commands. Palivane gives each assistant its own identity and boundary, then checks
              every action before it happens rather than logging it afterwards.</p>
            <a className="lp-textlink" href="/use-cases#engineering">How engineering teams use it →</a>
          </div>
          <div className="lp-split-media">
            <Shot src="/shots/agents.png?v=4" alt="AI assistant identity and limits"
                  onZoom={(s, a) => setZoom({ src: s, alt: a })} />
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <h2 className="lp-h2">It works wherever your team uses AI</h2>
            <p className="lp-sub">Nobody has to remember to run anything, and everything lands in
              the same console.</p>
          </div>
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
        <div className="lp-wrap lp-split lp-split-narrow">
          <div className="lp-split-text sticky">
            <span className="lp-eyebrow">Detection</span>
            <h2 className="lp-h2">What Palivane looks for</h2>
            <p className="lp-sub">Every check runs inside your deployment in milliseconds. No
              third-party AI service ever sees your content. One risk score decides whether to
              allow, warn, or block.</p>
            <a className="lp-textlink" href="/how-it-works">The scoring model →</a>
          </div>
          <ul className="lp-checklist">
            {LOOKS_FOR.map((s) => (
              <li key={s.title}>
                <h3>{s.title}</h3>
                <p>{s.body}</p>
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-faq-wrap">
          <div className="lp-band-head">
            <h2 className="lp-h2">Questions people ask first</h2>
          </div>
          <div className="lp-faq">
            {FAQ.map((f, i) => (
              <div key={f.q} className={`lp-faq-item ${openQ === i ? "is-open" : ""}`}>
                <button type="button" className="lp-faq-q" aria-expanded={openQ === i}
                        onClick={() => setOpenQ(openQ === i ? -1 : i)}>
                  <span>{f.q}</span>
                  <span className="lp-faq-sign" aria-hidden="true" />
                </button>
                {openQ === i && <p className="lp-faq-a">{f.a}</p>}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-closing">
            <h2>Start by watching.</h2>
            <p>Run it in monitor mode to see what your team is really sending, then switch on
              blocking when you have seen enough.</p>
            <div className="lp-cta">
              <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>
              <a className="lp-nav-ghost wide" href="/setup">Set it up</a>
            </div>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
