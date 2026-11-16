// The clip library: every product walkthrough in one place, each pointing at the page that
// says it in full. The landing page leads with screenshots and the demo org on purpose; the
// clips live here so they are findable without carrying any page.
import { demoUrl } from "../deployment.js";
import { Clip, SiteFooter, SiteNav } from "./SiteChrome.jsx";

const CLIPS = [
  { id: "hero", src: "/shots/demo18.mp4?v=6", poster: "/shots/demo-poster19.png", length: "2 min",
    title: "What leaves, and what gets stopped",
    body: "Prompts to Claude, ChatGPT and Gemini in the browser; Claude Code, Codex and Cursor on the desktop; a key in S3 and an agent in GitHub Actions; a document in Drive and Slack. Each one scored, and the console at the end.",
    href: "/how-it-works", link: "How it works" },
  { id: "tour", src: "/shots/console-tour2.mp4", poster: "/shots/console-poster2.png", length: "30 s",
    title: "Thirty seconds through the console",
    body: "Findings and their evidence, the shadow-AI inventory, coverage, policies and the report. Silent on purpose.",
    href: demoUrl(), link: "Open the demo org" },
  { id: "setup", src: "/shots/setup8.mp4?v=5", poster: "/shots/setup-poster8.png", length: "1 min",
    title: "Install on one machine, then the whole org",
    body: "The Connect page, the one-command install, Settings, and the MDM push that rolls it out everywhere.",
    href: "/setup", link: "Set it up" },
  { id: "agents", src: "/shots/agent-demo.mp4?v=6", poster: "/shots/agent-demo-poster.png", length: "30 s",
    title: "Agents that act",
    body: "The analyst investigating a credential-leak finding, attestation allowing an OIDC agent while blocking an unattested one, and the agent-to-agent flow graph.",
    href: "/agents", link: "The agent story" },
  { id: "mcp", src: "/shots/mcp-demo.mp4?v=6", poster: "/shots/mcp-demo-poster.png", length: "30 s",
    title: "Working the queue from Claude",
    body: "The MCP server: findings, the shadow-AI inventory, triage and OWASP coverage, asked for in plain language from Claude Code or Desktop.",
    href: "/how-it-works", link: "How the MCP server fits" },
];

export default function Demos() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">DEMOS</div>
        <h1>Five short clips, <span className="lp-hl">no sign-up.</span></h1>
        <p className="lp-sub">Rendered from the product and narrated. Each one is under two minutes
           and links to the page that explains it. For the real thing, the demo org is a
           read-only console you can open now.</p>
        <div className="lp-cta">
          <a className="primary-btn" href={demoUrl()}>Open the demo org</a>
          <a className="lp-nav-ghost wide" href="/assessment">Run the 7-day assessment</a>
        </div>
      </section>

      {CLIPS.map((c, i) => (
        <section key={c.id} id={c.id} className={`lp-section${i % 2 ? " alt" : ""}`}>
          <div className="lp-wrap">
            <div className="lp-band-head">
              <span className="lp-eyebrow">{c.length}</span>
              <h2 className="lp-h2">{c.title}</h2>
            </div>
            <Clip src={c.src} poster={c.poster} caption={c.body} />
            <p className="lp-sub" style={{ textAlign: "left", margin: "14px 0 0" }}>
              <a className="lp-textlink" href={c.href}>{c.link} →</a>
            </p>
          </div>
        </section>
      ))}

      <SiteFooter />
    </div>
  );
}
