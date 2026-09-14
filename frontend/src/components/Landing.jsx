import { useState } from "react";
import { BrandClaude, BrandCursor, BrandCopilot, BrandGemini, BrandPerplexity, BrandOpenAI,
         BrandDrive, BrandSlack, BrandGit, BrandGitHub, BrandNpm, BrandActions,
         BrandSharePoint, BrandSalesforce, BrandTeams, BrandGmail } from "./brandicons.jsx";
import { SiteNav, SiteFooter, Shot, Clip, Lightbox } from "./SiteChrome.jsx";
// Derived from the detector source at build time (frontend/scripts/gen-stats.mjs, CI
// fails when stale) — the band can never claim different numbers than the engine ships.
import stats from "../stats.gen.json";
import { SELF_HOSTED, SIGN_IN_IS_CROSS_ORIGIN, demoUrl, signInUrl } from "../deployment.js";

// The page alternates deliberately: a full-bleed band, then a two-column split, then the
// mirror of that split, then a card row. The previous version stacked five identical
// centred heading + subhead + grid blocks, which gave a reader no sense of progress and
// made every section feel equally weighted.

const STATS = [
  { n: "8", l: "surfaces covered",
    s: "browser, desktop, CLI, CI, MCP, cloud storage, repos, and your SaaS document libraries" },
  SELF_HOSTED
    ? { n: "0", l: "content leaves your infrastructure", s: "detection runs on the backend you deploy" }
    : { n: "0", l: "prompt text kept by default", s: "the verdict and its metadata, not what was typed" },
  { n: `${stats.detection_checks}`, l: "detection checks",
    s: `${stats.secret_formats} credential formats, PII, source code, prompt attacks, agent actions` },
  { n: "1", l: "afternoon to set up", s: "one command, and your MDM pushes the rest" },
];

// Ordered by what a buyer can turn on soonest, not by how the planes are built. Coding
// tools first: it is a one-line install, it is where the expensive leaks are (source code,
// production credentials), and it is the surface a CASB and a browser-only tool cannot see
// at all. Desktop apps last, because that is the only plane needing a system proxy and a
// trusted CA, and leading with it puts an MDM project in front of the value.
// Brand colors for the surface-card logos (on-dark values; black marks lightened so they show).
const C = {
  claude: "#D97757", cursor: "#F2F2F2", copilot: "#F2F2F2", gemini: "#4285F4",
  openai: "#10A37F", perplexity: "#20B8CD", slack: "#36C5F0", drive: "#00AC47",
  sharepoint: "#038387", salesforce: "#00A1E0", git: "#F05133", github: "#F2F2F2",
  npm: "#CB3837", actions: "#2088FF", teams: "#7B83EB", gmail: "#EA4335",
};

const CAPTURE = [
  { logos: [[BrandClaude, C.claude], [BrandCursor, C.cursor], [BrandOpenAI, C.openai], [BrandCopilot, C.copilot], [BrandGemini, C.gemini]], title: "In coding tools", body: "Claude Code, Cursor, Codex, Copilot, and Gemini CLI report every prompt and tool call, and any other OpenAI/Anthropic/Gemini-compatible CLI (Grok CLI) is captured through the gateway. Posture scans surface the agents that can't be hooked (Cline, Roo, Windsurf, Amazon Q, Antigravity). One line to install." },
  { logos: [[BrandOpenAI, C.openai], [BrandClaude, C.claude], [BrandGemini, C.gemini], [BrandPerplexity, C.perplexity]], more: stats.browser_sites - 4, title: "In the browser", body: `What people paste into ChatGPT, Claude, Gemini, Copilot, Perplexity, Grok, Qwen, Kimi. ${stats.browser_sites} AI sites in all, including the app builders (v0, Bolt, Lovable, Replit).` },
  { logos: [[BrandSlack, C.slack], [BrandTeams, C.teams], [BrandGmail, C.gmail], [BrandDrive, C.drive], [BrandSharePoint, C.sharepoint], [BrandSalesforce, C.salesforce]], title: "In the places it already sits", body: "Slack, Microsoft Teams, Gmail, Google Drive, SharePoint, and Salesforce, scanned where the data lives, because an AI rollout will index all of it long before anyone pastes it into a prompt. Outbound mail is covered too, it's where leaks actually leave. Read-only access, nothing installed anywhere." },
  { logos: [[BrandGit, C.git], [BrandGitHub, C.github], [BrandNpm, C.npm]], title: "In code and laptops", body: "Commits and dependencies before they land, and credentials already at rest." },
  { logos: [[BrandActions, C.actions]], title: "In CI pipelines", body: "Coding agents running on CI runners with your production credentials. GitHub Actions, GitLab CI, CircleCI, and Azure Pipelines, one scanner." },
  { logos: [[BrandClaude, C.claude], [BrandOpenAI, C.openai]], title: "In desktop apps", body: "The AI apps that never touch a browser: Claude and ChatGPT desktop. The one plane that needs a system proxy and a trusted CA, so it is usually a second phase." },
];

const LINEAGE = [
  { title: "The finding names the source",
    body: "\"An AWS key went to ChatGPT\" is a ticket. \"The Q3 forecast in this Drive doc went to ChatGPT, pasted by this person, at this time\" is an answer." },
  { title: "Known org data scores higher",
    body: "A leak of material Palivane has already seen in your own systems is treated as more serious than the same text arriving from nowhere, because it is." },
  { title: "Blast radius, per document",
    body: "Start from a document instead of a finding: which prompts carried it, to which AI tools, from whom. The question an incident actually opens with." },
  { title: "It travels with the alert",
    body: "The source document rides along into webhooks, the SIEM export, and the report, so the context is there before anyone opens the console." },
];

const INSTALL_CMD = "curl -fsSL https://app.palivane.io/install.sh | bash";

const MCP_ASKS = [
  { title: "“What high-severity findings landed today, and who triggered them?”",
    body: "Listed by actor and surface, in the chat, no login." },
  { title: "“Mark finding 4821 triaged.”",
    body: "Work the queue from the assistant. Dismissing stays admin-only, enforced by the API." },
  { title: "“Which unsanctioned AI tools are in use, and what leaked to them?”",
    body: "The shadow-AI inventory, without opening a dashboard." },
  { title: "“Are we covered for the OWASP LLM Top 10?”",
    body: "Framework coverage, control by control." },
];

const LOOKS_FOR = [
  { title: "Passwords, keys, and tokens", body: "Nearly sixty credential formats (cloud keys, API tokens, private keys, database passwords, and every major AI provider's own keys) in prompts and in what an assistant sends back." },
  { title: "Personal and customer data", body: "Social security numbers, payment cards, and customer records, tuned so ordinary engineering work does not trip it." },
  { title: "Whatever the file happens to be", body: "A leak is more often an exported spreadsheet, a signed PDF, or a pasted screenshot than a typed sentence. Palivane reads all three. What it genuinely cannot open it reports as unread, never as clean." },
  { title: "Code and confidential documents", body: "Proprietary source, financials, contracts, and material carrying a classification label." },
  { title: "Risky AI behaviour", body: "Attempts to hijack an assistant's instructions, talk it past its rules, or smuggle payloads through hidden characters." },
  { title: "Dangerous agent actions", body: "File reads and shell commands an assistant proposes, checked before they run rather than logged after." },
  { title: "A second opinion, optionally", body: "Everything above runs on the built-in engine. An LLM judge can review the ambiguous cases if you want one." },
];

const FAQ = [
  { q: "Does anyone have to touch every laptop?",
    a: "No. Two things do go on a machine, a browser extension and a small CLI that wires the coding-tool hooks, but the extension is force-installed by browser policy and the CLI arrives through your MDM or one command a person runs once. Nothing needs a per-machine visit. The gateway and the SaaS connectors put nothing on a machine at all." },
  { q: "Where does our prompt text actually go?",
    a: SELF_HOSTED
      ? "To the Palivane backend you deploy, and nowhere beyond it. It never leaves your infrastructure, so there is no vendor holding your prompts. Scoring is deterministic (rules and heuristics, no AI service in the loop) unless you switch on the optional LLM judge, which does send the content it reviews to the model provider you choose."
      : "To Palivane, and nowhere beyond it. By default we record the verdict and its metadata and discard the text itself, so what we hold is that a prompt to ChatGPT carried an AWS key, not the prompt. Scoring is deterministic (rules and heuristics, no AI service in the loop) unless you switch on the optional LLM judge, which does send the content it reviews to a model provider — your own account if you supply a key, otherwise ours. Prefer that none of it reaches us at all? Self-hosting runs the same detection inside your own infrastructure, where none of it reaches us — a supported Enterprise deployment we hand over and help you stand up." },
  { q: "Will it break the AI tools people already pay for?",
    a: "No. Personal Claude and ChatGPT sign-ins keep working, because the hooks score a prompt alongside the request rather than putting a gateway in its path, so the tool still talks to the provider itself with its own credentials. Gateway routing is available, and optional: OpenAI, Anthropic, Gemini, Azure OpenAI, or any OpenAI-compatible provider." },
  { q: "What happens the moment we turn it on?",
    a: "Nothing is blocked. Palivane starts in monitor mode, so the first thing you get is an inventory of which AI tools are in use and what has been going to them. Enforcement is a switch you flip later." },
  { q: "What if the backend is unreachable?",
    a: "Capture fails open. A down collector never blocks a prompt or breaks a developer's tool. Confirmed secret and PII leaks are the exception and still hard-block." },
  { q: "How much of a team does this need to run?",
    a: "One person, part time. It is designed to be set up once and then mostly leave you alone: domain claim for onboarding, policy defaults that are sensible on day one, and digests rather than a queue to work." },
];

// "Open the console" is sign-in for anyone not already signed in, so it crosses hosts on
// the same rule as the nav's Sign in — see SiteChrome and deployment.js APP_ORIGIN.
function ConsoleCta({ onSignIn }) {
  return SIGN_IN_IS_CROSS_ORIGIN
    ? <a className="primary-btn slim" href={signInUrl()}>Open the console →</a>
    : <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>;
}


export default function Landing({ onSignIn }) {
  const [zoom, setZoom] = useState(null);   // {src, alt} when a screenshot is enlarged
  const [copied, setCopied] = useState(false);
  const copyInstall = async () => {
    try {
      // navigator.clipboard is undefined outside a secure context — a self-hosted console
      // on plain http is precisely where someone copies this line, so the old
      // execCommand path stays as the fallback rather than failing silently.
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(INSTALL_CMD);
      } else {
        const ta = document.createElement("textarea");
        ta.value = INSTALL_CMD;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* Clipboard denied by policy: the command stays selectable, so say nothing. */
    }
  };
  const [openQ, setOpenQ] = useState(0);
  return (
    <div className="landing lp-atmos">
      <Lightbox src={zoom?.src} alt={zoom?.alt} onClose={() => setZoom(null)} />
      <SiteNav onSignIn={onSignIn} />

      <section className="lp-hero-wrap">
        <div className="lp-hero">
          <div className="lp-tagline">AI SECURITY FOR THE TOOLS YOUR TEAM ALREADY USES</div>
          <h1>Your secrets shouldn't leave with the prompt.</h1>
          <p className="lp-lead">
            Your team uses ChatGPT, Claude, Copilot, and AI coding assistants every day. Your
            CASB can tell you someone opened chatgpt.com. Palivane tells you <strong>a customer
            export went into it</strong>, and stops the data, passwords, and source code that
            shouldn't go.
          </p>
          <div className="lp-cta">
            <ConsoleCta onSignIn={onSignIn} />
            {/* Straight into a read-only seeded org (Login auto-triggers on #demo) —
                security buyers want to see real findings before installing anything. */}
            <a className="lp-nav-ghost wide" href={demoUrl()}>See the live demo</a>
          </div>
          <div className="lp-hero-cmd">
            <div className="lp-cmd-row">
              <code>{INSTALL_CMD}</code>
              <button type="button" className="lp-copy" onClick={copyInstall}
                      aria-label={copied ? "Copied" : "Copy install command"}>
                {copied ? (
                  <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                          strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                       <path d="M20 6L9 17l-5-5" /></svg>Copied</>
                ) : (
                  <><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                          strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                       <rect x="9" y="9" width="11" height="11" rx="2" />
                       <path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>Copy</>
                )}
              </button>
            </div>
            <span>one command, monitor mode, nothing blocked yet</span>
          </div>
        </div>
      </section>

      {/* Shown, not described. Every value is visibly illustrative: both addresses sit on
          invented companies, and the key is the documented test payload from
          docs/pilot-smoke-test.md.

          READ THIS BEFORE CHANGING EITHER DOMAIN. These are real TLDs, chosen deliberately
          over .example so the card reads as a real incident. That trade has a standing
          cost: this page shows a fabricated credential leak next to a domain someone could
          register. Both were undelegated when chosen (no A, no NS) and harbourline.com was
          rejected because it IS registered and serving — but "unowned today" is not a
          property that keeps. REGISTER harbourline.io AND northwind.io, or move back to
          .example. Do not swap in another domain without checking it first. The actor stays: "who
          sent it" is precisely what a CASB cannot tell you, which is the card's whole
          argument. */}
      <section className="lp-section" style={{ paddingTop: 0, paddingBottom: 0 }}>
        <div className="lp-wrap">
          <div className="lp-evidence">
            <div className="lp-evidence-head">
              <span className="who">
                <span className="lp-evidence-tag">BLOCKED</span>
                <code>d.okafor@harbourline.io</code>
                <span aria-hidden="true" style={{ color: "var(--muted-2)" }}>→</span>
                <code>chatgpt.com</code>
              </span>
              <code style={{ color: "var(--muted-2)", fontSize: 12 }}>before send · finding #4471</code>
            </div>
            <div className="lp-evidence-body">
              <div className="lp-evidence-prompt">
                clean up this customer list and fix the deploy script<br />
                <span className="dim">name,email,plan,mrr</span><br />
                <span className="hit">j.reyes@northwind.io,enterprise,4200</span><br />
                <span className="dim">export AWS_ACCESS_KEY_ID=</span><span className="hit">AKIA4YTGH2NBQF7XZP3K</span>
              </div>
              <dl className="lp-evidence-meta">
                <div><dt>What was in it</dt><dd>An AWS access key, and 1,848 customer records</dd></div>
                <div><dt>Where it came from</dt><dd>Q3_accounts.csv, in Google Drive</dd></div>
                <div><dt>Caught by</dt><dd>The browser extension, before the prompt sent</dd></div>
              </dl>
            </div>
          </div>
          <p className="lp-evidence-foot">
            A CASB logs one line: <code>user visited chatgpt.com</code>. Everything above is the part that matters.
          </p>
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
            <Clip src="/shots/demo18.mp4" poster="/shots/demo-poster18.png" />
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-split lp-split-rev">
          <div className="lp-split-text">
            <span className="lp-eyebrow">Visibility</span>
            <h2 className="lp-h2">You finally know which AI tools are in use</h2>
            <p className="lp-sub">The AI tools your company touches, who or which repo is using it,
              and what data went where, including the ones nobody asked permission for. Every
              destination is classified against a catalog of {stats.catalog_tools} AI tools that
              ships with the engine. Unlike log-only tools, the exposure column shows the real
              sensitive data each one received, and names the devices reporting nothing rather
              than counting them as clean.</p>
            <a className="lp-textlink" href="/coverage">What each surface requires →</a>
          </div>
          <div className="lp-split-media">
            <Shot src="/shots/discovery.png?v=7" alt="Inventory of AI tools in use"
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
            <Shot src="/shots/agents.png?v=7" alt="AI assistant identity and limits"
                  onZoom={(s, a) => setZoom({ src: s, alt: a })} />
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-split">
          <div className="lp-split-text">
            <span className="lp-eyebrow">Headless</span>
            <h2 className="lp-h2">Run it from your own AI assistant</h2>
            <p className="lp-sub">Nobody wants another dashboard to check. Palivane ships an MCP
              server, so your team governs AI security from the assistant they already use, Claude
              or any MCP client: ask what leaked today, triage a finding, sync a connector, pull a
              compliance report, without opening the console. The surface we secure, offered as the
              way you drive it.</p>
            <ul className="lp-checklist lp-checklist-tight">
              {MCP_ASKS.map((s) => (
                <li key={s.title}><h3>{s.title}</h3></li>
              ))}
            </ul>
            <a className="lp-textlink" href="https://github.com/SOC-Foundry/palivane-clients/tree/main/mcp-server">Wire it into Claude Code or Desktop →</a>
          </div>
          <div className="lp-split-media">
            <Clip src="/shots/mcp-demo.mp4?v=2" poster="/shots/mcp-demo-poster.png"
                  caption="Working the triage queue from Claude, without opening the console." />
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <h2 className="lp-h2">It works wherever your team uses AI</h2>
            <p className="lp-sub">Nobody has to remember to run anything, and everything lands in
              the same console. Only desktop-app coverage needs a system proxy and a certificate:
              start with the rest and add it later, or never.</p>
          </div>
          <div className="lp-cards lp-cards-5">
            {CAPTURE.map((c) => (
              <div key={c.title} className="lp-card">
                <span className="lp-card-logos">
                  {c.logos.map(([Logo, color], i) => <Logo key={i} style={{ color }} />)}
                  {c.more ? <span className="lp-more" title={`+${c.more} more`}>+{c.more}</span> : null}
                </span>
                <h3>{c.title}</h3>
                <p>{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Lineage reads as a chain, so it runs horizontally — and it was the third
          text-beside-a-list section in a row, which is the rhythm problem the styling
          alone could not fix. */}
      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head">
            <span className="lp-eyebrow">Lineage</span>
            <h2 className="lp-h2">Not just what leaked. Which document it came out of.</h2>
            <p className="lp-sub">Every document Palivane scans in Drive, SharePoint,
              Salesforce, Slack, or Teams is fingerprinted. When text from one of them turns up in a
              prompt later, the finding names the source, and the exposure view works the
              other way too: pick a document and see everywhere it has surfaced.</p>
          </div>
          <div className="lp-trace">
            {LINEAGE.map((s, i) => (
              <div key={s.title}>
                <div className="n">{String(i + 1).padStart(2, "0")}</div>
                <h3>{s.title}</h3>
                <p>{s.body}</p>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 40 }}>
            <Shot src="/shots/dashboard.png?v=8" alt="Exposure view: one document, everywhere it surfaced"
                  caption="Start from a document instead of a finding."
                  onZoom={(s, a) => setZoom({ src: s, alt: a })} />
          </div>
          <a className="lp-textlink" href="/use-cases" style={{ display: "inline-block", marginTop: 18 }}>What that changes in an incident →</a>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-split lp-split-narrow">
          <div className="lp-split-text sticky">
            <span className="lp-eyebrow">Detection</span>
            <h2 className="lp-h2">What Palivane looks for</h2>
            <p className="lp-sub">Every check runs {SELF_HOSTED ? "inside your own deployment"
              : "on your Palivane backend"} in milliseconds, deterministic rules with no
              AI service in the loop. One risk score decides whether to allow, warn, or
              block.</p>
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
            {/* The one place on the landing page with a route to a human. The hero stays
                two self-serve CTAs on purpose; someone who has read to the bottom and
                still wants a conversation is exactly who should find this. */}
            <div className="lp-cta">
              <ConsoleCta onSignIn={onSignIn} />
              <a className="lp-nav-ghost wide" href="mailto:sales@palivane.io?subject=Palivane">
                Talk to sales</a>
            </div>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
