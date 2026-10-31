import { useEffect, useRef, useState } from "react";
import { BrandClaude, BrandCursor, BrandCopilot, BrandGemini, BrandPerplexity, BrandOpenAI,
         BrandDrive, BrandSlack, BrandGit, BrandGitHub, BrandNpm, BrandActions,
         BrandSharePoint, BrandSalesforce, BrandTeams, BrandGmail,
         BrandSnowflake, BrandDatabricks, GenericDatabase } from "./brandicons.jsx";
import { SiteNav, SiteFooter, Shot, Clip, Lightbox } from "./SiteChrome.jsx";
import { FAQ, FAQ_FIRST, Faq } from "./Faq.jsx";
// Derived from the detector source at build time (frontend/scripts/gen-stats.mjs, CI
// fails when stale) — the band can never claim different numbers than the engine ships.
import stats from "../stats.gen.json";
import { SELF_HOSTED, SIGN_IN_IS_CROSS_ORIGIN, demoUrl, signInUrl } from "../deployment.js";

// The page alternates deliberately: a full-bleed band, then a two-column split, then the
// mirror of that split, then a card row. The previous version stacked five identical
// centred heading + subhead + grid blocks, which gave a reader no sense of progress and
// made every section feel equally weighted.

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
  snowflake: "#29B5E8", databricks: "#FF3621",
};

const CAPTURE = [
  { logos: [[BrandClaude, C.claude], [BrandCursor, C.cursor], [BrandOpenAI, C.openai], [BrandCopilot, C.copilot], [BrandGemini, C.gemini]], title: "In coding tools", body: "Claude Code, Cursor, Codex, Copilot CLI, and Gemini CLI report prompts and tool calls. One line to install." },
  // Second: for a Claude Enterprise org it is the fastest thing to turn on (a URL and a key in
  // claude.ai, nothing on any device), and the only plane that sees Cowork cloud sessions.
  { logos: [[BrandClaude, C.claude]], title: "Across every Claude product", body: "For Claude Enterprise: Anthropic checks each prompt and tool call with Palivane before Claude runs it, across claude.ai, Cowork (cloud sessions too), Claude Code, and Claude in Chrome. Nobody has to touch a laptop." },
  { logos: [[BrandOpenAI, C.openai], [BrandClaude, C.claude], [BrandGemini, C.gemini], [BrandPerplexity, C.perplexity]], more: stats.browser_sites - 4, title: "In the browser", body: `What people paste into ${stats.browser_sites} AI sites, from ChatGPT and Claude to the app builders.` },
  { logos: [[BrandSlack, C.slack], [BrandTeams, C.teams], [BrandGmail, C.gmail], [BrandDrive, C.drive], [BrandSharePoint, C.sharepoint], [BrandSalesforce, C.salesforce]], title: "In the places it already sits", body: "Slack, Teams, Gmail (sent mail), Drive, SharePoint, and Salesforce, scanned where the data lives. Read-only by default, nothing installed." },
  { logos: [[BrandGit, C.git], [BrandGitHub, C.github], [BrandNpm, C.npm]], title: "In code and laptops", body: "Commits and their npm and pip dependencies before they land, and credentials already at rest." },
  { logos: [[BrandGitHub, C.github]], title: "In your repositories", body: "Keys committed to GitHub, including ones deleted in the last 90 days (up to a year). Checked on a schedule, or within seconds of a push." },
  { logos: [[GenericDatabase, "#9AA7A0"]], title: "In your databases", body: "Provider keys kept in clear in a Postgres or SQLite table. A read-only, sampled scan that runs inside your network." },
  { logos: [[BrandSnowflake, C.snowflake], [BrandDatabricks, C.databricks]], title: "In the data warehouse", body: "Snowflake Cortex, read from the warehouse's own query history, and Databricks Model Serving, read from its AI Gateway inference tables once you enable them. It reports rather than blocks." },
  { logos: [[BrandActions, C.actions]], title: "In CI pipelines", body: "Agents on CI runners with production credentials. GitHub Actions across the org; GitLab CI, CircleCI, and Azure Pipelines configs scanned in the repo." },
  { logos: [[BrandClaude, C.claude], [BrandOpenAI, C.openai]], title: "In desktop apps and AI extensions", body: "Claude and ChatGPT desktop, Claude in Chrome, and AI sidebar extensions like Monica and Sider. A blocked message says why: Claude explains it in the conversation, and sidebar extensions show it as an error. Needs a system proxy and a trusted CA, so it is usually phase two." },
  // Was its own "Headless" section. The MCP server is one more place Palivane runs, so it is
  // one more tab: the link and the clip stay reachable from here.
  { logos: [[BrandClaude, C.claude]], title: "From your own AI assistant", notSurface: true, body: "Palivane ships an MCP server, so you can ask Claude what leaked recently without opening the console. Connect over OAuth to ask questions and, if you allow it, triage findings; run it locally with a write key to also pull a compliance report.",
    links: [["https://github.com/SOC-Foundry/palivane-clients/tree/main/mcp-server", "Wire it into Claude Code or Desktop"],
            ["/shots/mcp-demo.mp4?v=2", "Watch it work the triage queue"]] },
];

// Number and label only. Each tile used to carry a second line of small print; the surfaces
// are listed one section down and the data handling is the first FAQ answer. The surface
// count is the tabs above, less the one that is Palivane's own MCP server rather than a place
// it captures: a hand-written number here said 8 while the page listed 9, then 10.
const STATS = [
  { n: `${CAPTURE.filter((c) => !c.notSurface).length}`, l: "surfaces covered" },
  SELF_HOSTED
    ? { n: "0", l: "content leaves your infrastructure" }
    : { n: "0", l: "full prompts kept by default" },
  { n: `${stats.detection_checks}`, l: "detection checks" },
  { n: "1", l: "afternoon to set up" },
];

const LINEAGE = [
  { title: "The finding names the source",
    body: "\"An AWS key went to ChatGPT\" is a ticket. \"The Q3 forecast went to ChatGPT, pasted by this person\" is an answer." },
  { title: "Known org data scores higher",
    body: "Text Palivane has already seen in your own systems scores higher than the same text from nowhere." },
  { title: "Blast radius, per document",
    body: "Pick a document and see which AI tools it reached, from whom, and how often." },
  { title: "It travels with the alert",
    body: "The source rides along into webhooks and the SIEM export." },
];

const FEATURES = [
  { tab: "Visibility", title: <>You finally know which AI tools are <span className="lp-hl">in use</span></>,
    sub: (st) => `Which AI tools are in use, by whom, and what each received, including the unapproved ones. Checked against a catalog of ${st.catalog_tools} tools; devices that report nothing are named, never counted as clean.`,
    href: "/coverage", link: "What each surface requires",
    src: "/shots/discovery.png?v=8", alt: "Inventory of AI tools in use" },
  { tab: "Agents", title: <>AI coding assistants stay <span className="lp-hl">inside the lines</span></>,
    sub: () => "Each assistant gets its own identity and limits, and every action is checked before it runs, not logged afterwards.",
    href: "/use-cases#engineering", link: "How engineering teams use it",
    src: "/shots/agents.png?v=8", alt: "AI assistant identity and limits" },
  { tab: "Trust", title: <>Know how often each check is <span className="lp-hl">right</span></>,
    sub: () => "One-click reviews become a readout per check, and noisy commands and paths become a time-limited allowlist.",
    src: "/shots/precision.png?v=1", alt: "Detection precision: how often each check was right" },
];

// Proof the page can back up, each linked to the page that says it in full. No logos or
// quotes: a security buyer discounts unverifiable ones, and these are all checkable.
const TRUST = [
  { title: "No AI in the scoring path", body: "Rules decide. The LLM judge is opt-in.", href: "/how-it-works" },
  { title: "Self-host it", body: "Same detection, your infrastructure.", href: "/security" },
  { title: "Read every client", body: "Every hook and scanner is on GitHub.", href: "https://github.com/SOC-Foundry/palivane-clients" },
  { title: "SSO, MFA, audit log", body: "Every admin action recorded.", href: "/trust" },
  { title: "DPA and subprocessors", body: "Published on the Trust page.", href: "/trust" },
];

// The one picture of how it works: where a prompt comes from, the checkpoint it passes,
// and what can happen to it. Built from HTML, not an image, so it stays sharp and stacks on
// a phone.
const FLOW_FROM = ["Browser and AI sites", "Coding assistants", "Desktop apps", "Agents and CI"];
const FLOW_CHECKS = ["Credentials", "Personal data", "Source code", "Hijacked instructions"];
const FLOW_TO = ["ChatGPT", "Claude", "Copilot", "Gemini"];
const SURFACES_ON_PHONE = 5;   // the rest sit behind "Show more" on a narrow screen

const INSTALL_CMD = "curl -fsSL https://app.palivane.io/install.sh | bash";

// "Open the console" is sign-in for anyone not already signed in, so it crosses hosts on
// the same rule as the nav's Sign in — see SiteChrome and deployment.js APP_ORIGIN.
function ConsoleCta({ onSignIn }) {
  return SIGN_IN_IS_CROSS_ORIGIN
    ? <a className="primary-btn slim" href={signInUrl()}>Open the console →</a>
    : <button className="primary-btn slim" onClick={onSignIn}>Open the console →</button>;
}


// Scroll-driven reveal. The hiding class is only added once this runs, so a visitor without
// JavaScript (or with reduced motion) gets the whole page, never a blank one.
function useReveal(rootRef) {
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return undefined;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce || !("IntersectionObserver" in window)) return undefined;
    root.classList.add("js-rv");
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        if (e.isIntersecting) { e.target.classList.add("rv-in"); io.unobserve(e.target); }
      }
    }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
    root.querySelectorAll(".rv").forEach((el) => io.observe(el));
    return () => { io.disconnect(); root.classList.remove("js-rv"); };
  }, [rootRef]);
}

// Counts a whole number up the first time it scrolls into view. Anything else renders as is.
function CountUp({ value }) {
  const ref = useRef(null);
  const target = /^\d+$/.test(String(value)) ? Number(value) : null;
  const [n, setN] = useState(target);
  useEffect(() => {
    const el = ref.current;
    if (target === null || target < 3 || !el || !("IntersectionObserver" in window)
        || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return undefined;
    let raf = 0;
    const io = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      io.disconnect();
      const t0 = performance.now();
      const tick = (t) => {
        const k = Math.min(1, (t - t0) / 900);
        setN(Math.round(target * (1 - Math.pow(1 - k, 3))));
        if (k < 1) raf = requestAnimationFrame(tick);
      };
      setN(0);
      raf = requestAnimationFrame(tick);
    }, { threshold: 0.6 });
    io.observe(el);
    return () => { io.disconnect(); cancelAnimationFrame(raf); };
  }, [target]);
  return <span ref={ref}>{n ?? value}</span>;
}

// Example findings for the card under the hero. Every value is illustrative: the companies
// are invented, the only key is the documented test payload from docs/pilot-smoke-test.md,
// and the other secrets are made-up strings that match no vendor format (push protection
// reads a lookalike as a leaked key). Each example has four prompt lines and three facts so
// the card does not change height as it cycles. Keep the claims in the meta rows true to what
// the named plane really does.
const EXAMPLES = [
  { tag: "BLOCKED", actor: "d.okafor@harbourline.io", to: "chatgpt.com", ref: "before send · finding #4471",
    lines: [
      [["clean up this customer list and fix the deploy script", ""]],
      [["name,email,plan,mrr", "dim"]],
      [["j.reyes@northwind.io,enterprise,4200", "hit"]],
      [["export AWS_ACCESS_KEY_ID=", "dim"], ["AKIA4YTGH2NBQF7XZP3K", "hit"]],
    ],
    facts: [["What was in it", "An AWS access key, and 1,848 customer records"],
            ["Where it came from", "Q3_accounts.csv, in Google Drive"],
            ["Caught by", "The browser extension, before the prompt sent"]],
    foot: <>A CASB logs one line: <code>user visited chatgpt.com</code>. Everything above is the part that matters.</> },
  { tag: "BLOCKED", actor: "m.lindqvist@northwind.io", to: "Claude Code", ref: "before the file was read · finding #4502",
    lines: [
      [["cat .env and tell me why the migration keeps failing", ""]],
      [["tool call: Bash", "dim"]],
      [["command: ", "dim"], ["cat billing/.env", "hit"]],
      [["sensitive resource: production credentials file", "dim"]],
    ],
    facts: [["What it was", "An assistant about to read a production .env file"],
            ["Where it came from", "The billing repo, on a laptop"],
            ["Caught by", "The coding-tool hook in enforce mode, before the command ran"]],
    foot: <>No website was visited. The file would have gone out through a coding tool, where a browser-only control never looks.</> },
  { tag: "FOUND", actor: "Slack", to: "#support-escalations", ref: "found at rest · finding #4519",
    lines: [
      [["customer called about the refund, they read out the", ""]],
      [["social to verify the account:", ""]],
      [["219-09-9999", "hit"]],
      [["name on file, Jordan Reyes", "dim"]],
    ],
    facts: [["What was in it", "A social security number, in a 14-month-old message"],
            ["Where it came from", "A support reply in a busy channel"],
            ["Caught by", "The Slack scanner, before an AI rollout reads it"]],
    foot: <>Nothing was sent anywhere, so no outbound control sees this. It was just sitting where an assistant can read it.</> },
  { tag: "BLOCKED", actor: "billing-reconciler", to: "invoices MCP server", ref: "before the call ran · finding #4533",
    lines: [
      [["tool call: invoices.export", ""]],
      [["agent: billing-reconciler (ag_ bearer)", "dim"]],
      [["attestation: none", "hit"]],
      [["role allows: invoices.read, one customer", "dim"]],
    ],
    facts: [["What was in it", "A bulk export outside the agent's role"],
            ["Where it came from", "An autonomous agent with no workload identity"],
            ["Caught by", "Enforced agent attestation and role limits, before the call ran"]],
    foot: <>The text of that call is clean. A prompt scanner finds nothing wrong; the caller just was not entitled.</> },
];
const EXAMPLE_MS = 7000;

function EvidenceCycle() {
  const [i, setI] = useState(0);
  const [hold, setHold] = useState(false);       // pointer or focus is on the card
  const [auto, setAuto] = useState(true);        // false under reduced motion: manual only
  useEffect(() => {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) setAuto(false);
  }, []);
  useEffect(() => {
    if (!auto || hold) return undefined;
    const t = setTimeout(() => setI((n) => (n + 1) % EXAMPLES.length), EXAMPLE_MS);
    return () => clearTimeout(t);
  }, [i, auto, hold]);
  const ex = EXAMPLES[i];
  return (
    <>
      <div className="lp-evidence rv" onMouseEnter={() => setHold(true)} onMouseLeave={() => setHold(false)}
           onFocus={() => setHold(true)} onBlur={() => setHold(false)}>
        <div className="lp-evidence-swap" key={i}>
          <div className="lp-evidence-head">
            <span className="who">
              <span className={`lp-evidence-tag ${ex.tag === "FOUND" ? "found" : ""}`}>{ex.tag}</span>
              <code>{ex.actor}</code>
              <span aria-hidden="true" style={{ color: "var(--muted-2)" }}>→</span>
              <code>{ex.to}</code>
            </span>
            <code style={{ color: "var(--muted-2)", fontSize: 12 }}>{ex.ref}</code>
          </div>
          <div className="lp-evidence-body">
            <div className="lp-evidence-prompt">
              {ex.lines.map((segs, n) => (
                <div key={n}>
                  {segs.map(([text, kind], k) => <span key={k} className={kind}>{text}</span>)}
                </div>
              ))}
            </div>
            <dl className="lp-evidence-meta">
              {ex.facts.map(([t, d]) => <div key={t}><dt>{t}</dt><dd>{d}</dd></div>)}
            </dl>
          </div>
        </div>
        <div className="lp-evidence-dots" role="tablist" aria-label="Example findings">
          {EXAMPLES.map((e, n) => (
            <button key={e.ref} type="button" role="tab" aria-selected={n === i}
                    aria-label={`Example ${n + 1} of ${EXAMPLES.length}: ${e.to}`}
                    className={`lp-evidence-dot ${n === i ? "is-on" : ""} ${auto && !hold ? "is-running" : ""}`}
                    onClick={() => setI(n)}><i /></button>
          ))}
        </div>
      </div>
      <p className="lp-evidence-foot rv" style={{ "--i": 1 }}>{ex.foot}</p>
    </>
  );
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
  const [surf, setSurf] = useState(0);
  const [step, setStep] = useState(0);
  const [feat, setFeat] = useState(0);
  const [allSurf, setAllSurf] = useState(false);
  const rootRef = useRef(null);
  useReveal(rootRef);
  return (
    <div className="landing lp-atmos" ref={rootRef}>
      <Lightbox src={zoom?.src} alt={zoom?.alt} onClose={() => setZoom(null)} />
      <SiteNav onSignIn={onSignIn} />

      <section className="lp-hero-wrap">
        <div className="lp-rings" aria-hidden="true"><i /><i /><i /></div>
        <div className="lp-hero">
          <div className="lp-tagline">AI SECURITY FOR THE TOOLS YOUR TEAM ALREADY USES</div>
          <h1>Your secrets shouldn't leave with the <span className="lp-hl">prompt.</span></h1>
          <p className="lp-lead">
            Palivane stops the <strong>passwords, customer data, and source code</strong> your
            team pastes into ChatGPT, Claude, Copilot, and AI coding assistants.
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
            <span>one command, monitor mode, only confirmed secrets blocked</span>
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
          <EvidenceCycle />
        </div>
      </section>

      <section className="lp-stats-band">
        <div className="lp-wrap lp-stats">
          {STATS.map((s) => (
            <div key={s.l} className="lp-stat rv" style={{ "--i": STATS.indexOf(s) }}>
              <span className="lp-stat-n"><CountUp value={s.n} /></span>
              <span className="lp-stat-l">{s.l}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="lp-trust-band" aria-label="Why security teams can trust it">
        <div className="lp-wrap lp-trust">
          {TRUST.map((t, i) => (
            <a key={t.title} className="lp-trust-item rv" style={{ "--i": i }} href={t.href}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                   strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6z" /><path d="M9 12l2 2 4-4" />
              </svg>
              <span><strong>{t.title}</strong>{t.body}</span>
            </a>
          ))}
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head rv">
            <span className="lp-eyebrow">How it works</span>
            <h2 className="lp-h2">One checkpoint between your team and <span className="lp-hl">the AI tools they use</span></h2>
          </div>
          <div className="lp-flow rv" style={{ "--i": 1 }}>
            <div className="lp-flow-col">
              <span className="lp-flow-label">Where it starts</span>
              {FLOW_FROM.map((x) => <span key={x} className="lp-flow-chip">{x}</span>)}
            </div>
            <span className="lp-flow-arrow" aria-hidden="true" />
            <div className="lp-flow-core">
              <span className="lp-flow-brand">Palivane</span>
              <span className="lp-flow-label">checks for</span>
              <ul>{FLOW_CHECKS.map((x) => <li key={x}>{x}</li>)}</ul>
              <div className="lp-flow-out">
                <span className="ok">Allow</span><span className="warn">Warn</span><span className="block">Block</span>
              </div>
            </div>
            <span className="lp-flow-arrow" aria-hidden="true" />
            <div className="lp-flow-col">
              <span className="lp-flow-label">Where it was going</span>
              {FLOW_TO.map((x) => <span key={x} className="lp-flow-chip">{x}</span>)}
            </div>
          </div>
          <p className="lp-sub lp-flow-note rv">In monitor mode it only records. Turn on blocking for
            a person, a team, or one tool at a time, when you have seen enough.</p>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-split">
          <div className="lp-split-text rv">
            <span className="lp-eyebrow">See it work</span>
            <h2 className="lp-h2">The same secret, stopped <span className="lp-hl">eight times</span></h2>
            <p className="lp-sub">A hundred-second tour: browser, coding tools, S3, and CI, then
              every screen it lands in.</p>
            <a className="lp-textlink" href="/how-it-works">How the detection works →</a>
          </div>
          <div className="lp-split-media rv" style={{ "--i": 1 }}>
            <Clip src="/shots/demo18.mp4" poster="/shots/demo-poster19.png" />
          </div>
        </div>
      </section>

      {/* Visibility, agents and trust were three full-height splits in a row. One section
          with a choice of three keeps every screenshot and every claim and saves two screens. */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <div className="lp-band-head rv">
            <span className="lp-eyebrow">The console</span>
            <h2 className="lp-h2">What you get once it is <span className="lp-hl">running</span></h2>
          </div>
          <div className="lp-steptabs lp-feattabs rv" role="tablist" style={{ "--i": 1 }}>
            {FEATURES.map((f, i) => (
              <button key={f.tab} type="button" role="tab" id={`feat-tab-${i}`}
                      aria-selected={feat === i} aria-controls="feat-panel"
                      className={`lp-steptab ${feat === i ? "is-on" : ""}`}
                      onClick={() => setFeat(i)}>
                <span className="lp-tab-n">{String(i + 1).padStart(2, "0")}</span>{f.tab}
              </button>
            ))}
          </div>
          <div className="lp-split lp-feat-panel" role="tabpanel" id="feat-panel" key={feat}
               aria-labelledby={`feat-tab-${feat}`}>
            <div className="lp-split-text">
              <h3 className="lp-h2 lp-h3">{FEATURES[feat].title}</h3>
              <p className="lp-sub">{FEATURES[feat].sub(stats)}</p>
              {FEATURES[feat].href
                ? <a className="lp-textlink" href={FEATURES[feat].href}>{FEATURES[feat].link} →</a> : null}
            </div>
            <div className="lp-split-media">
              <Shot src={FEATURES[feat].src} alt={FEATURES[feat].alt}
                    onZoom={(s, a) => setZoom({ src: s, alt: a })} />
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section alt lp-surfaces">
        <div className="lp-wrap">
          <div className="lp-band-head rv">
            <h2 className="lp-h2">It works wherever your team <span className="lp-hl">uses AI</span></h2>
            <p className="lp-sub">One console for all of it. Only desktop apps and AI extensions need a
              proxy and a certificate, so start without them.</p>
          </div>
          <div className="lp-tabs rv" style={{ "--i": 1 }}>
            <div className={`lp-tablist ${allSurf ? "all" : ""}`} role="tablist"
                 aria-orientation="vertical">
              {CAPTURE.map((c, i) => (
                <button key={c.title} type="button" role="tab" id={`surf-tab-${i}`}
                        aria-selected={surf === i} aria-controls="surf-panel"
                        className={`lp-tab ${surf === i ? "is-on" : ""} ${i >= SURFACES_ON_PHONE ? "lp-tab-extra" : ""}`}
                        onClick={() => setSurf(i)}>
                  <span className="lp-tab-n">{String(i + 1).padStart(2, "0")}</span>{c.title}
                </button>
              ))}
              {/* Eleven near-identical rows were a long scroll on a phone: the first few, then
                  the rest on request. Desktop shows them all (CSS hides this button there). */}
              {!allSurf && (
                <button type="button" className="lp-tab-more" onClick={() => setAllSurf(true)}>
                  Show {CAPTURE.length - SURFACES_ON_PHONE} more
                </button>
              )}
            </div>
            <div className="lp-tabpanel" role="tabpanel" id="surf-panel" key={surf}
                 aria-labelledby={`surf-tab-${surf}`}>
              <span className="lp-card-logos">
                {CAPTURE[surf].logos.map(([Logo, color], i) => <Logo key={i} style={{ color }} />)}
                {CAPTURE[surf].more ? <span className="lp-more">+{CAPTURE[surf].more}</span> : null}
              </span>
              <h3>{CAPTURE[surf].title}</h3>
              <p>{CAPTURE[surf].body}</p>
              {CAPTURE[surf].links ? (
                <span className="lp-tab-links">
                  {CAPTURE[surf].links.map(([href, label]) =>
                    <a key={href} className="lp-textlink" href={href}>{label} →</a>)}
                </span>
              ) : null}
            </div>
          </div>
          {/* Replaces the seven-card "What Palivane looks for" section; /coverage is the
              page that goes into detection surface by surface. */}
          <p className="lp-sub lp-detect-line rv">
            Every surface runs the deterministic checks that apply to it ({stats.secret_formats} credential
            formats, personal and customer data, source code and confidential documents,
            hijacked instructions, risky agent actions) and one risk score decides: allow, warn,
            or block. <a className="lp-textlink" href="/coverage">What it covers, surface by surface →</a>
          </p>
        </div>
      </section>

      {/* Lineage reads as a chain, so it runs horizontally — and it was the third
          text-beside-a-list section in a row, which is the rhythm problem the styling
          alone could not fix. */}
      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-band-head rv">
            <span className="lp-eyebrow">Lineage</span>
            <h2 className="lp-h2">Not just what leaked. Which document it came out of.</h2>
            <p className="lp-sub">Palivane fingerprints every document it scans in Drive,
              SharePoint, Salesforce, Slack, and Teams, so a finding names the source.</p>
          </div>
          <div className="lp-steps-tabs rv" style={{ "--i": 1 }}>
            <div className="lp-steptabs" role="tablist">
              {LINEAGE.map((l, i) => (
                <button key={l.title} type="button" role="tab" id={`lin-tab-${i}`}
                        aria-selected={step === i} aria-controls="lin-panel"
                        className={`lp-steptab ${step === i ? "is-on" : ""}`}
                        onClick={() => setStep(i)}>
                  <span className="lp-tab-n">{String(i + 1).padStart(2, "0")}</span>{l.title}
                </button>
              ))}
            </div>
            <div className="lp-tabpanel lp-steppanel" role="tabpanel" id="lin-panel" key={step}
                 aria-labelledby={`lin-tab-${step}`}>
              <p>{LINEAGE[step].body}</p>
            </div>
          </div>
          <div className="rv" style={{ marginTop: 40 }}>
            <Shot src="/shots/dashboard.png?v=8" alt="Exposure view: one document, everywhere it surfaced"
                  caption="Start from a document instead of a finding."
                  onZoom={(s, a) => setZoom({ src: s, alt: a })} />
          </div>
          <a className="lp-textlink" href="/use-cases" style={{ display: "inline-block", marginTop: 18 }}>What that changes in an incident →</a>
        </div>
      </section>

      {/* The FAQ and the closing call to action share one band: the three questions a buyer
          asks first, then the ask. The other answers live on /pricing#faq (one list, in
          Faq.jsx), so nothing was dropped to make the page shorter. */}
      <section className="lp-cta-band lp-faq-band">
        <div className="lp-wrap lp-faq-wrap">
          <div className="lp-band-head rv">
            <h2 className="lp-h2">Questions people ask first</h2>
          </div>
          <Faq items={FAQ.slice(0, FAQ_FIRST)} className="rv" />
          <a className="lp-textlink lp-faq-more" href="/pricing#faq">
            More answers: compatibility, outages, and who runs it →</a>
        </div>
        <div className="lp-wrap">
          <div className="lp-closing rv">
            <h2>Start by <span className="lp-hl">watching.</span></h2>
            <p>Run it in monitor mode, then switch on blocking when you have seen enough.</p>
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
