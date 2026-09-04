// Public "Why Palivane" page at /why-palivane (legacy /why-palivane still routes). The differentiators, what sets Palivane apart.
// Reuses the landing (lp-*) design language.
import { SiteNav, SiteFooter, Shot } from "./SiteChrome.jsx";
import { signInUrl } from "../deployment.js";
import { IconShield, IconTarget, IconPlug, IconInbox, IconClipboard, IconAlert } from "./icons.jsx";

const REASONS = [
  {
    icon: <IconShield />,
    title: "No agent to package or roll out",
    body: "There is no proprietary always-on agent to build, sign, maintain, and explain to your developers. If you already use Jamf, Intune, or Group Policy, Palivane hands you the config to push through them. Some planes put nothing on a machine at all: the gateway is a base-URL change, and scanning Slack, Teams, Drive, SharePoint or Salesforce needs only read-only access (a bot token or a read-only app/service account). The endpoint planes do install something, a browser extension and a small CLI that wires the coding-tool hooks, and both go out through the same MDM.",
  },
  {
    icon: <IconTarget />,
    title: "No third-party AI sees your content",
    body: "Detection is Palivane's own engine, it calls no outside AI service to do its job. That keeps it fast, private, and predictable: the same input always gets the same answer. Run it as our hosted service or entirely inside your own infrastructure, and add an AI reviewer for hard cases only if you want one.",
  },
  {
    icon: <IconInbox />,
    title: "One tool instead of five",
    body: "Browser pastes, desktop apps, AI coding assistants, your own AI features, code commits, and credentials sitting on laptops all land in the same console under the same policy. No stitching together point products with five different rule sets.",
  },
  {
    icon: <IconAlert />,
    title: "It actually stops things",
    body: "Most tools tell you about the leak afterward. Palivane can block it as it happens, the browser refuses the paste, the AI tool gets an error, the commit fails. Start in watch-only mode, see what would have been caught, then turn blocking on when you trust it.",
  },
  {
    icon: <IconPlug />,
    title: "Works with what you already bought",
    body: "Claude, GPT, or Gemini. Palivane doesn't care which you use. It sits alongside GitHub secret scanning and your existing security stack rather than replacing them, and pulls results from scanners you already run into the same place.",
  },
  {
    icon: <IconTarget />,
    title: "Find the problem before you police it",
    body: "Palivane first shows you which AI tools are in use and by whom, so your policy is based on what's really happening. Then you decide: which checks matter, who they apply to, and where you want a hard stop versus a warning.",
  },
  {
    icon: <IconClipboard />,
    title: "Answers for your auditors and customers",
    body: "A full audit trail, alerts, exports to your SIEM or data lake, a signed DPA, and a monthly summary you can hand upward. Export everything or delete your org in one click, it stays your data.",
  },
];

export default function WhyPalivane() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">WHY PALIVANE</div>
        <h1>Why teams pick Palivane</h1>
        <p>Your people adopted AI faster than anyone could write a policy for it. Palivane was
           built for that reality: quick to stand up, honest about what it sees, and able to
           stop a leak rather than just report one.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-cards lp-cards-2">
            {REASONS.map((r) => (
              <div key={r.title} className="lp-card">
                <span className="lp-card-icon">{r.icon}</span>
                <h3 style={{ marginTop: 10 }}>{r.title}</h3>
                <p>{r.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">AI assistants get their own rules</h2>
          <p className="lp-sub">An AI assistant with access to your codebase deserves the same
             limits you would give a contractor. Palivane gives each one an identity and a
             boundary (which tools, commands, and data it may touch) and enforces it.</p>
          <Shot lead src="/shots/agents.png?v=6" alt="AI assistant identity and limits" />
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>Want the engineering detail?</strong> The technical overview covers every
              detection surface, the two-tier secret engine, and how scoring works.
            </div>
            <a className="lp-btn-ghost wide" href="/how-it-works">How it works →</a>
            <a className="primary-btn slim" href={signInUrl()} style={{ textDecoration: "none" }}>Sign in</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
