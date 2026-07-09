// Public "Why Warden" page at /why-warden. The differentiators — what sets Warden apart.
// Reuses the landing (lp-*) design language.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { IconShield, IconTarget, IconPlug, IconInbox, IconClipboard, IconAlert } from "./icons.jsx";

const REASONS = [
  {
    icon: <IconShield />,
    title: "Agentless by default",
    body: "The core — gateway, browser extension, egress proxy, CI — needs no endpoint agent. Push config zero-touch to managed fleets via an MDM policy pack (Jamf / Intune / GPO). Opt-in local sensors add stdio-level MCP and pre-tool-use depth only when you want it.",
  },
  {
    icon: <IconTarget />,
    title: "Offline-first detection",
    body: "The detection engine is pure regex and heuristics — no API key, no outbound call. That makes it fast, private (content never leaves your environment on the offline path), and deterministic. An optional LLM judge layers on top for novel cases, but nothing depends on it.",
  },
  {
    icon: <IconInbox />,
    title: "One engine, every surface",
    body: "Prompts to your own LLMs, pastes into public AI tools, agent tool-calls, commits, and credentials at rest all feed the same scoring engine and the same console. No stitching together five point tools with five policies.",
  },
  {
    icon: <IconAlert />,
    title: "Prevention, not just detection",
    body: "Start in monitor mode to see what would trip, then flip to enforce and Warden blocks at the source — the extension shows a block modal, the gateway returns an error, the git hook fails the commit. Real prevention, with a per-tenant block threshold you control.",
  },
  {
    icon: <IconPlug />,
    title: "Works with what you already have",
    body: "Provider-agnostic across Claude, GPT, and Gemini for both the gateway and the judge. Complements GitHub secret scanning and your CASB rather than replacing them, and folds in TruffleHog / Gitleaks / GitGuardian output so every finding lands in one place.",
  },
  {
    icon: <IconClipboard />,
    title: "Multi-tenant & compliance-ready",
    body: "Org signup, role-based console, per-tenant API keys and policy, a full audit log, alert digests, SIEM export, a signed DPA, and self-serve data export plus one-click delete-my-org. Deployable with docker compose locally or Cloud Run + Cloud SQL for production.",
  },
];

export default function WhyWarden() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">WHY WARDEN</div>
        <h1>Coverage that fits how AI actually spreads</h1>
        <p>AI adoption outran the tools built to govern it. Warden was built for it —
           agentless, offline-first, and prevention-capable across every surface.</p>
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

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>Curious how the engine works?</strong> The technical overview walks through
              surfaces, the two-tier secret engine, and the scoring model.
            </div>
            <a className="lp-btn-ghost wide" href="/how-it-works">How it works →</a>
            <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Sign in</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
