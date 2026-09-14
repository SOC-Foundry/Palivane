// Public pricing page at /pricing. Priced by PROTECTED USERS, not per seat and never by
// tokens: the buyer is a security owner with a risk-reduction budget who needs a
// predictable number, and token pricing makes the bill a function of how much the team
// uses AI — exactly the behaviour the product is meant to make safe.
//
// The plan KEYS behind this (team · enterprise) are unchanged and still mirror the feature
// gates in backend app/plans.py — keep those in sync. What changed is the price model and
// the entry offer: the first thing sold is an AI Exposure Assessment, not a subscription,
// because a two-week scoped look is a decision a security owner can actually make.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { signInUrl } from "../deployment.js";
import { DuoUsers, DuoBadgeCheck, DuoBeaker } from "./duoicons.jsx";

// Bands, by protected users. Published deliberately: the field routes every price to a
// demo, and a number on the page is how a buyer decides whether to spend the meeting.
const BANDS = [
  ["50–100 protected users", "$1,000–1,500 / month"],
  ["100–500", "$2,500–5,000 / month"],
  ["500–2,000", "$6,000–12,000 / month"],
  ["Larger, or regulated", "Custom annual"],
];

const TIERS = [
  {
    icon: <DuoBeaker />,
    name: "AI Exposure Assessment", price: "7–14 days", per: "a scoped engagement, not a subscription",
    blurb: "Before you buy anything: find out what is actually leaving, and who is sending it.",
    cta: { label: "Request an assessment →", href: "mailto:sales@palivane.io?subject=AI%20Exposure%20Assessment" },
    featured: true, badge: "START HERE",
    features: [
      "Runs in monitor mode — it observes and reports, and blocks nothing",
      "Inventory of AI tools in use, by person, device, repository and tool",
      "The high-severity exposures: credentials, customer data, source code, confidential files",
      "AI-agent and MCP activity reviewed for excessive permissions and risky actions",
      "An executive report with the policies we would actually turn on, and why",
      "Hosted or self-hosted, whichever your review allows",
    ],
  },
  {
    icon: <DuoUsers />,
    name: "Team", price: "From $1,000", per: "per month, by protected users",
    blurb: "The plan most companies run after an assessment. Covers everyone and tells you when something happens.",
    cta: { label: "Talk to us →", href: "mailto:sales@palivane.io?subject=Palivane%20Team" },
    features: [
      "Priced by protected users, not by tokens — the bill does not grow when your team uses AI more",
      "Covers the browser, desktop AI apps, AI coding tools, your code, and GitHub Actions",
      "Live findings, the AI tools in use, and who is covered and who is not",
      "Watch-only or blocking, your call",
      "Alerts where you already work, plus hourly or daily digests",
      "Push the setup to managed laptops (Jamf · Intune · Group Policy)",
      "Priority email support",
    ],
  },
  {
    icon: <DuoBadgeCheck />,
    name: "Enterprise", price: "Custom", per: "annual license",
    blurb: "For when identity, audit, deployment control and a security review are part of the deal.",
    cta: { label: "Talk to sales →", href: "mailto:sales@palivane.io?subject=Palivane%20Enterprise" },
    features: [
      "Everything in Team, on an annual license",
      "Self-hosted deployment: runs in your infrastructure, in your region, and we cannot see it",
      "Single sign-on with your identity provider (OIDC & SAML)",
      "Findings forwarded to your SIEM (Splunk HEC · CEF · JSON)",
      "Delivery to your own data lake (S3 for Panther, Athena, Snowflake)",
      "Optional LLM judge for the cases fixed rules miss, managed, or on your own provider key",
      "Custom limits, signed DPA, and help through security reviews",
    ],
  },
];

function Tier({ t }) {
  return (
    <div className="lp-card" style={t.featured ? {
      borderColor: "var(--accent)", boxShadow: "0 0 0 1px var(--accent), 0 18px 60px rgba(80,120,255,.12)",
    } : undefined}>
      <span className="lp-card-icon">{t.icon}</span>
      <h3>{t.name}{t.badge && <span className="lp-tagline" style={{ fontSize: 11, marginLeft: 8 }}>{t.badge}</span>}</h3>
      <p style={{ margin: "6px 0 2px" }}>
        <span style={{ fontSize: 34, fontWeight: 800, color: "var(--text)" }}>{t.price}</span>
      </p>
      <p style={{ minHeight: 18 }}>{t.per}</p>
      <p style={{ margin: "10px 0 14px" }}>{t.blurb}</p>
      <ul style={{ margin: "0 0 18px", padding: 0, listStyle: "none" }}>
        {t.features.map((f) => (
          <li key={f} style={{ fontSize: 13.5, color: "var(--muted)", lineHeight: 1.9 }}>✓ {f}</li>
        ))}
      </ul>
      <a className="primary-btn slim" href={t.cta.href} style={{ textDecoration: "none" }}>{t.cta.label}</a>
    </div>
  );
}

export default function Pricing() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">PRICING</div>
        <h1>Start by finding out what is already leaving.</h1>
        <p>Palivane is priced by protected users — not per token, so the bill does not grow
           because your team used AI more. Most companies start with a scoped{" "}
           <strong>AI Exposure Assessment</strong> in monitor mode rather than a subscription,
           because two weeks of evidence is a smaller decision than a platform. Deployment is
           yours to choose: hosted, or self-hosted in your own infrastructure — see{" "}
           <a href="/security">where your data goes</a> before you decide.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", alignItems: "start" }}>
            {TIERS.map((t) => <Tier key={t.name} t={t} />)}
          </div>
          <div style={{ maxWidth: 720, margin: "34px auto 0" }}>
            <h2 className="lp-h2" style={{ textAlign: "center" }}>What a subscription costs</h2>
            <p className="lp-sub" style={{ textAlign: "center" }}>
              By protected users, after an assessment has scoped it.
            </p>
            <div className="lp-card" style={{ padding: 0, marginTop: 18 }}>
              {BANDS.map(([band, price], i) => (
                <div key={band} style={{ display: "flex", justifyContent: "space-between", gap: 16,
                  padding: "14px 20px", borderTop: i ? "1px solid rgba(128,128,128,.18)" : "none" }}>
                  <span className="lp-sub" style={{ margin: 0 }}>{band}</span>
                  <strong style={{ whiteSpace: "nowrap" }}>{price}</strong>
                </div>
              ))}
            </div>
            <p className="lp-sub" style={{ marginTop: 18 }}>
              Higher tiers cover AI-agent and CI coverage, self-hosted deployment, advanced
              integrations and enterprise support. Everything that runs on your machines is
              public and Apache-2.0 at{" "}
              <a href="https://github.com/SOC-Foundry/palivane-clients">github.com/SOC-Foundry/palivane-clients</a>,
              so the capture side is auditable before you talk to anyone. Self-hosting itself
              is a supported enterprise deployment that we hand over and help you stand up —{" "}
              <a href="/security">stated plainly here</a>, including the parts that are
              inconvenient for us. Questions:{" "}
              <a href="mailto:sales@palivane.io">sales@palivane.io</a>.
            </p>
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-cta-wrap" style={{ textAlign: "center" }}>
          <h2 className="lp-h2">First findings in about two minutes</h2>
          <p className="lp-sub">An assessment starts the same way every deployment does: sign up,
             run one command, and watch real findings from your own traffic appear. Nothing is
             blocked until you decide it should be.</p>
          <a className="primary-btn slim" href="/setup" style={{ textDecoration: "none" }}>See the setup →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
