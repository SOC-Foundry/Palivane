// Public pricing page at /pricing. Two purchasable tiers (Team · Enterprise) plus the
// 14-day trial; mirrors the real plan gates in backend app/plans.py — keep in sync.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

const TIERS = [
  {
    name: "Team", price: "$12", per: "per user / month ($10 annual)",
    blurb: "The plan most companies run. Covers everyone and tells you when something happens.",
    cta: { label: "Talk to us →", href: "mailto:sales@tachtech.net?subject=Warden%20Team%20plan" },
    featured: true,
    features: [
      "Up to 25 people (more on request)",
      "Covers the browser, desktop AI apps, AI coding tools, your code, and GitHub Actions",
      "Live findings, every AI tool in use, and who is covered",
      "Watch-only or blocking — your call",
      "Alerts where you already work, plus hourly or daily digests",
      "Push the setup to managed laptops (Jamf · Intune · Group Policy)",
      "Priority email support",
    ],
  },
  {
    name: "Enterprise", price: "Custom", per: "annual license",
    blurb: "For when identity, audit, and a security review are part of the deal.",
    cta: { label: "Talk to sales →", href: "mailto:sales@tachtech.net?subject=Warden%20Enterprise" },
    features: [
      "Everything in Team, without the seat cap",
      "Single sign-on with your identity provider (OIDC & SAML)",
      "Findings forwarded to your SIEM (Splunk HEC · CEF · JSON)",
      "Delivery to your own data lake (S3 for Panther, Athena, Snowflake)",
      "A managed AI reviewer for the cases fixed rules miss",
      "Run it isolated, on infrastructure you control",
      "Custom limits, signed DPA, and help through security reviews",
    ],
  },
  {
    name: "Trial", price: "14 days", per: "free, everything unlocked",
    blurb: "See real findings from your own traffic before you decide anything.",
    cta: { label: "Start a 14-day trial →", href: "/#signin" },
    features: [
      "Every feature of Enterprise, for two weeks",
      "First findings in about two minutes",
      "No card, no call required to start",
      "Nothing to install on anyone's laptop",
      "When it ends, capture keeps running — you just stop configuring",
    ],
  },
];

function Tier({ t }) {
  return (
    <div className="lp-card" style={t.featured ? {
      borderColor: "var(--accent)", boxShadow: "0 0 0 1px var(--accent), 0 18px 60px rgba(80,120,255,.12)",
    } : undefined}>
      <h3>{t.name}{t.featured && <span className="lp-tagline" style={{ fontSize: 11, marginLeft: 8 }}>MOST POPULAR</span>}</h3>
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
        <h1>Try it for two weeks. Then pick a plan.</h1>
        <p>Every feature is unlocked during the trial, so you evaluate the real thing on your
           own traffic. Prefer to run it yourself? The core is source-available and free to
           self-host, for as long as you like.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", alignItems: "start" }}>
            {TIERS.map((t) => <Tier key={t.name} t={t} />)}
          </div>
          <p className="lp-sub" style={{ textAlign: "center", marginTop: 28 }}>
            Running it yourself is the free option: Warden's core is source-available, and an
            unlicensed instance keeps working indefinitely. Team and Enterprise licenses add
            the fleet and compliance features to a self-hosted deployment too.
            Questions: <a href="mailto:sales@tachtech.net">sales@tachtech.net</a>.
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-cta-wrap" style={{ textAlign: "center" }}>
          <h2 className="lp-h2">First findings in about two minutes</h2>
          <p className="lp-sub">The trial starts the same way every deployment does: sign up, run
             one command, and watch real findings from your own traffic appear.</p>
          <a className="primary-btn slim" href="/setup" style={{ textDecoration: "none" }}>See the setup →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
