// Public pricing page at /pricing. Three licensing tiers (Free · Team · Enterprise);
// mirrors the real plan gates in backend app/plans.py — keep the two in sync.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

const TIERS = [
  {
    name: "Free", price: "$0", per: "forever",
    blurb: "Find out what your team is actually sending, this afternoon.",
    cta: { label: "Start free →", href: "/#signin" },
    features: [
      "Up to 5 people",
      "Covers the browser, desktop AI apps, AI coding tools, and your code",
      "Live findings, a list of every AI tool in use, and who is covered",
      "Watch-only or blocking — your call",
      "Community support",
    ],
  },
  {
    name: "Team", price: "$12", per: "per user / month ($10 annual)",
    blurb: "Cover everyone, and get told when something happens.",
    cta: { label: "Contact us →", href: "mailto:sales@tachtech.net?subject=Warden%20Team%20plan" },
    featured: true,
    features: [
      "Everything in Free, for as many people as you have",
      "Alerts where you already work, plus hourly or daily digests",
      "Push the setup to managed laptops (Jamf · Intune · Group Policy)",
      "One-step install per device — no shared passwords to hand around",
      "Priority email support",
    ],
  },
  {
    name: "Enterprise", price: "Custom", per: "annual license",
    blurb: "For when identity, audit, and a security review are part of the deal.",
    cta: { label: "Talk to sales →", href: "mailto:sales@tachtech.net?subject=Warden%20Enterprise" },
    features: [
      "Everything in Team",
      "Single sign-on with your identity provider (OIDC & SAML)",
      "Findings forwarded to your SIEM (Splunk HEC · CEF · JSON)",
      "Delivery to your own data lake (S3 for Panther, Athena, Snowflake)",
      "Run it isolated, on infrastructure you control",
      "Custom limits, signed DPA, and help through security reviews",
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
        <h1>Start free. Pay when it covers everyone.</h1>
        <p>See it working on your own traffic before you spend anything. The paid plans are
           about scale and the things a security review asks for — not about unlocking the
           protection.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", alignItems: "start" }}>
            {TIERS.map((t) => <Tier key={t.name} t={t} />)}
          </div>
          <p className="lp-sub" style={{ textAlign: "center", marginTop: 28 }}>
            Want to run it yourself? Warden's core is source-available, and the same Team and
            Enterprise licenses cover supported self-hosted deployments.
            Questions: <a href="mailto:sales@tachtech.net">sales@tachtech.net</a>.
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-cta-wrap" style={{ textAlign: "center" }}>
          <h2 className="lp-h2">First findings in about two minutes</h2>
          <p className="lp-sub">Every plan starts the same way: sign up, run one command, and
             watch real findings from your own traffic appear.</p>
          <a className="primary-btn slim" href="/setup" style={{ textDecoration: "none" }}>See the setup →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
