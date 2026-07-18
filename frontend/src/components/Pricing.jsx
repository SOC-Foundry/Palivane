// Public pricing page at /pricing. Three licensing tiers (Free · Team · Enterprise);
// mirrors the real plan gates in backend app/plans.py — keep the two in sync.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

const TIERS = [
  {
    name: "Free", price: "$0", per: "forever",
    blurb: "Protect yourself and a few teammates in minutes.",
    cta: { label: "Start free →", href: "/#signin" },
    features: [
      "Up to 5 users",
      "Every capture plane: gateway, browser extension, hooks, proxy",
      "Live findings, discovery & coverage",
      "Monitor and enforce modes",
      "Community support",
    ],
  },
  {
    name: "Team", price: "$12", per: "per user / month ($10 annual)",
    blurb: "Roll Warden out to the whole team, with alerting and fleet installers.",
    cta: { label: "Contact us →", href: "mailto:sales@tachtech.net?subject=Warden%20Team%20plan" },
    featured: true,
    features: [
      "Everything in Free, unlimited users",
      "Webhook alerts + hourly/daily digests",
      "MDM policy packs (Jamf · Intune · GPO)",
      "Per-device fleet installers & enrollment keys",
      "Priority email support",
    ],
  },
  {
    name: "Enterprise", price: "Custom", per: "annual license",
    blurb: "Org-wide governance with identity, compliance, and data-plane integrations.",
    cta: { label: "Talk to sales →", href: "mailto:sales@tachtech.net?subject=Warden%20Enterprise" },
    features: [
      "Everything in Team",
      "SSO — OIDC & SAML",
      "SIEM forwarding (Splunk HEC · CEF · JSON)",
      "S3 / data-lake findings delivery",
      "Isolated single-tenant deployment option",
      "Custom quotas, DPA & compliance support",
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
        <h1>Plans for every team</h1>
        <p>Start free on your own machine today. Upgrade when you're ready to cover the
           team — or the whole company.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", alignItems: "start" }}>
            {TIERS.map((t) => <Tier key={t.name} t={t} />)}
          </div>
          <p className="lp-sub" style={{ textAlign: "center", marginTop: 28 }}>
            Self-hosting? Warden's core is source-available — the same Team and Enterprise
            licenses apply to supported self-hosted deployments.
            Questions: <a href="mailto:sales@tachtech.net">sales@tachtech.net</a>.
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-cta-wrap" style={{ textAlign: "center" }}>
          <h2 className="lp-h2">Two minutes to first findings</h2>
          <p className="lp-sub">Every plan starts the same way — sign up, run one command,
             watch the findings roll in.</p>
          <a className="primary-btn slim" href="/setup" style={{ textDecoration: "none" }}>See the setup →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
