// Public support page at /support. Honest by construction: it only promises the support
// that the plans actually include (see Pricing.jsx / plans.py) and routes each kind of
// request to a real inbox — support@/sales@/security@/privacy@ are Google Workspace groups
// on palivane.io. No SLA hours are stated that aren't committed.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

// Try the docs first — most "how do I…" questions are answered without waiting on email.
const SELF_SERVE = [
  ["Documentation", "Setup, deployment, and reference for every plane.", "/docs"],
  ["Set it up", "The one-command install and what your MDM pushes.", "/setup"],
  ["Coverage", "Every surface, and exactly what each one needs.", "/coverage"],
  ["Trust & security", "Data handling, tenant isolation, and disclosure.", "/trust"],
];

// What actually reaches a human, by plan — mirrors what each tier includes, nothing more.
const BY_PLAN = [
  ["Trial & self-hosted", "Documentation and community. The endpoint clients are open source. File issues at github.com/SOC-Foundry/palivane-clients."],
  ["Team", "Priority email support at support@palivane.io. Bring the org name and the plane involved and we can usually resolve it in one round trip."],
  ["Enterprise", "A named contact, plus help through security reviews and onboarding. Custom terms and a signed DPA are part of the agreement."],
];

// Route the request to the address that already exists (one Email Routing rule each).
const ROUTES = [
  ["Product help & how-tos", "support@palivane.io", "mailto:support@palivane.io"],
  ["Security & responsible disclosure", "security@palivane.io", "mailto:security@palivane.io"],
  ["Pricing, plans & upgrades", "sales@palivane.io", "mailto:sales@palivane.io"],
  ["Privacy & data requests", "privacy@palivane.io", "mailto:privacy@palivane.io"],
];

export default function Support() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">SUPPORT</div>
        <h1>Get help with Palivane</h1>
        <p>Most answers are in the docs. When you need a person, email{" "}
           <a href="mailto:support@palivane.io">support@palivane.io</a>. The more specific you
           are, the faster we can help.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Start here</h2>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
            {SELF_SERVE.map(([t, body, href]) => (
              <a key={t} href={href} className="lp-card" style={{ textDecoration: "none" }}>
                <h3>{t} →</h3>
                <p>{body}</p>
              </a>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Email support</h2>
          <p className="lp-sub" style={{ maxWidth: "70ch" }}>
            Write to <a href="mailto:support@palivane.io">support@palivane.io</a>. To get a
            useful answer on the first reply, include:
          </p>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
            <div className="lp-card"><h3>Your organization</h3><p>The org name you signed in with, so we can find your workspace.</p></div>
            <div className="lp-card"><h3>Which surface</h3><p>Gateway, browser, a coding tool, a SaaS connector, or the console.</p></div>
            <div className="lp-card"><h3>What you saw</h3><p>What happened versus what you expected, with a rough timestamp. Never paste secrets or live credentials.</p></div>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">What your plan includes</h2>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
            {BY_PLAN.map(([t, body]) => (
              <div key={t} className="lp-card"><h3>{t}</h3><p>{body}</p></div>
            ))}
          </div>
          <p className="lp-sub" style={{ marginTop: 18 }}>
            See <a href="/pricing">pricing</a> for what each plan covers.
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Reach the right inbox</h2>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
            {ROUTES.map(([t, addr, href]) => (
              <div key={t} className="lp-card">
                <h3>{t}</h3>
                <p><a href={href}>{addr}</a></p>
              </div>
            ))}
          </div>
          <p className="lp-sub" style={{ marginTop: 18 }}>
            For a security issue, please use <a href="mailto:security@palivane.io">security@palivane.io</a> and
            see the <a href="/trust">Trust &amp; security</a> page for scope and safe-harbor terms.
          </p>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
