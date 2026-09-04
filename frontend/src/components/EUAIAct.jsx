// Public EU AI Act page at /eu-ai-act — an honest deployer-side mapping, same contract as
// /trust: every claim here is implemented and verifiable (marketing's promise and
// engineering's checklist). Most Palivane customers are DEPLOYERS of AI systems and users
// of GPAI under the Act; this page maps their concrete obligations to the control or
// evidence Palivane produces, and says plainly what Palivane does not do.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

const ROWS = [
  ["Art. 4", "AI literacy",
   "Staff using AI must have an appropriate level of AI literacy.",
   "Enforcement that teaches at the moment of use: block and warn screens explain exactly what was flagged and why, coaching mode returns a cleaned prompt plus your sanctioned-tool alternatives, and justified-proceed records a business reason instead of training people to file tickets around policy."],
  ["Art. 5", "Prohibited practices",
   "Certain AI uses (e.g. emotion recognition in the workplace) are banned outright.",
   "You can't attest to what you can't see. Discovery inventories every AI tool in use across browsers, CLIs, OAuth grants, and CI — classified against a 500+ tool catalog with categories — so an unsanctioned tool in a banned category surfaces instead of running quietly."],
  ["Art. 26(1)–(2)", "Deployer obligations: oversight & control",
   "Use high-risk systems per instructions and assign competent human oversight.",
   "Per-surface enforcement (gateway, browser, CLI hooks, MCP) with block/warn thresholds your security team sets; AI agents get their own identities and least-privilege roles, and agent tool-calls are checked before execution, not logged after."],
  ["Art. 26(4)", "Input data control",
   "Deployers must ensure input data is relevant and appropriately controlled.",
   "The DLP core: secrets, PII/PHI, source code, and labeled-confidential material are detected in prompts before they reach a model — block, redact, or tokenize on the way through, with confirmed credentials hard-stopped even in monitor mode."],
  ["Art. 26(6) & Art. 12", "Logging & record-keeping",
   "Deployers keep the logs the system generates, at least six months.",
   "Every verdict is a durable, per-org record (metadata-first by default; content storage is an explicit opt-in) with configurable retention, full JSON export, and continuous delivery to your SIEM (Splunk HEC, CEF, JSON) or S3 data lake."],
  ["Art. 14", "Human oversight",
   "High-risk AI must be designed so humans can effectively oversee it.",
   "The gates are the oversight: risky prompts stop before the model sees them, dangerous agent actions stop before they run, and every override is a recorded human decision — who, what, why, when — in the audit log."],
  ["Art. 50", "Transparency",
   "AI-generated content and AI interactions must be identifiable.",
   "Findings tag AI-generated content where Palivane can establish it, and the discovery inventory shows which teams route which data through which AI systems — the map a transparency notice has to be written from."],
];

const NOT_ROWS = [
  ["Conformity assessment & CE marking (Art. 43)",
   "Provider obligations. If you build a high-risk AI system, you need a notified body or self-assessment process — Palivane supplies deployment-side evidence, not the assessment."],
  ["Fundamental-rights impact assessment (Art. 27)",
   "A documented organizational process. Palivane's inventory and exposure data feed it; the assessment itself is yours to run."],
  ["Technical documentation for providers (Art. 11)",
   "Belongs to whoever places the AI system on the market, not to the deployer's security tooling."],
];

export default function EUAIAct() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">COMPLIANCE</div>
        <h1>Palivane and the EU AI Act</h1>
        <p>Most organizations are <strong>deployers</strong> under the Act, and deployer
           obligations are concrete: control the inputs, keep the logs, oversee the use,
           know what's running. This page maps each one to the control or evidence Palivane
           produces — and says plainly what it does not do. Nothing on this page is
           aspirational; every control is shipped and verifiable.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Obligation → control mapping</h2>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))" }}>
            {ROWS.map(([art, name, duty, control]) => (
              <div key={art} className="lp-card">
                <span className="lp-card-icon" style={{ fontSize: 13 }}>{art}</span>
                <h3>{name}</h3>
                <p style={{ opacity: 0.75, fontSize: 13 }}>{duty}</p>
                <p>{control}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">What Palivane does not do</h2>
          <p className="lp-sub" style={{ maxWidth: "72ch" }}>
            Compliance pages that promise everything are how vendors end up in your risk
            register. Palivane is deployer-side tooling — it produces the technical evidence
            and enforcement the Act asks of you, and none of the following:</p>
          <div className="lp-cards">
            {NOT_ROWS.map(([t, body]) => (
              <div key={t} className="lp-card">
                <h3>{t}</h3>
                <p>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-cta-wrap" style={{ textAlign: "center" }}>
          <h2 className="lp-h2">Preparing an AI Act evidence pack?</h2>
          <p className="lp-sub">We'll walk your compliance team through the mapping against
             your actual deployment.</p>
          <a className="primary-btn slim" href="mailto:sales@palivane.io"
             style={{ textDecoration: "none" }}>Talk to us →</a>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
