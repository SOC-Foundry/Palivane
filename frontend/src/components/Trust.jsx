// Public trust page at /trust, the pre-SOC2 bridge: what a security reviewer needs to
// know before the attestation exists. Every claim here is implemented and verifiable;
// keep it that way (this page is marketing's promise and engineering's checklist).
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { DuoLock, DuoColumns, DuoKey, DuoServer, DuoShield, DuoRefresh, DuoBeaker } from "./duoicons.jsx";

const SECTIONS = [
  {
    icon: <DuoLock />,
    title: "Data protection",
    items: [
      ["Encryption in transit", "TLS everywhere: Cloudflare terminates public TLS; origin traffic is authenticated (IAM-signed) service-to-service."],
      ["Encryption at rest", "Cloud SQL disk encryption plus application-layer encryption of finding content under a per-tenant data key (envelope encryption)."],
      ["Redaction before storage", "Detected secrets are replaced with labels and PII is masked before a finding is written, the default posture is metadata-only, with full-content storage an explicit per-org opt-in. See the data-flows page for exactly what leaves the machine, per mode."],
      ["Retention & deletion", "Per-org findings retention (down to days), self-serve full data export (JSON), and self-serve organization deletion that removes every row the org owns."],
      ["DPA", "A data-processing agreement is presented in-product and acceptance is recorded with version history."],
    ],
  },
  {
    icon: <DuoColumns />,
    title: "Tenant isolation",
    items: [
      ["Row-Level Security", "Isolation is enforced in the database itself: Postgres RLS policies on every tenant-scoped table, keyed to the authenticated request, defense-in-depth beneath the application's own tenant scoping."],
      ["Per-tenant keys", "Encrypted content is sealed under per-tenant data keys; per-tenant provider keys mean one org's gateway traffic can never bill another's account."],
    ],
  },
  {
    icon: <DuoKey />,
    title: "Access & identity",
    items: [
      ["SSO & MFA", "OIDC and SAML 2.0 SSO per organization (Enterprise); TOTP two-factor authentication for password sign-ins."],
      ["Least privilege", "Admin/analyst roles; per-agent identities with short-lived session tokens, per-agent rate limits, and least-privilege role policies for AI agents."],
      ["Audit trail", "Administrative actions are recorded in a per-org audit log visible in the console."],
      ["Session control", "Instant revocation of all sessions per user; agent tokens are revoked the moment an agent is disabled."],
    ],
  },
  {
    icon: <DuoServer />,
    title: "Infrastructure",
    items: [
      ["Hosting", "Google Cloud (us-central1). The application runs on Cloud Run, IAM-locked so only the Cloudflare front door can invoke it; the database is private-IP only, unreachable from the internet."],
      ["Edge protection", "Cloudflare fronts all traffic with per-IP rate limiting on authentication endpoints and scanner-path blocking at the edge."],
      ["Secrets", "All credentials live in Google Secret Manager, none in code, images, or environment files."],
      ["Infrastructure as code", "The production stack is defined in Terraform with drift-free state."],
    ],
  },
  {
    icon: <DuoShield />,
    title: "Vulnerability disclosure",
    items: [
      ["Reporting channel", "security@palivane.io, also machine-readable at /.well-known/security.txt (RFC 9116). Reports get a human acknowledgement within 2 business days and triage within 5."],
      ["Safe harbor", "Good-faith research against your own Palivane org or the public site is authorized: we will not pursue legal action for testing that respects other tenants' data, avoids service degradation, and gives us reasonable time to fix before disclosure."],
      ["Scope", "palivane.io, app.palivane.io, the published browser extension, and the open-source clients. Out of scope: denial of service, social engineering, and third-party services we run on (report those to the vendor)."],
      ["Independent testing", "Internal adversarial bug bashes run routinely against each release; an independent penetration test is scheduled within the SOC 2 observation window and its summary will be available under NDA."],
    ],
  },
  {
    icon: <DuoRefresh />,
    title: "Resilience",
    items: [
      ["Backups", "Daily automated backups with 14-day point-in-time recovery."],
      ["Tested restores", "Restore drills are performed against real backups and verified row-by-row, most recent drill: July 2026, full restore in ~35 minutes."],
      ["Monitoring", "External uptime probes on the service health endpoint from multiple regions, with alerting to on-call."],
    ],
  },
  {
    icon: <DuoBeaker />,
    title: "Security testing",
    items: [
      ["Open endpoint code", "Everything Palivane runs on your machines (the browser extension, CLI capture hooks, egress proxy, and MCP server) is public and Apache-2.0 licensed, auditable at github.com/SOC-Foundry/palivane-clients."],
      ["Adversarial reviews", "Multiple internal adversarial security audits (authentication, tenant isolation, SSRF, injection, extension surface) with all findings remediated, most recent: July 2026."],
      ["Independent testing", "A third-party penetration test is scheduled as part of the SOC 2 program."],
      ["Responsible disclosure", "security@palivane.io, see our security policy for scope and safe-harbor terms."],
    ],
  },
];

const SUBPROCESSORS = [
  ["Google Cloud Platform", "Application hosting & database (us-central1, United States)"],
  ["Cloudflare", "Edge network, TLS termination, DDoS & WAF"],
  ["Anthropic", "Optional LLM judge for detection quality, off unless enabled, per-organization opt-out; no customer content is used for model training"],
  ["Google Workspace", "Transactional email (verification, password reset, invites)"],
];

export default function Trust() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">TRUST &amp; SECURITY</div>
        <h1>How Palivane protects your data</h1>
        <p>Palivane inspects your organization's most sensitive traffic, so it's built to be
           the most locked-down thing you run. Everything below is implemented today and
           verifiable, ask us anything: <a href="mailto:security@palivane.io">security@palivane.io</a>.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          {SECTIONS.map((s) => (
            <div key={s.title} style={{ marginBottom: 36 }}>
              <h2 className="lp-h2" style={{ display: "flex", alignItems: "center", gap: 10 }}><span className="lp-card-icon" style={{ width: 34, height: 34, marginBottom: 0 }}>{s.icon}</span>{s.title}</h2>
              <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
                {s.items.map(([t, body]) => (
                  <div key={t} className="lp-card">
                    <h3>{t}</h3>
                    <p>{body}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Compliance</h2>
          <p className="lp-sub" style={{ maxWidth: "70ch" }}>
            Our <strong>SOC 2 Type II</strong> program is underway, with a report expected in
            2027 (Type I sooner). In the meantime this page, our DPA, and a completed CAIQ
            questionnaire are available for security reviews,{" "}
            <a href="mailto:security@palivane.io">request the package</a>.
          </p>

          <h2 className="lp-h2" style={{ marginTop: 36 }}>Subprocessors</h2>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
            {SUBPROCESSORS.map(([name, role]) => (
              <div key={name} className="lp-card">
                <h3>{name}</h3>
                <p>{role}</p>
              </div>
            ))}
          </div>
          <p className="lp-sub" style={{ marginTop: 16 }}>
            Self-hosted deployments keep all data inside your own infrastructure, the only
            optional external call is the LLM judge, under your own provider account.
          </p>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
