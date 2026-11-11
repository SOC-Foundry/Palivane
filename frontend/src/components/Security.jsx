// Public security page at /security (and /trust, which lands on #controls), written for the
// person who has to approve Palivane: a security reviewer deciding where this runs, what it
// holds, who operates it, and which controls back that up. It used to be two pages; the
// decision and the controls inventory now sit on one.
//
// Every claim below is checked against the code that implements it. If a default changes,
// this page changes in the same commit — it is the page a buyer will quote back to us.
import { Fragment, useEffect } from "react";
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { DuoServer, DuoEye, DuoLock, DuoUsers, DuoShield } from "./duoicons.jsx";

// The deployment decision: one row per question, an answer per column, so the two line up.
const DEPLOY_COLS = [
  ["Palivane-hosted", "app.palivane.io · Google Cloud us-central1 (US)"],
  ["Self-hosted", "Your infrastructure · your region · your database"],
];

const DEPLOY_ROWS = [
  ["Where captured traffic goes",
   "Through our service, which scans it and writes a verdict.",
   "Nowhere new. Detection runs inside your network."],
  ["Who can read your content",
   "By default nobody: we keep that a prompt carried an AWS key, not the prompt. Opt-in content storage is encrypted under a per-tenant key.",
   "Only you."],
  ["Data residency", "United States.", "Wherever you run it."],
  ["Who operates it", "We do (see below).", "You do. We support it; we cannot see it."],
  ["Time to running", "One command.", "A conversation with us first."],
];

// What crosses the boundary, per plane: the answer differs, so it is listed.
const FLOWS = [
  ["Browser extension & CLI hooks", "A verdict and metadata. Text only if your org turns on content storage. A hook that can't reach us fails open."],
  ["Egress proxy", "Inspected on your machine; the verdict leaves it."],
  ["MCP", "Tool calls inspected; benign ones discarded unless you keep them."],
  ["SaaS connectors", "Read-only API access you grant and can revoke. Slack installs with one click; the bot joins public channels only if you turn that on."],
  ["Warehouse AI", "Read-only queries against the platform's own AI-call records."],
  ["At-rest scanners", "Run where the data lives; only category, location and a masked preview travel."],
  ["Optional LLM judge", "Off unless enabled. Then the content it reviews goes to a model provider, yours if you supply a key, otherwise ours (Anthropic, below)."],
  ["Optional AI analyst", "Runs when someone clicks Investigate, on redacted context, with your own provider key only. Recommends, never acts."],
];

const RETENTION = [
  ["Metadata-only by default", "The verdict, detector, surface and actor. Not the prompt."],
  ["Benign traffic isn't kept", "Clean captures feed the inventory, then go."],
  ["Content storage is opt-in", "Per org, encrypted under a per-tenant data key."],
  ["Retention, export, deletion", "Per-org retention down to days; self-serve JSON export and organization deletion."],
];

// The controls inventory (formerly /trust). Every item is implemented and verifiable.
const CONTROLS = [
  ["Encryption", "TLS everywhere, Cloudflare at the edge and IAM-authenticated to the origin. Finding content encrypted under per-tenant data keys on encrypted Cloud SQL."],
  ["Tenant isolation", "Postgres row-level security on every tenant table, beneath the application's own scoping. Per-tenant provider keys, so no org bills another's account."],
  ["Identity & access", "Per-org OIDC and SAML 2.0 SSO, TOTP MFA, SCIM 2.0, admin/analyst/member roles, short-lived agent identities, instant session revocation, an admin audit log."],
  ["Infrastructure", "Cloud Run reachable only through the Cloudflare front door; private-IP database; secrets in Secret Manager; Terraform-managed, with separate least-privilege identities for deploys, data jobs and infrastructure."],
  ["Signed releases", "The CLI, hooks and installer are signed with a key held in Cloud KMS that never leaves it. Once a client has verified a signed release, it refuses unsigned or older ones."],
  ["Resilience", "Daily backups with 14-day point-in-time recovery; restores drilled and verified row by row (July 2026, ~35 minutes); multi-region uptime probes."],
  ["Open endpoint code", "Everything that runs on your machines is public: Apache-2.0 at github.com/SOC-Foundry/palivane-clients (the VS Code extension is MIT)."],
  ["Testing", "Recurring internal adversarial reviews, most recently November 2026, findings remediated. An independent penetration test is scheduled in the SOC 2 window."],
];

const SUBPROCESSORS = [
  ["Google Cloud Platform", "Hosting and database (us-central1, US)"],
  ["Cloudflare", "Edge network, TLS, DDoS and WAF"],
  ["Anthropic", "Optional LLM judge, off unless enabled; no customer content used for training"],
  ["Google Workspace", "Transactional email"],
];

const CELL = {
  padding: "14px 18px",
  borderTop: "1px solid rgba(128,128,128,.18)",
  verticalAlign: "top",
};

const GRID = { gridTemplateColumns: "repeat(auto-fit, minmax(min(280px, 100%), 1fr))" };

function Heading({ icon, children, id }) {
  return (
    <h2 className="lp-h2" id={id} style={{ display: "flex", alignItems: "center", gap: 10 }}>
      {icon && <span className="lp-card-icon" style={{ width: 34, height: 34, marginBottom: 0 }}>{icon}</span>}
      {children}
    </h2>
  );
}

export default function Security() {
  // /trust (the old controls page) lands on the controls section.
  useEffect(() => {
    if (window.location.pathname === "/trust" && !window.location.hash) {
      document.getElementById("controls")?.scrollIntoView();
    }
  }, []);

  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">SECURITY &amp; TRUST</div>
        <h1>Where your data goes, and who is on the other end</h1>
        <p>What crosses the boundary, what we keep, who operates it, and the controls behind
           it. Per-surface detail is in <a className="lp-textlink" href="/docs/data-flows">Data flows</a>; questions go
           to <a className="lp-textlink" href="mailto:security@palivane.io">security@palivane.io</a>.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <Heading icon={<DuoServer />}>Two ways to run it</Heading>
          <p className="lp-sub" style={{ maxWidth: "72ch" }}>Same engine either way. What differs is who holds the data.</p>
          <div style={{ overflowX: "auto" }}>
            <div className="lp-card" style={{ minWidth: 640, padding: 0 }}>
              <div style={{ display: "grid", gridTemplateColumns: "minmax(150px, 22%) 1fr 1fr" }}>
                <div />
                {DEPLOY_COLS.map(([name, sub]) => (
                  <div key={name} style={{ padding: "18px 18px 12px" }}>
                    <h3 style={{ margin: 0 }}>{name}</h3>
                    <p className="lp-sub" style={{ margin: "4px 0 0", fontSize: ".86em" }}>{sub}</p>
                  </div>
                ))}
                {DEPLOY_ROWS.map(([label, hosted, self]) => (
                  <Fragment key={label}>
                    <div style={CELL} className="lp-sub"><strong>{label}</strong></div>
                    <div style={CELL}>{hosted}</div>
                    <div style={CELL}>{self}</div>
                  </Fragment>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <Heading icon={<DuoEye />}>What crosses the boundary</Heading>
          <p className="lp-sub" style={{ maxWidth: "72ch" }}>Per plane, on a hosted deployment. Self-hosted: nothing, for all of them.</p>
          <div className="lp-cards" style={GRID}>
            {FLOWS.map(([t, body]) => (
              <div key={t} className="lp-card"><h3>{t}</h3><p>{body}</p></div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <Heading icon={<DuoLock />}>What we retain</Heading>
          <div className="lp-cards" style={GRID}>
            {RETENTION.map(([t, body]) => (
              <div key={t} className="lp-card"><h3>{t}</h3><p>{body}</p></div>
            ))}
          </div>
        </div>
      </section>

      {/* Nothing here is softened: a reviewer who finds any of it out later would be right
          to discount everything else we say. */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <Heading icon={<DuoUsers />}>Who is on the other end</Heading>
          <div style={{ maxWidth: "74ch" }}>
            <p className="lp-sub">
              <strong>Palivane is founder-operated.</strong> One person builds, deploys and is on
              call for it. Price that into your review.
            </p>
            <p className="lp-sub">
              <strong>We are not SOC 2 certified today.</strong> The Type II program is underway,
              report expected in 2027, Type I sooner. Until then we offer this page, our DPA, a
              completed CAIQ and the source of everything on your machines. If your process needs
              an attestation, self-hosting is the honest answer.
            </p>
            <p className="lp-sub">
              <strong>A hosted deployment concentrates risk.</strong> It holds findings across
              tenants. Metadata-only defaults, per-tenant keys and row-level security shrink that
              blast radius; they don't remove it. If that matters to you, run it yourself and we
              will help.
            </p>
            <p className="lp-sub">
              <strong>Your own inventory will flag us.</strong> Until you sanction it,{" "}
              <code>app.palivane.io</code> shows as an unsanctioned AI destination like any other.
            </p>
            <p className="lp-sub">
              <strong>Self-hosting goes through us today.</strong> The client side is public to
              audit; the server package is handed over and supported rather than downloaded.{" "}
              <a className="lp-textlink" href="mailto:sales@palivane.io">sales@palivane.io</a>.
            </p>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <Heading icon={<DuoShield />} id="controls">Controls</Heading>
          <div className="lp-cards" style={GRID}>
            {CONTROLS.map(([t, body]) => (
              <div key={t} className="lp-card"><h3>{t}</h3><p>{body}</p></div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2" id="disclosure">Vulnerability disclosure</h2>
          <p className="lp-sub" style={{ maxWidth: "74ch" }}>
            Report to <a className="lp-textlink" href="mailto:security@palivane.io">security@palivane.io</a> (also at{" "}
            <code>/.well-known/security.txt</code>). Acknowledgement within 2 business days,
            triage within 5. Good-faith testing against your own org or the public site is
            authorized and we won't pursue it legally, provided it respects other tenants' data,
            avoids degrading the service, and allows reasonable time to fix. In scope: palivane.io,
            app.palivane.io, the browser extension and the open-source clients. Out of scope:
            denial of service, social engineering, and third-party services.
          </p>

          <h2 className="lp-h2" style={{ marginTop: 36 }}>Compliance & subprocessors</h2>
          <p className="lp-sub" style={{ maxWidth: "74ch" }}>
            SOC 2 Type II in progress (report 2027). The DPA is accepted in-product with version
            history; the CAIQ is available on <a className="lp-textlink" href="mailto:security@palivane.io">request</a>.
          </p>
          <div className="lp-cards" style={GRID}>
            {SUBPROCESSORS.map(([name, role]) => (
              <div key={name} className="lp-card"><h3>{name}</h3><p>{role}</p></div>
            ))}
          </div>
          <p className="lp-sub" style={{ marginTop: 16 }}>
            Not ready to decide? Palivane starts in monitor mode and blocks nothing until you say
            so. <a className="lp-textlink" href="mailto:sales@palivane.io">Ask for an AI exposure assessment</a>.
          </p>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
