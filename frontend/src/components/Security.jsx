// Public security page at /security, written for the person who has to approve Palivane:
// a security reviewer deciding where this runs and what it holds.
//
// /trust is the controls inventory — encryption, isolation, disclosure, resilience. This
// page is the DECISION: hosted or self-hosted, what crosses the boundary in each, what is
// retained, and who is on the other end. It exists because the honest answer to "who
// operates this" is small, and a reviewer who discovers that after reading the controls
// page reads the controls page as spin. Better they get it here, in our words, first.
//
// Every claim below is checked against the code that implements it. If a default changes,
// this page changes in the same commit — it is the page a buyer will quote back to us.
import { Fragment } from "react";
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { DuoServer, DuoEye, DuoLock, DuoUsers, DuoRadar } from "./duoicons.jsx";

// The deployment decision. Kept as one row per question with an answer per column, rather
// than two independent cards, because side-by-side cards whose rows do not line up are not
// a comparison — the reader has to hold each answer in their head to match it to the other.
const DEPLOY_COLS = [
  ["Palivane-hosted", "app.palivane.io · Google Cloud us-central1 (US)"],
  ["Self-hosted", "Your infrastructure · your region · your database"],
];

const DEPLOY_ROWS = [
  ["Where captured traffic goes",
   "Through our infrastructure. Prompts are scanned in our service before a verdict is written.",
   "Nowhere it does not already go. Detection runs inside your network and no prompt content reaches us."],
  ["Who can read your content",
   "By default nobody — the default posture is metadata-only, so what we hold is that a prompt carried an AWS key, not the prompt. Switch on content storage and it is encrypted under a per-tenant key, and readable by an operator with database access.",
   "Only you. We have no access of any kind to a self-hosted deployment."],
  ["Data residency",
   "United States. No region choice today.",
   "Wherever you run it."],
  ["Who operates it",
   "We do. Read “Who is on the other end” below before you decide.",
   "You do. We support it; we cannot see it."],
  ["Time to running",
   "One command, no contact with us required.",
   "A conversation with us first — see “Self-hosting, plainly” below."],
];

// What crosses the boundary, per plane. The table exists because the answer DIFFERS by
// plane, and a reviewer who assumes "all of it, always" is wrong in both directions.
const FLOWS = [
  ["Browser extension", "Prompt text is scanned and a verdict plus metadata is sent. The text itself is sent only if your org has switched on content storage."],
  ["CLI hooks — Claude Code, Cursor, Codex, Copilot, Gemini", "The same verdict-and-metadata default. A hook that cannot reach Palivane fails open: your tooling keeps working and the capture is lost rather than your work."],
  ["Egress proxy (desktop apps)", "Traffic is inspected by the proxy on your own machine. The verdict is what leaves it."],
  ["MCP — local stdio wrapper and hosted endpoint", "Tool calls are inspected. Benign captures are discarded rather than stored, unless you turn that on."],
  ["SaaS connectors — Workspace, M365, Slack, Salesforce", "Read-only API access under credentials you grant and can revoke from the console at any time."],
  ["Warehouse AI — Snowflake Cortex, Databricks Model Serving", "Read-only queries against the platform's own logs, under a credential you issue and can revoke. We read records of AI calls your warehouse already kept; nothing is added to it."],
  ["Optional LLM judge", "Off unless you enable it. When on, the content it reviews goes to a model provider — your own account if you supply a key, and otherwise ours, which is why Anthropic appears in our subprocessor list. Detection without the judge is deterministic and involves no AI service at all."],
];

const RETENTION = [
  ["Metadata-only by default", "A finding records the verdict, the detector that fired, the surface and the actor. Not the prompt."],
  ["Benign traffic is not persisted", "Clean captures feed the inventory and usage counters, then go. Keeping them is opt-in, per surface."],
  ["Content storage is an explicit opt-in", "Per organization, off until an admin turns it on, encrypted under a per-tenant data key when they do."],
  ["Retention is yours to set", "Per-org findings retention, down to days."],
  ["Export and deletion are self-serve", "Full JSON export, and organization deletion that removes every row your org owns — without going through us."],
];

const CELL = {
  padding: "14px 18px",
  borderTop: "1px solid rgba(128,128,128,.18)",
  verticalAlign: "top",
};

export default function Security() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">SECURITY</div>
        <h1>Where your data goes, and who is on the other end</h1>
        <p>Palivane reads the traffic you care most about, so the deployment question matters
           more here than it does for most tools. This page answers it directly: what crosses
           the boundary, what we keep, what we are, and when you should run it yourself
           instead. The controls behind it are inventoried on{" "}
           <a href="/trust">Trust &amp; security</a>; the per-surface detail is in{" "}
           <a href="/docs/data-flows">Data flows</a>.</p>
      </section>

      {/* Deployment first: it is the decision, and it changes every answer below it. */}
      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2" style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="lp-card-icon" style={{ width: 34, height: 34, marginBottom: 0 }}><DuoServer /></span>
            Two ways to run it
          </h2>
          <p className="lp-sub" style={{ maxWidth: "72ch" }}>
            Same detection engine either way. What differs is who holds the data.
          </p>
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
          <h2 className="lp-h2" style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="lp-card-icon" style={{ width: 34, height: 34, marginBottom: 0 }}><DuoEye /></span>
            What actually crosses the boundary
          </h2>
          <p className="lp-sub" style={{ maxWidth: "72ch" }}>
            Per capture plane, on a hosted deployment. On a self-hosted one the answer is
            “nothing”, for all of them.
          </p>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
            {FLOWS.map(([t, body]) => (
              <div key={t} className="lp-card"><h3>{t}</h3><p>{body}</p></div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2" style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="lp-card-icon" style={{ width: 34, height: 34, marginBottom: 0 }}><DuoLock /></span>
            What we retain
          </h2>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
            {RETENTION.map(([t, body]) => (
              <div key={t} className="lp-card"><h3>{t}</h3><p>{body}</p></div>
            ))}
          </div>
        </div>
      </section>

      {/* The section this page exists for. Nothing here is softened: a reviewer who finds
          any of it out later would be right to discount everything else we say. */}
      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2" style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="lp-card-icon" style={{ width: 34, height: 34, marginBottom: 0 }}><DuoUsers /></span>
            Who is on the other end
          </h2>
          <div style={{ maxWidth: "74ch" }}>
            <p className="lp-sub">
              <strong>Palivane is founder-operated.</strong> One person builds it, deploys it
              and is on call for it. That is unusual for a security vendor and you should
              price it into your review rather than discover it afterwards.
            </p>
            <p className="lp-sub">
              <strong>We are not SOC 2 certified today.</strong> The Type II program is
              underway with a report expected in 2027, Type I sooner, and an independent
              penetration test is scheduled inside that observation window. Until those
              exist, what we can give a reviewer is this page, our DPA, a completed CAIQ
              questionnaire and the source of everything that runs on your machines. Not an
              attestation. If your process requires one, self-hosting is the honest answer
              and we would rather say so now than waste your quarter.
            </p>
            <p className="lp-sub">
              <strong>A hosted deployment concentrates risk, by design.</strong> It holds
              scored, labelled findings across every tenant — which makes it a more
              attractive target than any single tool it watches. Metadata-only defaults,
              per-tenant encryption keys and Postgres row-level security are how we shrink
              that blast radius, and they are real. They do not make the concentration go
              away. If your threat model takes that seriously, it is a legitimate reason to
              run Palivane yourself, and we will help you do it.
            </p>
            <p className="lp-sub">
              <strong>Your own inventory will flag us.</strong> Palivane does not exempt
              itself from its own shadow-AI detection: unless you add it to your sanctioned
              list, <code>app.palivane.io</code> shows up as an unsanctioned destination in
              your inventory alongside everything else. That is deliberate. A tool that hid
              its own traffic from you would be the wrong tool.
            </p>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Self-hosting, plainly</h2>
          <div style={{ maxWidth: "74ch" }}>
            <p className="lp-sub">
              Self-hosting is a real, supported deployment — and today it goes through us
              rather than a download link. Everything that runs on your machines is already
              public and Apache-2.0 at{" "}
              <a href="https://github.com/SOC-Foundry/palivane-clients">github.com/SOC-Foundry/palivane-clients</a>,
              so you can audit the capture side before you talk to anyone. The server package
              is not yet a self-serve release; we hand it over, help you stand it up and
              support it from there.
            </p>
            <p className="lp-sub">
              Being direct about the trade: that means the deployment which requires the most
              trust from us is the one you can start alone, and the one that requires none is
              the one where you have to talk to us first. We would rather state that than
              let you find it at the bottom of a pricing page. If self-hosting is what your
              review needs, start the conversation:{" "}
              <a href="mailto:sales@palivane.io">sales@palivane.io</a>.
            </p>
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2" style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="lp-card-icon" style={{ width: 34, height: 34, marginBottom: 0 }}><DuoRadar /></span>
            You do not have to decide this first
          </h2>
          <div style={{ maxWidth: "74ch" }}>
            <p className="lp-sub">
              Palivane starts in monitor mode: it observes, scores and reports, and blocks
              nothing until you turn enforcement on for specific rules. So the first decision
              is not “do we route everything through this vendor forever”, it is “can we look
              at what is already leaving, for a couple of weeks, and read the report”.
            </p>
            <p className="lp-sub">
              That is a smaller question, and it is the one most teams should answer first —
              on hosted if the scope is acceptable to you, self-hosted if it is not.{" "}
              <a href="mailto:sales@palivane.io">Ask for an AI exposure assessment</a>, or
              read <a href="/trust">how the controls are built</a> before you do.
            </p>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
