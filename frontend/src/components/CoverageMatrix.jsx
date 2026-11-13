// Public coverage matrix at /coverage: every surface Palivane watches, the exact
// interception mechanism, what it requires on the device, and whether it can block or
// only observe, including the known gaps. This page is deliberately blunt: the product's
// core promise is honesty about what it sees, so the matrix says precisely what each
// claim on the landing page rests on. Content mirrors README "Where Palivane captures
// AI usage", keep the two in sync. (Coverage.jsx is the console's fleet-coverage view;
// this is the marketing page.) The gaps and the bypass list are accordions: every item
// stays on the page, one line until opened.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { IconShield } from "./icons.jsx";
import { Faq } from "./Faq.jsx";

// mode: "block" (can stop it inline) | "observe" (visibility only)
const GROUPS = [
  {
    title: "Network planes, nothing on the device",
    sub: "Capture happens server-side. No agent, no helper, no certificate.",
    rows: [
      {
        surface: "Your own AI apps & API traffic",
        how: "LLM gateway: an OpenAI-, Anthropic-, Gemini- and xAI-compatible reverse proxy that scores prompts and responses inline. Claude can also route through AWS Bedrock or GCP Vertex AI.",
        needs: "A base-URL change in the client or SDK.",
        mode: "block",
      },
      {
        surface: "Every Claude product, for Claude Enterprise: claude.ai, Cowork, Claude Code, Claude in Chrome, Claude for Microsoft 365",
        how: "Anthropic Inference hooks: each prompt and set of tool calls comes to Palivane for allow or deny before the model runs.",
        needs: "Claude Enterprise; an Owner points Inference hooks at Palivane. Palivane Team or Enterprise plan.",
        mode: "block",
      },
      {
        surface: "Slack, Microsoft Teams",
        how: "Slack: one-click Add to Slack, scanned in real time as messages and files land, with a scheduled pull as the safety net. Teams: channels and thread replies via Graph, opted-in chats via the export API.",
        note: "The Slack bot reads channels it is in; an org can let it join every public channel. Enterprise Grid's Discovery API covers private channels and DMs org-wide.",
        needs: "Add to Slack (or your own bot token); an Entra app with ChannelMessage.Read.All for Teams.",
        mode: "observe",
      },
      {
        surface: "Outbound email: Gmail, Outlook / Exchange Online",
        how: "Each user's sent mail, body and text attachments, incrementally per mailbox.",
        needs: "Google domain-wide delegation (gmail.readonly) or an Entra app with Mail.Read.",
        mode: "observe",
      },
      {
        surface: "Google Drive, SharePoint / OneDrive, Salesforce",
        how: "Drive and SharePoint/OneDrive scanned on write and on a cursor; Salesforce records and attachments on a cursor.",
        note: "Reads PDFs, Office, RTF, OpenDocument, and images where OCR is on. What can't be opened is reported as unread, never clean.",
        needs: "A read-scoped token or connected app per platform.",
        mode: "observe",
      },
      {
        surface: "AI inside the warehouse: Snowflake Cortex, Databricks Model Serving",
        how: "Polled from Snowflake QUERY_HISTORY and Databricks inference tables, then scored like any prompt: the LLM calls no browser or laptop ever sees.",
        needs: "A read-scoped warehouse credential.",
        mode: "observe",
      },
      {
        surface: "Alerts, SIEM, data lake",
        how: "Slack and webhook alerts, Splunk HEC / CEF / JSON, an S3 NDJSON archive.",
        needs: "A destination URL or bucket.",
        mode: "observe",
      },
    ],
  },
  {
    title: "Browser & desktop, pushed via MDM or one command",
    sub: "On a managed fleet you push these (Jamf, Intune, Group Policy); on an unmanaged machine it's one command.",
    rows: [
      {
        surface: "Browser AI: claude.ai, ChatGPT, Gemini, Copilot web",
        how: "Manifest V3 extension; checks the prompt before it is sent.",
        needs: "Chrome Web Store, policy force-install, or a self-hosted CRX.",
        mode: "block",
      },
      {
        surface: "Desktop AI apps, AI browser extensions, IDE assistants, third-party CLIs",
        how: "Local TLS egress proxy that inspects calls to known AI hosts, including sidebar extensions (Monica, Sider, Merlin, HARPA, MaxAI) the browser extension can't see. In Claude apps a blocked message shows its reason in the conversation.",
        needs: "palivane-desktop: a local proxy and a trusted CA, MDM-pushable.",
        mode: "block",
      },
      {
        surface: "Credentials already on laptops",
        how: "Scheduled local scan (palivane-secrets), including keys hidden by look-alike characters or encoding.",
        needs: "The CLI helper and a scheduled task, MDM-pushable.",
        mode: "observe",
      },
    ],
  },
  {
    title: "AI coding tools, checked before anything leaves or runs",
    sub: "Coding agents on subscription sign-in send prompts no network plane can see. Local hooks read the prompt and the tool call first.",
    rows: [
      {
        surface: "Claude Code, Codex CLI, Gemini CLI, Cursor: prompts & tool calls",
        how: "Each tool's own hooks (palivane-hook and siblings), scored before the prompt leaves or the tool runs.",
        needs: "One-line CLI install; hooks are wired for every tool present.",
        mode: "block",
      },
      {
        surface: "GitHub Copilot, CLI & VS Code agent mode",
        how: "Copilot hooks: tool calls checked before they run, prompts captured on submit.",
        note: "Copilot's hook API makes prompts observe-only.",
        needs: "Same CLI install.",
        mode: "block",
      },
      {
        surface: "Agent tool use over MCP",
        how: "Remote MCP through the egress proxy, local stdio servers through the palivane-mcp wrapper, tool definitions read off gateway traffic.",
        needs: "The proxy or the wrapper.",
        mode: "block",
      },
    ],
  },
  {
    title: "Code & CI",
    rows: [
      {
        surface: "Commits, pull requests, CI pipelines",
        how: "Pre-commit hook and GitHub Action for secrets, PII and dependency risk; pipeline scan for agents handed credentials and runner-posture risks (pwn-request triggers, unpinned actions).",
        needs: "A hook or workflow step.",
        mode: "block",
      },
      {
        surface: "GitHub organization, continuously",
        how: "A read-only connector reads every repository once, then each new commit (hourly, or within seconds with a push webhook). Finds keys deleted but still in history.",
        needs: "A fine-grained read token.",
        mode: "observe",
      },
      {
        surface: "S3 buckets, repositories, databases at rest",
        how: "Scanners that run where the data lives, so only findings travel: category, label, line, masked preview. palivane-dbscan samples Postgres and SQLite tables under a read-only role.",
        note: "Read-only by design: reports what is exposed, never deletes or rewrites.",
        needs: "Read credentials for the target.",
        mode: "observe",
      },
    ],
  },
];

// The gaps, stated plainly. A coverage page that only lists wins is a brochure.
const GAPS = [
  ["Unmanaged, unenrolled devices", "A personal laptop with no extension, proxy, or hooks is invisible. The console's coverage view exists to show you who that is."],
  ["Copilot prompts", "Copilot's hook API lets us deny tool calls but only observe prompts."],
  ["Column-bound warehouse prompts", "A Cortex or Model Serving prompt read from a table column isn't in the query record, so there is nothing to score. Those calls are counted and shown as column-bound."],
  ["OTEL-bridge capture", "The claude-otel bridge is monitor-only and after the fact."],
  ["Slack private channels and DMs (below Enterprise Grid)", "A bot reads only conversations it is in: public channels can be auto-joined, private ones must invite it, DMs are invisible. Enterprise Grid's Discovery API covers all of them; below Grid Slack offers no equivalent."],
  ["Database scans sample", "palivane-dbscan reads 2,000 rows per table by default, so one bad row in a large table can be missed until you raise the sample."],
  ["GitHub scanning has an edge", "Default branch unless you choose every branch; seconds only with the webhook; a secret never pushed is out of reach."],
  ["Formats nothing can open", "Pre-2007 Office, encrypted PDFs, and images with OCR off are reported as unread, never as clean."],
  ["SaaS scanning is detect-after", "Slack, Drive and SharePoint scan within seconds of landing; Teams, email and Salesforce on a cursor. Either way the leak is found after it lands: these platforms have no pre-delivery inspection point."],
  ["Teams chats are opt-in and metered", "1:1 and group chats need each mailbox named and a licensed export model; ChannelMessage.Read.All needs Microsoft's one-time approval."],
  ["Email scanning is outbound only", "Sent mail only, after it is sent. Inbound isn't scanned."],
  ["Inference hooks are allow or deny", "Anthropic's hook can't redact, is Claude Enterprise only, and never carries image bytes."],
  ["AI sidebar extensions are covered by host", "Inspected at the API hosts in each extension's code. A vendor that moves hosts drops out until the list is updated, and Fleet shows the unreadable traffic."],
  ["Mobile apps", "Native mobile AI apps are not covered."],
  ["Agentic browsers", "Perplexity Comet and the ChatGPT desktop app are handled by the proxy but not yet verified against real builds; treat them as discovery-only for now. Dia is discovery-only by design."],
];

// The threat model, including the bypass list. Every control here runs on a machine the
// user administers, so a determined insider can defeat it, say so before a buyer's red
// team does. Framing: Palivane prevents accidents and produces evidence; it is not an
// insider-threat containment tool.
const BYPASSES = [
  ["Local admin can disable the planes", "Root can remove hooks, the proxy, or the extension. MDM re-applies them and the coverage view shows the device going dark, after the fact."],
  ["Environment overrides", "A shell export can point a tool back at the provider. The hooks still see supported coding tools; an unhooked tool off-fleet is out of sight."],
  ["The second screen", "Retyping source into a phone touches no endpoint control, ours or anyone's."],
  ["Novel or self-hosted AI endpoints", "The proxy inspects known AI hosts. An unlisted endpoint passes as ordinary HTTPS unless you add it."],
];

// What Palivane does with what it captures: not interception points, but named here so
// nothing reads as missing to an evaluator scoping "coverage" as the whole product.
const GOVERNANCE = [
  ["Enforcement, per surface", "Monitor first; blocking is a per-org switch. Allow, warn, redact or tokenize, with thresholds per surface. A confirmed secret or PII leak blocks even in monitor mode."],
  ["Justified proceed", "A blocked user records a business reason and carries on; it lands on the finding and in the audit log. Confirmed credentials can't be overridden."],
  ["Agent least-privilege", "Short-lived agent identities, per-agent rate limits, role policies for servers, tools and data. MCP tool calls are checked before they run, and MCP servers against a weekly reputation dataset."],
  ["Identity & provisioning", "Per-org SSO (OIDC, SAML 2.0), TOTP MFA, and SCIM 2.0 from Okta or Entra ID."],
  ["Alerting & reporting", "Real-time alerts, first-sighting of new AI tools, a weekly exec email, SIEM and S3 export."],
  ["Data governance", "The verdict, not the prompt, by default; per-org retention; redaction before storage; self-serve export and deletion; an in-product DPA."],
];

function ModeBadge({ mode }) {
  return mode === "block"
    ? <span className="cov-badge cov-block">can block</span>
    : <span className="cov-badge cov-observe">observe-only</span>;
}

const asItems = (pairs) => pairs.map(([q, a]) => ({ q, a }));

export default function CoverageMatrix() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">COVERAGE</div>
        <h1>What Palivane sees, and what that takes</h1>
        <p>Every surface, how it's captured, what it requires, and whether it can block or
           only observe. Gaps included.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="cov-explainer">
            <p className="lp-sub" style={{ textAlign: "left", margin: 0 }}>
              <strong>Can block</strong> means the check sits in front of an action that hasn't
              happened yet (the request, the prompt, the merge). <strong>Observe-only</strong> means
              it already happened and the check reports it. Scanning at rest is read-only on
              purpose: Palivane is never given access to delete or rewrite your data, and the
              hook and pull-request gate stop new secrets earlier.
            </p>
          </div>
          {GROUPS.map((g) => (
            <div key={g.title} style={{ marginBottom: 36 }}>
              <h2 className="lp-h2" style={{ fontSize: 21 }}>{g.title}</h2>
              {g.sub && <p className="lp-sub" style={{ textAlign: "left", margin: "6px 0 14px" }}>{g.sub}</p>}
              <div className="cov-scroll">
                <table className="cov-table">
                  <thead>
                    <tr><th>Surface</th><th>How it's captured</th><th>What it requires</th><th>Enforcement</th></tr>
                  </thead>
                  <tbody>
                    {g.rows.map((r) => (
                      <tr key={r.surface}>
                        <td className="cov-surface">{r.surface}</td>
                        <td>{r.how}{r.note && <span className="cov-note"> {r.note}</span>}</td>
                        <td>{r.needs}</td>
                        <td><ModeBadge mode={r.mode} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
          <p className="lp-sub" style={{ textAlign: "left" }}>
            Every plane starts in <strong>monitor mode</strong>. Deployment details are on the{" "}
            <a className="lp-textlink" href="/setup">Setup page</a>; what leaves the machine, per
            mode, is on the <a className="lp-textlink" href="/docs/data-flows">data-flows page</a>.
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Measured detection quality</h2>
          <p className="lp-sub" style={{ textAlign: "left" }}>
            Our own labeled corpora, LLM judge off, measured 2026-08-12. The corpora and harnesses
            are in the repo, so you can reproduce them:
            {" "}<code>pytest tests/bench_recall.py tests/bench_false_positives.py tests/bench_evasion.py tests/bench_code_discrimination.py -s</code>.
          </p>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(220px, 100%), 1fr))" }}>
            <div className="lp-card">
              <div className="bench-stat">100%</div>
              <h3>Recall</h3>
              <p>97 of 97 malicious payloads: injection, jailbreak, exfiltration, PII, secrets,
                 source code, dangerous commands.</p>
            </div>
            <div className="lp-card">
              <div className="bench-stat">0%</div>
              <h3>False-positive rate</h3>
              <p>0 of 103 benign samples. Generic code stays benign (25 of 25) while proprietary
                 code is flagged (12 of 12).</p>
            </div>
            <div className="lp-card">
              <div className="bench-stat">7</div>
              <h3>Known evasion bypasses</h3>
              <p>Transforms (leetspeak, word-splitting, translation) that still beat the offline
                 detectors. Published, not hidden; the LLM judge closes most of them.</p>
            </div>
            <div className="lp-card">
              <div className="bench-stat">2</div>
              <h3>On-box ML classifiers</h3>
              <p>Code/prose (99% precision) and prompt injection (precision 1.0), both held-out.
                 CPU-only, sub-millisecond, weights in the repo.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Governance & enforcement</h2>
          <p className="lp-sub">What Palivane <em>does</em> with what it sees.</p>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(min(300px, 100%), 1fr))" }}>
            {GOVERNANCE.map(([title, body]) => (
              <div className="lp-card" key={title}>
                <h3>{title}</h3>
                <p style={{ marginTop: 8 }}>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap lp-faq-wrap">
          <h2 className="lp-h2">Known gaps</h2>
          <p className="lp-sub">Where the visibility ends. If a vendor says their coverage has no
             edges, ask harder questions.</p>
          <Faq items={asItems(GAPS)} open={-1} />
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap lp-faq-wrap">
          <h2 className="lp-h2">The threat model, including how to bypass us</h2>
          <p className="lp-sub">Every control runs on a machine its user administers. Palivane
             stops accidents and produces evidence for everything else. A containment pauses a
             person, a device or an agent on every plane and keeps blocking offline, but a local
             admin can still strip the controls, and Fleet then shows that device as gone quiet
             rather than stopped. It is not an insider-threat containment tool, and nobody's
             endpoint control is.</p>
          <Faq items={asItems(BYPASSES)} open={-1} />
          <p className="lp-sub" style={{ textAlign: "left", marginTop: 18 }}>
            The coverage view names every device and person outside the controls, so a bypass
            becomes a signal rather than a silence.
          </p>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>Prove it against your own fleet.</strong> The console's coverage view shows
              which people and machines are reporting, per plane, and which aren't.
            </div>
            <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Open the console →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
