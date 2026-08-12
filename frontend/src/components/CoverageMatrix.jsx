// Public coverage matrix at /coverage: every surface Palivane watches, the exact
// interception mechanism, what it requires on the device, and whether it can block or
// only observe — including the known gaps. This page is deliberately blunt: the product's
// core promise is honesty about what it sees, so the matrix says precisely what each
// claim on the landing page rests on. Content mirrors README "Where Palivane captures
// AI usage" — keep the two in sync. (Coverage.jsx is the console's fleet-coverage view;
// this is the marketing page.)
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { IconShield } from "./icons.jsx";

// mode: "block" (can stop it inline) | "observe" (visibility only)
const GROUPS = [
  {
    title: "Network planes — nothing on the device",
    sub: "Capture happens server-side. No agent, no helper, no certificate.",
    rows: [
      {
        surface: "Your own AI apps & API traffic",
        how: "LLM gateway — an OpenAI-, Anthropic- and Gemini-compatible reverse proxy; prompts and responses are scored inline on the way to the provider",
        needs: "A base-URL change in the client or SDK. Nothing installed anywhere.",
        mode: "block",
      },
      {
        surface: "Alerts, SIEM, data lake",
        how: "Findings pushed from the backend (Slack/webhook alerts, Splunk HEC / CEF / JSON, S3 NDJSON archive)",
        needs: "A destination URL or bucket. Nothing installed anywhere.",
        mode: "observe",
      },
    ],
  },
  {
    title: "Browser & desktop planes — pushed via MDM, or one command",
    sub: "These need something on the machine. On a managed fleet you push it (Jamf, Intune, Group Policy) and nobody installs anything by hand; on an unmanaged machine it's one command.",
    rows: [
      {
        surface: "Browser AI (claude.ai, ChatGPT, Gemini, Microsoft Copilot web)",
        how: "Manifest V3 browser extension — intercepts the prompt before it's sent",
        needs: "Extension install: browser-policy force-install via self-hosted CRX (public Web Store listing coming), or manual on unmanaged machines.",
        mode: "block",
      },
      {
        surface: "Desktop AI apps, IDE assistants, third-party CLIs (Claude/ChatGPT desktop, GitHub Copilot, …)",
        how: "Local TLS egress proxy (mitmproxy) — inspects outbound calls to known AI hosts",
        needs: "palivane-desktop: a local proxy + a trusted CA certificate, MDM-pushable.",
        mode: "block",
      },
      {
        surface: "Credentials already sitting on laptops",
        how: "Scheduled local filesystem scan (palivane-secrets, TruffleHog-backed when available)",
        needs: "The CLI helper + a scheduled task (launchd / cron / Task Scheduler), MDM-pushable.",
        mode: "observe",
      },
    ],
  },
  {
    title: "AI coding tools — local hooks, before anything leaves or runs",
    sub: "Coding agents under subscription sign-in send prompts no network plane can see. These hooks read the prompt and the tool call on the device, before transmission or execution.",
    rows: [
      {
        surface: "Claude Code — typed prompts & tool calls (shell, files, MCP)",
        how: "UserPromptSubmit + PreToolUse hooks (palivane-hook) — scored before the prompt leaves / before the tool runs",
        needs: "One-line CLI install (palivane-connect wires the hooks).",
        mode: "block",
      },
      {
        surface: "Codex CLI / Gemini CLI — prompts & tool calls (every auth mode)",
        how: "The same hook pattern per tool (palivane-codex-hook, palivane-gemini-hook)",
        needs: "Same CLI install — hooks are wired automatically when the tool is present.",
        mode: "block",
      },
      {
        surface: "GitHub Copilot — CLI & VS Code agent mode",
        how: "Copilot hooks (palivane-copilot-hook): tool calls inspected pre-execution; prompts captured on submit",
        needs: "Same CLI install.",
        mode: "block",
        note: "Tool calls are deniable; Copilot's hook API makes prompts observe-only.",
      },
      {
        surface: "Cursor — prompts & tool calls",
        how: "Cursor agent hooks — local, pre-execution (Cursor's chat pins its TLS certificate, so the proxy deliberately isn't the mechanism here)",
        needs: "Same CLI install.",
        mode: "block",
      },
      {
        surface: "Agent tool-use over MCP (remote and local stdio servers)",
        how: "Remote/HTTP MCP through the egress proxy; local stdio via the palivane-mcp wrapper; tool definitions also read off gateway LLM traffic — requests, responses, and mid-stream",
        needs: "The proxy or the wrapper, per server type.",
        mode: "block",
      },
    ],
  },
  {
    title: "Code & CI — at the boundary where secrets become incidents",
    rows: [
      {
        surface: "Commits & repositories",
        how: "Pre-commit hook + GitHub Action → code scan (secrets, PII, dependency risk)",
        needs: "A hook or workflow step in the repo.",
        mode: "block",
      },
      {
        surface: "Coding agents on GitHub Actions runners",
        how: "Workflow scan (palivane-ci-scan): flags steps handing agents non-model credentials or disabling approvals, plus runner-posture risks",
        needs: "A workflow step; runs pre-merge.",
        mode: "block",
      },
      {
        surface: "S3 buckets & GitHub repos at rest",
        how: "Scheduled server-side scans of configured buckets/repos",
        note: "Read-only by design: it reports what is already exposed and how to fix it — it never deletes an object, rewrites history, or changes a bucket policy.",
        needs: "Read credentials for the target (s3:GetObject / a read token). Nothing on devices.",
        mode: "observe",
      },
    ],
  },
];

// The gaps, stated plainly. A coverage page that only lists wins is a brochure.
const GAPS = [
  ["Unmanaged, unenrolled devices", "A personal laptop with no extension, proxy, or hooks is invisible. The coverage view in the console exists precisely to show you who that is."],
  ["Copilot prompts", "Copilot's hook API allows inspecting tool calls (deniable) but exposes prompts observe-only — we can see them, not stop them."],
  ["OTEL-bridge capture", "Orgs using the claude-otel bridge get monitor-only, post-hoc capture — the event has already happened when it's scored."],
  ["Mobile apps", "Native mobile AI apps are not covered. The browser extension covers mobile web only where the browser supports extensions."],
  ["Agentic browsers", "Where the agent IS the browser (Perplexity Comet, Dia, the ChatGPT desktop app that absorbed Atlas), the model call originates from the browser itself, not a page fetch the extension wraps. The egress proxy now parses Comet's assistant SSE and flags its agent WebSocket, and the ChatGPT desktop app rides the proxy's existing chatgpt.com handling — but none of it has been verified against a real build yet (no Linux builds exist; the macOS/Windows pass is docs/agentic-browser-verification.md). Until that pass lands, treat these as discover-only: we see the usage, inline interception is built but unproven. Dia stays discovery-only by design — its real API hosts are unverified (catalog row flagged provisional)."],
];

// The threat model, including the bypass list. Every control here runs on a machine the
// user administers, so a determined insider can defeat it — say so before a buyer's red
// team does. Framing: Palivane prevents accidents and produces evidence; it is not an
// insider-threat containment tool.
const BYPASSES = [
  ["Local admin can disable the planes", "A developer with root can unset the hooks, remove the proxy and CA, or uninstall the extension. On managed fleets MDM re-applies configuration and the coverage view shows the device going dark — you'll know, but only after the fact."],
  ["Environment overrides", "Gateway routing rides on a base-URL variable; a shell export can point a tool back at the provider. The local hooks still see prompts and tool calls in the supported coding tools — but a tool we don't hook, run off-fleet, is out of sight."],
  ["The second screen", "A phone on desk data-egress: reading source on the laptop and retyping it into a personal device never touches any control Palivane (or any endpoint product) has."],
  ["Novel or self-hosted AI endpoints", "The egress proxy inspects known AI hosts. An unlisted endpoint — a personal VPS running an open-weights model — passes as ordinary HTTPS unless you add it to the inspected list."],
];

function ModeBadge({ mode }) {
  return mode === "block"
    ? <span className="cov-badge cov-block">can block</span>
    : <span className="cov-badge cov-observe">observe-only</span>;
}

export default function CoverageMatrix() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">COVERAGE</div>
        <h1>What Palivane sees — and what that takes</h1>
        <p>Every surface, the exact interception mechanism, what it requires, and whether it
           can block or only observe. Most tools in this category won't publish this table;
           we'd rather you evaluate against it than find out later.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="cov-explainer">
            <h2 className="lp-h2" style={{ fontSize: 19, marginBottom: 8 }}>
              What the Enforcement column means</h2>
            <p className="lp-sub" style={{ textAlign: "left", margin: "0 0 10px" }}>
              <strong>Can block</strong> means the check sits in front of an action that hasn't
              happened yet — the API request, the paste, the prompt, the merge — so refusing it
              prevents the thing. <strong>Observe-only</strong> means the action already
              happened and the check reports on it.
            </p>
            <p className="lp-sub" style={{ textAlign: "left", margin: "0 0 10px" }}>
              It's a question of <em>when you look</em>, not of how good the detection is. The
              same workflow scan that fails a pull request before merge becomes observe-only
              once that code is in the repo, because there is nothing left to refuse — only a
              fact to hand you, with the fix.
            </p>
            <p className="lp-sub" style={{ textAlign: "left", margin: 0 }}>
              That's why scanning at rest is deliberately read-only. Palivane reads your bucket
              with <code>s3:GetObject</code> and your repositories with a read token; it cannot
              delete an object or rewrite a branch, because it is never given the access to do
              so. Handing a detection tool write access to production so it could "remediate"
              on a match is a worse failure mode than a finding you action yourself. The
              enforcement point for <em>new</em> secrets is earlier — the pre-commit hook and
              the pull-request gate, both of which can block.
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
            Every plane above starts in <strong>monitor mode</strong> — you see findings before
            anything is ever blocked, and blocking is a per-org switch (confirmed secret leaks
            hard-block even in monitor mode, by design). Deployment details for each plane are
            on the <a className="lp-textlink" href="/setup">Setup page</a>; exactly what leaves
            the machine, per mode, is on the <a className="lp-textlink" href="/docs/data-flows">data-flows
            page</a>.
          </p>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">Measured detection quality</h2>
          <p className="lp-sub" style={{ textAlign: "left" }}>
            Numbers from our own labeled corpora, offline detectors only (the optional LLM
            judge disabled), measured 2026-08-10. The corpora and the harnesses that produce
            these are in the repo — reproduce it yourself:
            {" "}<code>pytest tests/bench_recall.py tests/bench_false_positives.py tests/bench_evasion.py -s</code>.
            We publish the weak numbers too; a benchmark that only flatters is a brochure.
          </p>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>
            <div className="lp-card">
              <div className="bench-stat">95.9%</div>
              <h3>Recall</h3>
              <p>93 of 97 malicious payloads detected and actioned across injection,
                 jailbreak, exfiltration, PII, secrets, dangerous commands.</p>
            </div>
            <div className="lp-card">
              <div className="bench-stat">5.8%</div>
              <h3>False-positive rate</h3>
              <p>6 of ~100 benign samples. Zero on prose, business/legal, AI prompts, and
                 benign MCP — concentrated in real source code (26.7%), which is the honest
                 weak spot we're still driving down.</p>
            </div>
            <div className="lp-card">
              <div className="bench-stat">19</div>
              <h3>Known evasion bypasses</h3>
              <p>Adversarial transforms (leetspeak, homoglyphs, spacing, translation) that
                 still defeat the offline detectors in our own evasion matrix. Tracked, not
                 hidden — the LLM judge closes most of these when enabled.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <h2 className="lp-h2">Known gaps</h2>
          <p className="lp-sub">Where the visibility ends. If a vendor tells you their coverage
             has no edges, ask harder questions.</p>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
            {GAPS.map(([title, body]) => (
              <div className="lp-card" key={title}>
                <h3>{title}</h3>
                <p style={{ marginTop: 8 }}>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-section alt">
        <div className="lp-wrap">
          <h2 className="lp-h2">The threat model — including how to bypass us</h2>
          <p className="lp-sub">Every control above runs on a machine its user administers, so
             an honest threat model starts with what a determined person can defeat. Palivane
             is built to <strong>stop accidents before they happen and produce evidence and
             coverage visibility for everything else</strong> — the engineer about to paste a
             customer export into ChatGPT at 6pm, the agent about to run a destructive command,
             the key that's been sitting in a repo since March. It is not an insider-threat
             containment tool, and a vendor who claims endpoint controls can contain a
             malicious insider is describing a product that doesn't exist.</p>
          <div className="lp-cards" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
            {BYPASSES.map(([title, body]) => (
              <div className="lp-card" key={title}>
                <h3>{title}</h3>
                <p style={{ marginTop: 8 }}>{body}</p>
              </div>
            ))}
          </div>
          <p className="lp-sub" style={{ textAlign: "left", marginTop: 18 }}>
            What this buys you in practice: the accidental leak is stopped inline, the risky
            pattern is visible before it becomes an incident, policy violations carry an audit
            trail, and the <strong>coverage view names every device and person outside the
            controls</strong> — so the bypass itself becomes a signal. If your requirement is
            containing a malicious insider with local admin, you need device attestation and a
            legal deterrent, not a DLP product — ours or anyone's.
          </p>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>Prove it against your own fleet.</strong> The console's coverage view shows
              which people and machines are actually reporting — per plane — and which aren't.
              Start in monitor mode and see what your coverage really is this afternoon.
            </div>
            <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Open the console →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
