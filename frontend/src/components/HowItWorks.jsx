// Public technical deep-dive, reachable without auth at /how-it-works. Linked from the
// landing page's "How detection works" section. Reuses the landing (lp-*) shell and the
// .legal article styling so it matches the brand. Content mirrors README "How detection
// works" — kept accurate for a security-minded reader evaluating the engine.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";

const SEVERITIES = [
  ["critical", "80–100", "block", "A verified secret, or several strong signals at once."],
  ["high", "60–79", "quarantine", "A strong data-loss or attack signal."],
  ["suspicious", "35–59", "quarantine", "Worth review — often a warn in monitor mode."],
  ["low", "15–34", "monitor", "A minor or low-confidence signal."],
  ["benign", "0–14", "allow", "No meaningful risk signal."],
];

export default function HowItWorks() {
  return (
    <div className="landing">
      <SiteNav />

      <article className="legal">
        <h1>How Warden works</h1>
        <p className="legal-updated">The detection engine, end to end — and why the core runs entirely offline.</p>

        <p>
          Warden turns every piece of AI-bound content — a prompt to your own LLM, a paste into
          ChatGPT, an AI agent's tool-call, a commit — into a single <strong>risk verdict</strong>.
          The pipeline is the same everywhere it captures: <strong>content → detectors → signals →
          scoring → verdict</strong>. The core is <strong>pure Python regex and heuristics — no API
          key, no network call, deterministic</strong>. An optional LLM judge layers on top for the
          novel cases the rules miss, but nothing below depends on it.
        </p>

        <h2>1. Capture, then route by surface</h2>
        <p>
          Content arrives from whichever capture point saw it — the LLM gateway, the browser
          extension, the egress proxy, or CI — tagged with a <strong>surface</strong> describing
          where it came from: <code>llm_io</code> (prompts to your own models), <code>ai_usage</code>{" "}
          (content bound for external AI tools), <code>mcp</code> (agent tool-use), <code>deps</code>,{" "}
          <code>ide</code>, and <code>secrets</code> (credentials at rest on a device). The engine
          runs <strong>only the detectors that declare that surface</strong>, so attack rules apply
          to your models and data-loss rules apply to outbound content. Each detector is sandboxed —
          one that errors can never sink the whole analysis.
        </p>

        <h2>2. Detectors emit signals</h2>
        <p>
          A detector inspects content and emits zero or more <strong>signals</strong>, each a single
          piece of evidence carrying a <strong>weight</strong> (how much this kind of evidence
          matters) and a <strong>confidence</strong> (how sure the detector is it's really present).
          The offline detectors:
        </p>
        <ul>
          <li>
            <strong>Prompt-threat detector</strong> (<code>llm_io</code>) — instruction-override /
            injection, jailbreak &amp; guardrail-evasion personas, and system-prompt / secret
            exfiltration. It matches against a <em>normalized</em> view of the text that folds
            homoglyphs, full-width, zero-width, and spacing tricks, so evasion like <code>іgnore</code>{" "}
            (Cyrillic <code>і</code>) still trips. Long base64 blobs are decoded and re-scanned — if a
            blob decodes to attack text it's treated as the real injection — and invisible / zero-width
            characters get their own signal.
          </li>
          <li>
            <strong>Shadow-AI detector</strong> (<code>ai_usage</code> / <code>mcp</code>) — secrets,
            PII (SSN with or without dashes, Luhn-valid payment cards, IBAN / national IDs,
            keyword-confirmed passport / EIN / routing / SWIFT, and single-record combinations),
            proprietary source code, and confidential business content (including classification
            labels like TLP and Purview/MIP banners).
          </li>
          <li>
            <strong>Agentic (MCP) guard</strong> — sensitive-file access, dangerous commands, tool
            poisoning, and untrusted MCP servers, read off the agent's tool-use.
          </li>
          <li>
            <strong>Supply-chain &amp; IDE guards</strong> (<code>deps</code> / <code>ide</code>) —
            risky dependency manifests (install-script abuse, non-registry sources, known-bad
            packages + OSV CVEs) and unapproved editor extensions.
          </li>
          <li>
            <strong>Credentials at rest</strong> (<code>secrets</code>) — live keys sitting on a
            managed endpoint (cloud SA keys, <code>.npmrc</code>, <code>.git-credentials</code>, key
            files), optionally with TruffleHog/Gitleaks verification.
          </li>
        </ul>

        <h2>3. Secret detection is two-tier</h2>
        <p>
          Because a leaked credential is the highest-stakes finding, secret detection is layered:
        </p>
        <ul>
          <li>
            <strong>Known formats</strong> — distinctive-prefix patterns (OpenAI, Anthropic, AWS,
            GitHub incl. fine-grained PATs, GitLab, Stripe, Slack, Google, npm/PyPI, PEM private keys,
            JWTs, labeled <code>key=value</code>). A match is near-certain, so it carries full weight
            and hard-blocks.
          </li>
          <li>
            <strong>Evasion variants</strong> — the same prefixes with the separator deliberately
            stripped (<code>ghp_…</code> → <code>ghp…</code>). A real key never ships without its
            delimiter, so this reads as an attempt to slip a credential past DLP — still a hard block,
            labeled as a likely bypass.
          </li>
          <li>
            <strong>High-entropy heuristic</strong> — catches novel/vendor tokens with no known prefix
            using Shannon entropy and mixed character classes, while excluding hex digests (git SHAs)
            and UUIDs. Lower-confidence by nature, so it <strong>warns rather than blocks</strong> on
            its own.
          </li>
          <li>
            <strong>Custom patterns</strong> — each org can add its own secret / PII / confidential
            formats (customer IDs, account numbers, MRNs, codenames), applied across every plane with
            no redeploy.
          </li>
        </ul>

        <h2>4. Scoring fuses signals into one verdict</h2>
        <p>
          The scoring engine combines signal contributions (weight × confidence) with a{" "}
          <strong>saturating probabilistic OR</strong>: <code>1 − Π(1 − c)</code>. This means a pile
          of weak signals can't trivially max the score, but a few strong ones reliably do. The{" "}
          <strong>attack / data-loss confidence is the base risk</strong>; an "AI-generated"
          assessment is only an amplifier (plenty of benign text is AI-written), never a threat on its
          own. The result maps to a 0–100 score, a severity, and a recommended action:
        </p>
        <table className="hiw-table">
          <thead><tr><th>Severity</th><th>Risk</th><th>Action</th><th>Meaning</th></tr></thead>
          <tbody>
            {SEVERITIES.map(([sev, range, action, desc]) => (
              <tr key={sev}>
                <td><span className={`sev sev-${sev}`}>{sev}</span></td>
                <td><code>{range}</code></td>
                <td>{action}</td>
                <td>{desc}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <h2>5. Monitor or enforce</h2>
        <p>
          Each capture point runs in one of two modes. In <strong>monitor</strong> mode nothing is
          blocked — content passes through and findings are recorded, ideal for a rollout's first
          phase so you see what would trip before you turn on enforcement. In <strong>enforce</strong>{" "}
          mode, findings at or above your block severity are stopped at the source: the extension
          shows a block modal, the gateway returns an error, the git hook fails the commit. Source-code
          detection is automatically suppressed for sanctioned coding tools (Claude Code, Cursor,
          Copilot) — but a <em>secret</em> inside that code still blocks.
        </p>

        <h2>6. Offline first — the judge is additive</h2>
        <p>
          Everything above runs with <strong>no API key and no outbound call</strong>. That makes
          detection <strong>fast, free, private</strong> (content never leaves your environment on the
          offline path), and <strong>deterministic</strong> — the same input always yields the same
          verdict, which is what makes Warden's labeled-corpus evaluation meaningful. Connect a
          frontier model (Claude, GPT, or Gemini) and the <strong>LLM judge</strong> reads content like
          an analyst for the novel cases the rules miss — but it's strictly additive. A tenant can turn
          it off for data-residency and still get a fully functional engine.
        </p>

        <p style={{ marginTop: 32 }}>
          <a className="primary-btn slim" href="/" style={{ textDecoration: "none" }}>← Back to overview</a>
        </p>
      </article>

      <SiteFooter />
    </div>
  );
}
