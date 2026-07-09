// Public "Use cases" page at /use-cases. Concrete scenarios Warden addresses, mapped to
// the real capture planes and detectors. Reuses the landing (lp-*) design language.
import { SiteNav, SiteFooter } from "./SiteChrome.jsx";
import { IconTarget, IconShield, IconAlert, IconInbox, IconClipboard, IconPlug } from "./icons.jsx";

const CASES = [
  {
    icon: <IconTarget />, tag: "Shadow AI",
    title: "Stop sensitive data leaking into public AI tools",
    body: "Employees paste customer records, credentials, and source into ChatGPT, Claude, Gemini, and Copilot. Warden's browser extension and gateway scan every prompt and warn or block on secrets, PII, source code, and confidential content before it's sent — and offer a sanctioned alternative in the block screen.",
  },
  {
    icon: <IconShield />, tag: "AI coding assistants",
    title: "Let developers use Claude Code, Cursor & Copilot — safely",
    body: "Coding assistants are the fastest-growing egress path. Warden allows the code they're meant to see, but still blocks API keys and credentials in it, flags unsafe autonomy (YOLO / auto-apply / auto-run) and dangerous commands in AI chats, and governs the agent's MCP tool-use — source-code detection auto-suppressed for sanctioned tools so it never gets in the way.",
  },
  {
    icon: <IconInbox />, tag: "Need-to-know",
    title: "Stop your own AI from oversharing internal data",
    body: "Enterprise LLMs (M365 Copilot, Glean, internal RAG) will surface HR files, salary data, and confidential docs to any employee who asks. Warden checks each answer against your need-to-know rules and flags — or blocks — when restricted data reaches someone outside the allowed group.",
  },
  {
    icon: <IconAlert />, tag: "Agentic (MCP)",
    title: "Govern what autonomous agents are allowed to do",
    body: "AI agents call tools, run commands, and touch files. Warden inspects MCP tool-use for dangerous commands, sensitive-file access, tool-poisoning, and calls to untrusted servers — over the LLM traffic, even for local stdio MCP, so an agent can't quietly exfiltrate or destroy.",
  },
  {
    icon: <IconClipboard />, tag: "Secrets sprawl",
    title: "Find credentials before they leak — at rest and in git",
    body: "Keys don't only leak through prompts. warden-secrets scans managed endpoints for credentials at rest (cloud SA keys, .npmrc, .git-credentials, key files), and a pre-commit hook + CI check keep secrets and PII out of repos — with a one-time history sweep via TruffleHog/Gitleaks for what's already committed.",
  },
  {
    icon: <IconInbox />, tag: "Protect your own LLMs",
    title: "Defend the AI features you ship to customers",
    body: "Point your own apps at the Warden gateway and every prompt is checked for instruction-override / injection, jailbreak & guardrail-evasion, and system-prompt or secret exfiltration — with response-side DLP scanning the model's output too. Monitor first, then enforce.",
  },
  {
    icon: <IconPlug />, tag: "Compliance & visibility",
    title: "Prove governance and close your blind spots",
    body: "Coverage reconciliation compares your IdP/CASB record of who used AI to what Warden actually captured — surfacing the unmanaged, shadow set. Add per-tenant policy, a full audit log, alert digests, SIEM export, a signed DPA, and self-serve data export/delete for a defensible AI-governance story.",
  },
];

export default function UseCases() {
  return (
    <div className="landing">
      <SiteNav />

      <section className="lp-pagehead">
        <div className="lp-tagline">USE CASES</div>
        <h1>Where Warden earns its keep</h1>
        <p>From shadow-AI data loss to autonomous agents and secrets in git — one engine and
           one console across every way AI touches your organization.</p>
      </section>

      <section className="lp-section">
        <div className="lp-wrap">
          <div className="lp-cards lp-cards-2">
            {CASES.map((c) => (
              <div key={c.tag} className="lp-card">
                <span className="lp-card-icon">{c.icon}</span>
                <span className="tag tag-ai" style={{ marginLeft: 2 }}>{c.tag}</span>
                <h3 style={{ marginTop: 10 }}>{c.title}</h3>
                <p>{c.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="lp-cta-band">
        <div className="lp-wrap">
          <div className="lp-banner">
            <IconShield width={22} height={22} />
            <div>
              <strong>See it on your own traffic.</strong> Sign in, connect one source, and watch
              findings land in minutes — the core runs offline, no API key required.
            </div>
            <a className="primary-btn slim" href="/#signin" style={{ textDecoration: "none" }}>Open the console →</a>
          </div>
        </div>
      </section>

      <SiteFooter />
    </div>
  );
}
