# Palivane. Overview

**Govern how your organization uses AI. DETECT · BLOCK · PROTECT.**

Palivane is a **hosted, multi-tenant** security gateway for AI (self-hostable if you prefer).
It sits between your people and tools and the models they talk to, your own LLM apps or
public services like ChatGPT, Claude and Gemini, and detects, records and (optionally)
blocks risky prompts and data before they cause harm. You don't run infrastructure: sign in
to the console and configure every capture plane from **Connect → Quick start**.

---

## 1. The problem

Organizations adopting AI face two risks at once:

- **Attacks on your own LLM apps.** Prompt injection, jailbreaks, and attempts to pull out
  your system prompt, keys, or other secrets the model can see.
- **Shadow-AI data leakage.** Employees and agents send secrets, personal data and
  proprietary code to AI tools, often ones IT never approved.

Palivane covers both from one control plane, captured **automatically at the edge**, in
**monitor mode** (record and alert) or **enforce mode** (block inline).

---

## 2. What it does

- **Detects** injection, jailbreak and exfiltration attempts against your LLMs.
- **Detects** secrets, PII/PHI and source code headed to AI tools, including keys disguised
  by stripped separators, look-alike characters, or base64/hex encoding.
- **Enforces** an allowlist of sanctioned AI tools, and blocks or redacts inline.
- **Checks agents' tool calls** (shell, files, MCP) before they run.
- **Scans** commits, CI pipelines, repositories, buckets, databases and laptops for
  credentials already exposed, with only masked findings leaving the machine.
- **Scans** Slack, Teams, email, Drive, SharePoint and Salesforce for what landed there.
- **Gives** security teams one console to triage, set policy, and prove coverage.

Core detection runs **offline** on local rules and on-box classifiers, with no LLM key. An
optional **LLM judge** (Claude, GPT or Gemini, or your org's own key) adds a second opinion
for novel attacks and unmarked confidential content.

---

## 3. How traffic is captured

Each plane is described in full, with what it needs and whether it can block, on the
[coverage page](/coverage).

| Plane | What it covers | Installs |
|---|---|---|
| **LLM gateway** | Your own apps and SDKs (OpenAI, Anthropic, Gemini, Responses API) | A base-URL change |
| **Inference hooks** | Every Claude product, for Claude Enterprise | Nothing on devices |
| **Browser extension** | claude.ai, ChatGPT, Gemini, Copilot web | Extension, MDM-pushable |
| **Egress proxy** | Desktop AI apps, AI sidebar extensions, IDE assistants, CLIs | Local proxy + CA, MDM-pushable |
| **Coding-tool hooks** | Claude Code, Cursor, Codex, Gemini CLI, Copilot | One CLI install |
| **Git & CI** | Commits, pull requests, pipelines, GitHub orgs | A hook or workflow step |
| **SaaS connectors** | Slack (one-click), Teams, Gmail, Outlook, Drive, SharePoint, Salesforce, warehouse AI | A read-scoped token |
| **At-rest scanners** | Laptops, S3, repositories, databases | Runs where the data lives |

**Onboarding is managed or self-serve.** Fleets get zero-touch config from the MDM policy
pack; individuals sign in from the extension or `palivane connect`, which mints a
per-user, revocable key.

**Every plane fails open.** If Palivane is unreachable, tools keep working. Confirmed
secret and personal-data leaks are the one exception and still block.

**Agents are covered across vendors.** Claude Code, Cursor, Codex, Gemini CLI, Copilot,
browser AI and MCP land in one normalized **session timeline**, and a sequence that only
looks dangerous together (read credentials, run a command, send data out) raises one
escalated finding.

---

## 4. How detection works

Every captured item is routed by **surface** to the detectors that apply, scored, and
turned into a **verdict**.

- **Prompt threats:** injection, jailbreak and exfiltration phrasing, plus an on-box
  classifier for paraphrases.
- **Shadow AI:** secrets (known formats, evasion variants, high-entropy tokens, your own
  patterns), PII and PHI, confidential markings, source code, and the destination checked
  against your allowlist.
- **Agentic (MCP) guard:** sensitive-file access, dangerous commands, poisoned tool
  descriptions, and untrusted servers, checked against a weekly reputation dataset built
  from the official MCP registry, npm, PyPI and OSV.
- **Supply chain & IDE:** risky dependencies, known-bad editor extensions, and hidden
  instructions in agent rules files (CLAUDE.md, .cursorrules, AGENTS.md).
- **Optional LLM judge:** a frontier model reads the content like an analyst.

**Scoring.** Signals combine with a saturating OR, so many weak signals don't max out the
score but one strong signal can. The result is a 0–100 risk score and a severity.

**Evasion resistance.** Text is normalized (Unicode folding, look-alike letters, zero-width
characters) and encoded runs are decoded and re-scanned before matching, on the server and
in the at-rest scanners alike.

**Policy.** Signals that don't apply in context are suppressed per tool: Claude Code
legitimately sends source code, so that signal is off for it while secret detection stays on.

---

## 5. Data flow examples

### A paste into a public AI site (browser extension)

```
1. User pastes a secret into claude.ai
2. The extension extracts the prompt before it is sent
3. → POST /api/ingest/ai-usage
4. → detectors + destination check (+ optional judge)
5. → allow | warn | block, enforced in the page
```

### A prompt through the gateway (Claude Code)

```
1. ANTHROPIC_BASE_URL points at Palivane
2. → POST /v1/messages, authenticated, tenant and user resolved
3. → detectors → verdict → per-tool policy
4. → enforce and over threshold: a provider-shaped 403
     otherwise: finding recorded, request forwarded, response streamed back
```

Exactly what leaves each machine, per mode, is on the [data-flows page](/docs/data-flows).

---

## 6. Security of the platform

- **Tenant isolation** enforced in the database (row-level security), not only in code.
- **Metadata by default:** findings keep the verdict and a masked excerpt, not the prompt.
- **SSO** (OIDC, SAML 2.0), **TOTP MFA**, **SCIM 2.0**, an admin **audit log**.
- **Per-org retention**, self-serve export, and one-click organization deletion.
- **Signed releases:** the CLI, hooks and installer are signed with a key held in Cloud
  KMS, and clients refuse anything unsigned or older than what they already run.

More on the [security page](/security).

---

## 7. Use it from your AI assistant

Palivane's console is also an MCP server. Connect Claude Code, Claude Desktop or any MCP
client to `https://app.palivane.io/api/mcp/` and ask it to list findings, investigate one,
check the AI tool inventory, or triage, with the same permissions you have in the console.
See [Connect your AI assistant](/docs/mcp).

---

## 8. Running it yourself

Palivane is a managed service; self-hosting is a supported Enterprise option. The same
image runs with Docker Compose for evaluation (`docker compose up --build`) or on your own
cloud. See [Setting up Palivane](/docs/setup).
