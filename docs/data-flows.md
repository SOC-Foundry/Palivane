# Data flows: what leaves the machine, in every mode

The most important question about a tool that inspects prompts, code, and agent activity
is *where the content goes*. This page answers it precisely — per hop, per mode — instead
of with a tagline. It is deliberately blunt about the one thing marketing copy tends to
fudge.

## The one-sentence version

**Content leaves the endpoint only to reach your own Palivane backend, over TLS, so it can
be scored — and what that backend then keeps or forwards is metadata-only by default and
entirely under your control.** On a self-hosted deployment "your backend" is inside your
own network, so nothing crosses an organizational boundary at all unless *you* turn on the
optional LLM judge with a provider key.

What we do **not** claim: that "no traffic ever leaves the machine." A local hook or the
egress proxy has to send the content it captures to the scoring backend — that's an HTTP
request. Any vendor telling you their endpoint tool scores prompts with zero network
egress is either scoring nothing or not telling you where the request goes. Ours goes to
*your* Palivane instance and nowhere else by default.

## The three hops

### Hop 1 — endpoint → Palivane backend (capture)

Every capture plane sends the captured content to the backend's ingest/scan API so the
detection engine can score it:

| Plane | What it transmits |
| --- | --- |
| LLM gateway | the prompt + response it's proxying |
| Browser extension | the prompt text you're about to send |
| Egress proxy | the request body to a recognized AI host (AI hosts only — everything else is tunnelled un-decrypted; see the coverage page) |
| Coding-tool hooks (Claude Code, Codex, Gemini, Copilot, Cursor) | the typed prompt and/or the tool call, before it leaves or runs |
| Commit / CI / at-rest scanners | the file, diff, object, or repo slice being scanned |

- **In transit the content is the full captured text** — it has to be, to be scored — over
  **TLS**, authenticated with the device's per-tenant token (`ak_…`).
- The content is held in memory for scoring. **What gets *stored* is decided at the next
  hop** — transmission and retention are separate decisions.
- **Fail-open:** if the backend is unreachable the capture plane allows the action through
  rather than blocking it (a circuit breaker stops retry storms). A Palivane outage never
  becomes an outage of the user's AI tools.

### Hop 2 — what the backend stores

The engine produces a verdict (severity, risk score) and a list of **signals** — each a
category (`secret_leak`, `pii_exposure`, `prompt_injection`, …) plus short **evidence**
that is already redacted upstream: a label (`"AWS access key id"`), a ≤10-char prefix, or a
`«redacted:…»` marker — never the full secret.

| Setting | Default | Effect |
| --- | --- | --- |
| store the natural-language content | **off** | By default the backend stores **metadata only** — the verdict, the signals, and the redacted evidence. The prompt/code prose itself is **not written to the database**. |
| `PALIVANE_STORE_CONTENT` (or per-tenant opt-in) | off | Turn it on and the content *is* stored — but first **redacted** (secrets → `«redacted:label»`, SSNs and Luhn-valid cards masked) and then **encrypted at rest** under the tenant's own key (Fernet, `enc:v2:`). |
| `PALIVANE_REDACT_FINDINGS` | **on** | Redaction applied before any content or evidence is persisted. |
| `PALIVANE_ENCRYPT_FINDINGS` | **on in the managed service** | Stored content and evidence are ciphertext at rest; the raw DB column holds no plaintext secret. |

So the honest matrix of what the database holds: **by default, no prose at all** — just the
risk metadata. With content storage opted in: redacted-then-encrypted prose. The managed
service runs redact-on + encrypt-on.

### Hop 3 — what the backend forwards to third parties

All of these are **optional and off unless you configure them**, and all except the LLM
judge send only to sinks *you* own:

| Destination | What's sent | Default |
| --- | --- | --- |
| **LLM judge** (Anthropic / OpenAI / Gemini) | the content of the flagged item, for a second-opinion verdict | **off**; per-org opt-out; plan-gated on the managed service; supports bring-your-own-key |
| **SIEM** (Splunk HEC / CEF / JSON) | the finding: verdict + **redacted** signals/evidence | off until you set an endpoint |
| **Data lake / S3 archive** | analyzed events as NDJSON; prose **redacted by default** (raw is an explicit per-org opt-in) | off until configured |
| **Alerts** (Slack / webhook) | finding metadata + redacted evidence | off until you set a channel |

**The LLM judge is the only path on which un-redacted content can reach a party other than
you.** That party is a frontier-model provider (the same class of vendor whose tool the
user was already using), it runs only when enabled, an org can opt out entirely, and with
bring-your-own-key the content goes to *your* provider account on *your* bill. On the
managed service today the judge is off.

## Per mode

| | Managed SaaS (app.palivane.io) | Self-hosted |
| --- | --- | --- |
| Where the backend runs | our GCP project | **your infrastructure** |
| Hop 1 (endpoint → backend) | leaves the device to our service, over TLS | leaves the device but **stays inside your network** |
| Hop 2 (storage) | metadata-only by default; redact-on + encrypt-on | you set the policy; same defaults ship |
| Hop 3 → your SIEM / lake / alerts | to sinks you own | to sinks you own |
| Hop 3 → LLM judge | off today; opt-in, plan-gated, BYOK | off unless you set a provider key; then it's the only egress that leaves your network |
| Net for a fully-offline posture | n/a (it's our service) | **nothing crosses your org boundary** — judge off, everything else is your own infra |

For the strictest data-residency requirement, self-host with the judge off: capture,
scoring, storage, and forwarding all happen on infrastructure you control, and no content
ever leaves your network.

## What you can and cannot say about this

**Accurate:** "No third-party AI service sees your content" (judge off, or BYOK to your own
account). "Captured and scored before it reaches the provider." "Metadata-only by default —
the prose is never stored unless you opt in, and then it's redacted and encrypted."
"Self-host and nothing leaves your network."

**Not accurate:** "Nothing leaves the machine" / "scored entirely on-device." Content
leaves the endpoint to reach the Palivane backend — that's the design. The correct claim is
about *which* backend (yours) and *what* it retains (metadata by default), not about the
absence of a network request.
