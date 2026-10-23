# Palivane security review

Source review of the Palivane tree, dated 2026-10-22. The lens is NIST SP 800-53
Rev 5 (the control catalog) and the Produce practices in NIST SP 800-218, the
Secure Software Development Framework (SSDF). Ordinary secure-coding practice is
named with CWE where a control maps to a specific weakness.

This is a reading of the source. It is not a penetration test, not a control
assessment for an authorization, and not a statement that a deployment meets
800-53. A control is "satisfied in the source" only where the code implements
the behavior the control asks for. A deployment can still miss it by leaving a
setting off.

Inline comments in the tree point here with `SEC-0N` and a fragment such as
`#sec-01`. The earlier review notes in those same files describe the processing
gap. This document is the security reading of that gap.

## How a finding is judged

Impact is what an attacker, or a simple failure, can do to confidentiality,
integrity, or the detection control itself.

| Rating | Meaning |
|---|---|
| Moderate | The control that is supposed to see or stop the data does not, on a path a real client uses, and the caller is given a normal allow. |
| Low | The control holds for the data, and the residual is quota, noise, a late check, or a default that the hosted deploy script already overrides. |

No finding in this pass is a direct authentication bypass, a cross-tenant read,
or an injection into a shell or a query. Those areas were read and are listed
under [Controls that hold](#controls-that-hold).

<a id="sec-01"></a>
## SEC-01. The control fails open, and it does not decide the same way everywhere

**800-53:** SI-4 (system monitoring), SI-11 (error handling), AC-3 (access
enforcement). **SSDF:** PW.7, PW.8. **CWE-636** (failing open), **CWE-390**
(error without action).

Three layers treat an error as permission to proceed.

- `Engine.analyze` (`backend/app/engine.py`) catches every detector exception,
  logs nothing, and still returns `score(signals)`. A detector that crashed is
  indistinguishable from one that ran and found nothing. SI-11 asks for an
  error the operator can act on. This path produces neither a log line nor a
  signal.
- The CLI hooks and the desktop proxy catch a failed scan and return allow.
  `cli/palivane-hook` exits 0 on any exception so a developer session is never
  broken. `proxy/palivane_addon.py` `scan()` returns `action=allow` on any
  error, and the circuit breaker then keeps returning allow while the backend
  is down or the key is rejected. That is a deliberate availability choice.
  The security consequence is that the sensor, once it cannot reach the
  service, stops being a sensor and the traffic continues.
- `verdict['ask']` is set by the server for an enforced user in the warn band.
  Claude Code and Cursor read it only when local enforce is already on. Codex,
  Gemini, and Copilot never read it. AC-3 is the same decision on every path
  that can carry the action. Here the decision depends on which binary
  delivered the event.

**Direction.** Keep the user unblocked when the goal is availability, and make
that state visible: log the detector name, return a verdict that says the
analysis was partial, and on the sensor side surface `scan-failed` to the
operator instead of folding it into allow. Honor `ask` on every hook, or stop
telling the console that ask is a tenant-wide control.

<a id="sec-02"></a>
## SEC-02. The gateway does not inspect the whole request it forwards

**800-53:** SI-10 (information input validation), AC-4 (information flow
enforcement), SC-8 (transmission confidentiality, for the tokenization step).
**SSDF:** PW.8. **CWE-693** (protection mechanism failure).

The gateway is the mediation point between a client and the model provider.
Mediation has to cover the bytes that leave.

- `POST /v1/responses` scores `_responses_user_text` of `input` and does not
  call `_with_image_text`. The Responses system prompt lives in `instructions`.
  Chat, Anthropic, and Gemini pass the system prompt through `_scan_messages`
  and OCR the body. `tokenize_payload` does rewrite `instructions`, so a
  personal-data value there is hidden from the provider and still never
  scored. An item list with no `role` scores as empty and is forwarded.
  Codex uses this API.
- `_with_image_text` appends OCR text only when the string is non-empty.
  `extract_image_text` returns that same empty string when an image was
  present and dropped (over 5MB, past the four it keeps, a tesseract error).
  The request is then scored as text. The connector path treats empty OCR as
  unread. The gateway does not.
- `tokenize()` returns the original string once it is longer than
  `MAX_CHARS` (200,000). The scan has already run. Tokenization is the step
  that was supposed to keep the value out of the upstream body. Over the cap,
  the provider receives it. The `tokenize_payload` docstring used to call an
  unrecognized shape fail-safe. That is true for reversal. It is not true for
  the values in the body.
- The on-box classifiers do not cover the text they score. Code windows are
  240 characters stepped by 400, and nothing past index 2640 is scored.
  Injection scoring covers the first 1,200 characters and the last 240. A
  payload in a gap or in the middle of a long prompt does not move the
  probability, and the verdict still reads as if the tier had looked.

**Direction.** Build one scan input per provider that includes the system
prompt and a distinct "image present, text not recovered" result. Tokenize in
chunks, or refuse to forward a body `tokenize()` did not rewrite. Score
overlapping windows across the whole input, or label a truncated score as
truncated.

<a id="sec-03"></a>
## SEC-03. A partial read is recorded as a finished read

**800-53:** SI-7 (information integrity), SI-10, AU-12 (audit generation —
the record of what was examined). **SSDF:** PW.8. **CWE-345** (insufficient
verification of data authenticity, in the sense that the "scanned" mark is
not authentic).

- `_xml_text` decodes six entities. `&#65;`, `&#x41;`, and `&#xA;` stay in
  the string as the characters of the reference. OOXML writes values that
  way. The detectors then run on the reference.
- `_extract_pdf` takes parenthesized `Tj` / `TJ` literals. Hex string
  literals and the `'` / `"` show operators are skipped. A stream that fails
  to inflate contributes nothing and is not reported. `doc_extract.extract`
  treats any non-empty string as a successful read of that tier, so one
  recovered stream makes the file look scanned. The RTF destination-group
  expression stops at the first closing brace.
- `_scan_commits` appends a sha after a non-rate-limit fetch error, and it
  skips a file with no `patch` on the same line as a deleted file. GitHub
  omits `patch` when the diff is too large. `_commits` advances `last_sha`
  and `since` from the returned list, so the secret in that diff is not read
  on a later sync.

**Direction.** Decode numeric character references before the detectors see
the text. Treat a PDF or Office extract that skipped a stream as partial.
Leave a failed commit sha out of the watermark, and record a missing patch
as a skipped file.

<a id="sec-04"></a>
## SEC-04. A read method that writes, and an open metrics port

**800-53:** AC-3, AC-6 (least privilege), AU-2 (event logging — the metrics
are an operational disclosure). **CWE-749** (exposed dangerous method),
**CWE-200** (information exposure).

- `POST /api/auth/demo` mints an admin session for `viewer@demo.local` when
  `PALIVANE_DEMO_ORG` is set. Non-GET methods are refused, and
  `DEMO_BLOCKED_GET` lists the reads that mint a link or an export. `GET
  /api/siem/s3/role-setup` still commits `siem_s3_external_id` and is not in
  that tuple. A demo visitor who can call it plants an external id on the
  shared demo org. The route is dark until the demo org is configured.
- `GET /metrics` is unauthenticated when `PALIVANE_METRICS_TOKEN` is empty.
  The operator routes next to it (`/api/admin/funnel`, `/api/admin/plans`)
  answer 404 in that same case, so they cannot be left open by forgetting
  the token. Metrics can. The exposition is route-level volume and latency,
  not tenant data. On a deployment whose port is reachable, that is still an
  unauthenticated operational readout.

**Direction.** Put the role-setup GET on `DEMO_BLOCKED_GET` until it stops
committing, and have the route walk fail when a GET writes. Require
`PALIVANE_METRICS_TOKEN` whenever the process is not on a loopback listener,
the same way the admin routes already refuse to serve with no token.

<a id="sec-05"></a>
## SEC-05. Webhook authenticity holds, and the retry memory does not

**800-53:** SC-23 (session authenticity), AU-2, SI-4. **CWE-294**
(authentication bypass by capture-replay) for the residual, not for the
signature check itself.

The signature checks are real. Slack verifies HMAC-SHA256 over
`v0:{timestamp}:{body}` and rejects a timestamp outside the replay window.
GitHub verifies `X-Hub-Signature-256` over the raw body before any parse,
and an unknown connector fails the same way as a wrong signature. Graph and
Drive notifications carry a signed `clientState` / channel token with a
`typ` the session authenticator rejects, so that token is not a console
session. Unsigned notifications are dropped.

What does not hold is the memory of "already handled":

- GitHub records `X-GitHub-Delivery` before `_process_push` runs. The map is
  in-process and lives an hour. A scan that fails is seen, so GitHub's retry
  inside that hour does not run, and a second instance has its own map. The
  signature has no timestamp of its own (Slack's does). After the hour, or
  on another instance, a captured delivery is accepted again. The handler
  re-reads the named commits from GitHub with the connector token. It does
  not trust file contents from the webhook body. The impact is a repeated
  scan and quota use, and a missed retry after a crash.
- Graph answers 202 for a bad `clientState`, which is the right response for
  a sender that retries on any other code, and it means a stream of forgeries
  is invisible. `_RECENT` debounce is also per process. `clientState` is
  minted for 60 days and sent to Microsoft in the subscription. It cannot be
  presented as a user session.

**Direction.** Mark a GitHub delivery after the scan succeeds, or give a
failure a short TTL. Share that set across instances if more than one
serves the webhook. Keep the 202 on Graph. Count verification failures the
way the GitHub receiver already counts them.

<a id="sec-06"></a>
## SEC-06. Release integrity is enforced at boot, and the deploy does not check first

**800-53:** SI-7 (software integrity), CM-3 (configuration change control).
**SSDF:** PW.8, PW.9.

`release_signing.enforce_key_pair` refuses to boot a production-shaped
process whose signing key does not match the pinned public key. On Cloud
Run a revision that fails its probe never receives traffic, so a mismatched
key does not start serving. That is the control, and it holds.

`deploy/cloudrun/deploy.sh` does not compare the key with the pinned public
key before `gcloud run deploy`. The workflow's verify step runs after a
deploy the probe already rejected, and it does not roll traffic back,
because traffic never moved. A bad key still creates a failed revision and
a failed job. The check that would keep the bad artifact out of the deploy
is the one that has not run yet.

**Direction.** Compare the pair in `deploy.sh` before `gcloud run deploy`.

<a id="sec-07"></a>
## SEC-07. Secure defaults depend on which entrypoint started the process

**800-53:** CM-6 (configuration settings), CM-7 (least functionality).
**SSDF:** PW.6 (configure software to have secure settings by default),
PW.5.

| Setting | Code default | Hosted deploy script |
|---|---|---|
| `GATEWAY_ENFORCE` | off (monitor) | `true` in `deploy/cloudrun/deploy.sh` |
| `CLIENT_ENFORCE` | off | not set by that script |
| `PALIVANE_ALLOW_SIGNUP` | on | left on, which is the hosted product |
| `PALIVANE_METRICS_TOKEN` | empty | see [SEC-04](#sec-04) |
| Database | SQLite if unset | Cloud SQL in the deploy script |

Confirmed secret and PII leaks still hard-block in monitor mode
(`gateway_enforce_secrets`, `force_block`). The fuzzy verdicts do not.
`CLIENT_ENFORCE` is what the hooks are told when the device has no local
flag. The hosted script turns the gateway on and leaves the hooks in
monitor unless the tenant changes Settings.

On SQLite the startup path logs that Postgres row-level security is not
active and that a weak `PALIVANE_SECRET_KEY` warns instead of refusing to
boot. The same function refuses a weak key when the database URL is not
SQLite. A self-host that stays on the SQLite default has application
`tenant_id` filters and no database backstop, and it will run with the
dev signing key.

`PALIVANE_ALLOW_SIGNUP` defaults to on so the hosted service can take a new
org. A single-org install that does not set it to false accepts a public
`POST /api/auth/signup` and that caller becomes admin of a new tenant on
the same database.

**Direction.** For a single-org install, refuse to boot with signup enabled
and a weak key, the way the non-SQLite path already refuses the key. Have
the install script set `CLIENT_ENFORCE` to the same value it sets for the
gateway, and state in the install output that SQLite has no row-level
security.

<a id="controls-that-hold"></a>
## Controls that hold

These were read against the same catalog. They are why the findings above
are gaps in mediation and in defaults, rather than a break in authentication
or in tenant isolation.

| Control | What the source does |
|---|---|
| IA-5, authenticator management | Passwords are argon2id. Legacy PBKDF2 is verified in constant time and rehashed on login. A missing user pays the same verify cost against a dummy hash. API keys and the SCIM token are stored as SHA-256 of a high-entropy secret and shown once. |
| IA-2, identification | Session tokens are HS256 only. `alg=none` and any other `alg` are rejected. Signatures use `hmac.compare_digest`. A token with a `typ` (MFA challenge, password reset, OIDC state, Graph `clientState`) is rejected by `user_for_session_payload`, so it is not a console session. `token_version` revokes existing sessions on password reset, logout-all, and SCIM deactivation. |
| AC-6, least privilege on SCIM | A SCIM token cannot rename an admin or deactivate the last admin. New SCIM users arrive as analysts with an unusable password. |
| AC-3, AC-4, tenant isolation | Requests bind `tenant_id` for Postgres RLS after authentication. Console and API-key queries filter on the caller's tenant. Login does not pick a tenant when the same email exists in more than one. A production-shaped process refuses to boot with an empty, short, or placeholder `PALIVANE_SECRET_KEY`. |
| SC-7, boundary protection | `netguard.safe_client` resolves a tenant-supplied URL once, rejects non-global addresses including IPv4-mapped IPv6, and pins the connection to that IP. An unresolvable host fails closed. |
| SC-12, SC-28, crypto at rest | Tenant credentials use Fernet over an HKDF-SHA256 key, with a per-tenant data key wrapped by the deployment key. Decrypt failure of a credential returns empty, which callers treat as not configured, rather than sending a marker string as an API key. |
| SC-23, webhook authenticity | Slack, GitHub, and Graph verify a secret or a signed token before acting. See [SEC-05](#sec-05) for the retry-memory residual. |
| SI-7, release signing at runtime | A production boot calls `enforce_key_pair` and refuses a mismatched key. See [SEC-06](#sec-06) for the deploy-script ordering. |
| SI-10, input bounds that do hold | Request bodies are capped. Pydantic bounds fields. SCIM filters accept only `userName eq "..."`. Static file and distribution downloads reject path traversal. OOXML reads are capped per zip member. |
| AU-2, admin audit | Security-relevant admin actions, including a justified proceed, are written to the tenant audit log. |

## SSDF practices this review did not execute

PW.8 asks that the software be shown to meet its security requirements.
This pass did that by reading the source. It did not re-run the backend
suite, and it did not exercise a deployment. PW.9 (archive and protect each
release) is the signing control in [SEC-06](#sec-06). RV (respond to
vulnerabilities) is out of scope of a single source pass.

## Related notes already in the tree

The processing comments next to the SEC-02 and SEC-03 sites describe the
same code paths in more detail. `docs/compliance/policies/08-secure-development.md`
records the July 2026 audits and the rule that a security fix lands with a
regression test. The findings here do not yet have those tests, because this
pass did not change behavior.
