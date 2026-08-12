# MCP Enterprise-Managed Authorization (EMA) — Palivane's position

*Status: positioning decision, made; build-list items 1–3 shipped (Aug 2026 — EMA actor
identity, ID-JAG issuance-leg audit, role-precedence semantics). Item 4 (partnership) is
open. Palivane integrates as the enforcement + audit layer for EMA-governed fleets; it
does not compete with the IdP for connection-level authority. This doc records the
reasoning and the (small) code changes the posture implies.*

## What EMA actually does

The MCP 2026-07-28 release made EMA a stable extension
(`io.modelcontextprotocol/enterprise-managed-authorization`, from SEP-990, built on the
IETF identity-chaining drafts; Okta ships it as "Cross App Access"). The flow:

1. User signs into the MCP client via enterprise SSO; the client holds an identity
   assertion (OIDC ID token or SAML).
2. The client exchanges it at the IdP (RFC 8693 token exchange) for an **ID-JAG** — a
   short-lived (~5 min) JWT authorization grant, one per target MCP server. **This is
   where admin policy runs**: the IdP decides which user + client may reach which server,
   with what max scopes. Unauthorized servers aren't blocked — they're invisible.
3. The client redeems the ID-JAG at the MCP server's authorization server (RFC 7523
   JWT-bearer) for a normal, audience-restricted MCP access token. No per-server consent
   screens ("zero-touch OAuth").
4. The client calls the MCP server with that Bearer token.

Adoption as of Aug 2026: Okta is the only shipping IdP; Anthropic's clients (Claude,
Claude Code, Cowork) and VS Code support it; Asana, Atlassian, Canva, Figma, Granola,
Linear, Supabase on the server side.

## The gap the spec states in its own text

> "The visibility the IdP has between the MCP Client and MCP Server is limited to the
> process of issuing the access token, but does not extend to the actual MCP traffic."

EMA governs **who may connect**. It has no view of — and defines no hooks for — what the
agent then *does*: which tools it calls, with what arguments, returning what data. There
are no PEP/audit extension points in the spec at all. Once the token is issued, every
`tools/call` is ungoverned unless something sits inline. That something is Palivane.

## Division of labor

**Delegate to EMA** (where the tenant has an EMA-capable IdP):

- Connection-level grants — which user/client may reach which MCP server. Consume the
  IdP's decision instead of maintaining a competing approved-server registry for humans.
- Human identity issuance. Accept the EMA-minted MCP access token as the principal:
  validate it where inspectable, take `sub`/`email` as the actor. This is a small
  extension of the existing JWKS path in `oidc.py` (add `typ`/audience handling), not a
  new subsystem — and it upgrades attribution from "whoever holds the ak_ key" to an
  IdP-governed identity.
- Human-credential revocation (centralized at the IdP).

**Keep — EMA structurally cannot do these:**

- **Per-call authorization.** The whole `authz.py` role model — tool/server globs,
  shell-command allowlists, data scopes evaluated against request content. EMA's scope
  decision happens once, at issuance, at OAuth-scope granularity; Palivane re-decides on
  every call with the arguments in hand.
- **Content inspection.** Detection/redaction on prompts and tool-call bodies. The IdP
  never sees traffic; this is the product.
- **Session audit.** The per-call event trail with kill-chain correlation. EMA produces
  issuance logs inside the IdP console; nothing standardized logs the calls themselves.
  Bonus surface: ID-JAGs are per-server and ~5-minute-lived, so issuance is chatty — an
  audit/analytics view across clients that no IdP console presents well.
- **Workload/agent identity.** EMA's flow starts from a *user* SSO assertion; it says
  nothing about headless agents. `ag_` tokens, minted short-lived agent tokens, and
  workload-OIDC subject mapping remain Palivane's layer for CI/deploy/autonomous agents.
  *Watch item:* if the IETF identity-chaining drafts extend to workload principals, IdPs
  come for this segment next — revisit the moat then.
- **Coverage of non-EMA reality.** One IdP ships EMA today; servers need code changes;
  fallback flows are mandatory. Fleets will be mixed for years, and Palivane is the layer
  that behaves identically across EMA and non-EMA servers.

**The one-sentence version:** the IdP is the policy decision point for *connections*;
Palivane is the decision + enforcement point for *actions*, and the audit plane for both.

## Honest constraints

- **Third-party access tokens may be opaque.** The ID-JAG format is normative; the final
  MCP access token is whatever the server's AS issues. For SaaS MCP servers Palivane can
  gate and log the call (it's inline) but may not be able to independently validate the
  token. Enforcement rests on placement, not cryptography — say so in sales conversations.
- **Inline placement is the price of admission.** For third-party servers this is the
  egress-proxy plane (TLS inspection + MDM root cert), with its known deployment friction.
- **There is no API to "integrate with".** No PEP registration, no metadata field, no
  error signal for "enterprise auth required". Integration = sitting inline + validating
  EMA artifacts + partnership motion (Okta, MCP-AS vendors), not a code handshake.

## Competitive lens

- **Aembit** ships an "MCP Identity Gateway" — the closest rival to the PEP position, from
  a workload-IAM heritage (credential brokering). Differentiation: Palivane inspects
  content and audits sessions; Aembit brokers identity.
- **Cisco/Astrix** is inventory/posture over non-human identities — governs the credential
  sprawl EMA doesn't reach; not an inline enforcer.
- **Noma** competes on agent-governance breadth (discovery, posture, runtime guardrails),
  not on standards-native EMA positioning.
- **Teleport** has the same PEP-shaped instinct anchored in infra access (short-lived
  certs); lane-adjacent rather than head-on.

## Role precedence under EMA

Where a tenant's IdP governs MCP server access via EMA, the IdP is the **primary gate for
connections**: it decides at issuance which user/client may reach which server, and servers
it denies never produce traffic. A Palivane role's `allow_servers` is then a **tightening
overlay** — it can further narrow (deny) what the IdP allowed, but can never widen it,
because nothing in Palivane mints credentials or opens connections. That deny-only property
holds by construction in `backend/app/authz.py` (an allow verdict there grants nothing the
IdP didn't already grant) and must be preserved. For non-EMA tenants and non-EMA servers —
fleets stay mixed for years — `allow_servers` remains the primary connection-policy gate,
with identical behavior. Per-*action* authorization (tool globs, shell-command allowlists,
data scopes, decided per call against request content) is Palivane's in both worlds; EMA
has no view of it.

## What to build (small, in order)

1. **Accept EMA-minted tokens as actor identity** — **shipped.** `oidc.inspect_ema_token`
   recognizes the ID-JAG shape (`typ: oauth-id-jag+jwt`) and JWT access tokens
   (audience/resource claims), maps `sub`/`email` to the session actor on the MCP ingest
   path (`MCPIngest.authorization`, forwarded by the egress-proxy addon from the request's
   Bearer header). Honest by design: `verified` is set only when the signature checks out
   against the tenant's own configured IdP JWKS; third-party AS tokens parse unverified or
   degrade to opaque-token attribution — never an error, never a claimed validation.
2. **Audit the issuance leg** — **shipped.** The addon detects the two legs where the
   token endpoints route through the proxy (`PALIVANE_PROXY_INTERCEPT_EXTRA`): RFC 8693
   token exchange requesting `…:token-type:id-jag` (client → IdP) and RFC 7523 jwt-bearer
   redemption whose assertion carries the ID-JAG `typ` (client → MCP AS). Audience/
   resource/scope are recorded as always-persisted `auth/id-jag.*` session events through
   the existing MCP ingest pipeline; the leg is audit-only, never blocked — the IdP is the
   connection PDP.
3. **Roles reference EMA reality** — **shipped.** Precedence documented above and in
   `authz.py` / the `AgentRole` model; the tightening-overlay semantics required no
   behavior change (the role model was already deny-only) and non-EMA tenants are
   unaffected. The EMA `auth/*` audit events are exempt from the MCP server allowlist
   check — their host is a token endpoint, not an MCP server.
4. **Partnership motion** (not code, still open): Okta XAA validation, and presence in
   the MCP AS vendors' compatibility stories.
