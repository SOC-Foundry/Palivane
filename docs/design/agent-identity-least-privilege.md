# Design draft — Agent identity & least-privilege enforcement

> Status: **BUILT — Phases 0–3 shipped.** Runtime **authorization** for AI agents: a
> verifiable identity per agent and enforcement that an agent can only reach the tools,
> servers, commands, and data its role permits. Everything else Palivane does is *detection*
> (flag/block bad content); this adds *authorization* (deny an action because the caller
> isn't entitled to it).
>
> - **Phase 0** — Agent identity + `ag_` tokens + per-finding attribution. ✅
> - **Phase 1** — `AgentRole` (allow tools/servers) authorized on MCP calls, monitor/enforce. ✅
> - **Phase 2** — shell `allow_commands`, `data_scopes` (wired to detection), per-agent deny. ✅
> - **Phase 3** — OAuth/workload identity: agents authenticate with an OIDC JWT validated
>   against the tenant's JWKS, mapped to an agent by `sub`/`client_id`. ✅ (SPIFFE/mTLS: future.)
>
> The sections below are the original design; the shipped implementation follows it closely.

## 1. The gap

Kirin's AI-Agent capabilities include **OAuth-based agent authentication** and **map agent
roles to privileges (need-to-know boundaries)**. Palivane today:

- authenticates *tenants/clients* (JWT users, `ak_` API keys) but has **no per-agent identity**;
- inspects agent tool-use (`mcp_guard`) and blocks dangerous/poisoned/untrusted actions, but
  does **not** enforce a per-agent allow-set ("agent *billing-bot* may call the `invoices`
  MCP server and nothing else").

So a compromised or over-eager agent that issues a *legitimate-looking* call to a *sensitive*
tool isn't stopped — the call isn't malicious content, it's just unauthorized. That's the hole.

## 2. Goals / non-goals

**Goals**
- A verifiable **agent identity** distinct from the human/tenant, carried on every request.
- A **least-privilege policy**: role → allowed tools / MCP servers / data scopes / commands.
- **Enforcement at the choke points Palivane already owns** — the LLM gateway and the MCP path
  (proxy + `palivane-mcp` sensor + Cursor hook) — returning a clean *deny* with a reason.
- Reuse the existing **Policies** console and **per-user/group override** model.
- Full **audit** of every allow/deny (we already have findings + audit + SIEM).

**Non-goals (v1)**
- Becoming a general IdP. We *consume* identity (OIDC/OAuth client-credentials) rather than
  minting human identities.
- Network-layer microsegmentation. Enforcement is at the AI/MCP request layer.

## 3. Identity model

An **Agent** is a first-class principal within a tenant:

```
Agent
  id, tenant_id
  name              "billing-bot"
  kind              service | interactive   (autonomous vs. human-in-the-loop)
  role              FK -> AgentRole
  auth              how it proves identity (below)
  status            active | disabled
  created_at, last_seen
```

**How an agent proves identity** (in priority order, pick per deployment):
1. **OAuth 2.0 client-credentials** — the agent holds a client_id/secret (or a workload
   federation token) and presents a bearer JWT; Palivane validates it against the tenant's
   configured issuer/JWKS (we already have SSRF-guarded OIDC discovery in `oidc.py`).
2. **Palivane-minted agent token** — an `ag_…` credential (sibling to `ak_…`), hashed at rest,
   bound to one Agent. Simplest path for agents that can't do OAuth (local MCP, scripts).
3. **mTLS / SPIFFE** — future, for workload-identity shops.

The identity travels on the existing surfaces: `Authorization: Bearer …` (gateway) or an
`X-Palivane-Agent` token (MCP/CLI). The gateway/proxy resolves it to an `Agent` + `AgentRole`.

## 4. Policy model (least-privilege)

```
AgentRole
  id, tenant_id, name            "billing", "read-only-research"
  allow_tools     [glob]         MCP tool names the role may call        ("invoices.*")
  allow_servers   [glob]         MCP servers it may reach                ("mcp.acme.internal")
  allow_commands  [glob]         shell/tool commands permitted           ("gh issue *")
  data_scopes     [label]        need-to-know labels it may receive      (reuses oversharing)
  deny            [glob]         explicit denies (win over allows)
  default         allow | deny   posture for anything unlisted (default: deny)
```

Design choices:
- **Default-deny** for `allow_*` lists (least-privilege by construction); `default: allow` is
  an opt-out for gradual rollout (monitor first).
- **Reuse `data_scopes` with the oversharing engine** — a role's allowed labels are exactly the
  need-to-know check we already built, so "agent authorization" and "response oversharing"
  share one data-classification model.
- Roles are editable in the **Policies** console; **per-user/group overrides** already exist
  and extend naturally to per-agent overrides (same resolution precedence code).

## 5. Enforcement flow

At each choke point Palivane already intercepts:

```
request (gateway / MCP proxy / palivane-mcp / cursor-hook)
  → resolve Agent from credential           (401 if unknown/disabled)
  → derive intended action:
       tool call → tool name + server + args
       shell     → command
       response  → data labels present (oversharing engine)
  → authorize against AgentRole:
       explicit deny            → DENY
       matches an allow-set     → ALLOW
       unlisted + default=deny  → DENY
  → on DENY: record a finding (new category `agent_authz`), return a clean refusal
             with the reason + remediation ("role X may not call Y; request access")
  → on ALLOW: fall through to the existing content detectors (a permitted call is still
             scanned for secrets/poisoning/dangerous commands — authz and detection compose)
```

Modes mirror the rest of Palivane: **monitor** (log would-deny, allow through) → **enforce**
(actually deny). This lets an org watch what each agent *does* before locking the role down.

## 6. New pieces vs. reuse

| Concern | Approach |
|---|---|
| Agent identity token (`ag_…`) | new, mirror `ApiKey` (hashed, tenant-scoped) |
| OAuth validation | reuse `oidc.py` (issuer/JWKS, SSRF-guarded) |
| Agent + AgentRole models | new tables + migration |
| Role authorization logic | new `authz.py` (pure, unit-testable) |
| Enforcement points | extend gateway + `mcp_guard` path (already intercept) |
| Data-scope / need-to-know | **reuse** the oversharing engine + rules |
| Console (roles, agents, assign) | new **Agents** page; roles live under Policies |
| Overrides (per-agent) | **reuse** `resolve_disabled`/override precedence |
| Deny finding + audit + SIEM | reuse findings, audit log, SIEM forwarder |
| In-IDE deny reason | reuse the new remediation surfacing (cursor hook) |

## 7. Phasing

- **Phase 0 — identity only.** Introduce `Agent` + `ag_…` tokens; stamp every finding with the
  resolved agent (richer attribution in the Scan log / Discovery). No enforcement yet.
- **Phase 1 — MCP least-privilege (monitor).** `AgentRole` with `allow_tools`/`allow_servers`;
  authorize MCP calls, log would-deny. Console: Agents page + role editor.
- **Phase 2 — enforce + shell/data scopes.** Turn on deny; add `allow_commands` and
  `data_scopes` (wired to oversharing). Per-agent overrides.
- **Phase 3 — OAuth/workload identity.** Client-credentials + JWKS validation; SPIFFE/mTLS later.

## 8. Open questions / risks

- **Identity bootstrap** for local/desktop agents that can't hold an OAuth secret — likely the
  `ag_…` token provisioned by `palivane connect`, scoped to that machine+user.
- **Args-level authorization** (e.g. "may read `invoices/*` but not `payroll/*`") needs a small
  per-tool argument policy; start coarse (tool/server) and refine.
- **Latency**: authz is an in-memory policy check on data we already parse — negligible.
- **False-deny blast radius**: monitor-first + a clear deny reason + per-agent override is the
  mitigation; never fail-closed on a Palivane outage for identity resolution unless configured.

## 9. Why this fits Palivane

It doesn't bolt on a new product — it adds an **authorization layer on the choke points Palivane
already inspects**, reusing OIDC, the oversharing/need-to-know engine, the Policies console, the
override-resolution code, and the findings/audit/SIEM pipeline. The net new surface is small
(agent identity + a role authz check); the leverage is large (closes the last Kirin gap and
generalizes need-to-know from *responses* to *agent actions*).
