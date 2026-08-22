# Corporate deployment checklist

Collisions and gaps to check before rolling Palivane out to a fleet, corporate or small.
Every failure mode here is one we've either hit in the field or verified in testing; the
device-posture checks (below) catch most of them continuously, but check them **once,
deliberately, before rollout** so they never page you at all.

Where a check is continuous, the `check` key it fires under is noted, tune or disable
each in **Policies → Checks**.

---

## 1. Network path & TLS

- [ ] **Chained corporate proxy (Zscaler / Netskope / SWG).** If devices can't reach the
  internet directly, run the egress proxy in upstream mode
  (`PALIVANE_UPSTREAM_PROXY=http://corp:port`, plus `--upstream-auth` if required) and
  point `ssl_verify_upstream_trusted_ca` at the corp proxy's CA. Verified working
  end-to-end (enforce, streaming, and MCP blocking all hold through a chain).
- [ ] **The corp proxy must not also intercept the AI hosts.** Double-decrypt works but
  doubles latency and muddies incident forensics, exempt `api.anthropic.com`, `claude.ai`
  (and the rest of the intercept list) from the SWG's TLS inspection.
- [ ] **PAC files.** IT-pushed PAC files can silently override the system proxy Palivane
  sets. Confirm the *effective* proxy on a pilot device is Palivane, not just the setting.
- [ ] **QUIC/HTTP-3, only if you deviate.** With the explicit-proxy model browsers don't
  use QUIC, so nothing leaks. If you ever deploy via transparent redirection instead,
  browser AI traffic will escape over HTTP/3, block UDP/443 for the AI hosts or stay
  explicit.

## 2. Proxy port & agent collisions

- [ ] **Port 8081 is a common squat** (dev servers, other agents). It's configurable,
  probe before standing the proxy up, especially on developer machines.
  *Continuous:* `proxy_port_conflict` fires when a non-Palivane process owns the port.
- [ ] **A dead proxy that's still routed is a hard outage**: every AI tool on the device
  fails ("Claude is broken" tickets) *and* nothing is governed.
  *Continuous:* `proxy_dead` fires on exactly this state.
- [ ] **SASE clients fight for the system proxy.** Zscaler Client Connector and friends
  re-assert the system proxy periodically. Where one runs, prefer the **CLI-shim mode**
  (per-tool `HTTPS_PROXY`, no system proxy) over `--desktop`.
- [ ] **Shared workstations / VDI / Citrix:** the proxy is per-user; a second user's
  instance can't bind the same port. Use per-user ports (`PALIVANE_PROXY_PORT`) or a
  shared host-level proxy.

## 3. Trust stores are per-tool, not per-machine

- [ ] Node-based CLIs (Claude Code, many agents) don't read the system trust store, the
  shims set `NODE_EXTRA_CA_CERTS` before launch, which covers the known tools. Anything
  **new** that bundles its own CA store (Java IDEs, `certifi`-pinned Python tools, Deno)
  will show TLS errors against intercepted hosts until you inject the CA its way.
- [ ] **Version floor:** the proxy addon needs **mitmproxy ≥ 8 on Python ≥ 3.9** (async
  hooks). The launchers install a current self-contained binary; only manual installs and
  `PALIVANE_MITM_VERSION` pins can go below it, don't.

## 4. Plane overlap (double capture)

- [ ] Extension + proxy both see a browser claude.ai prompt; gateway (`--route-gateway`)
  + proxy both see Claude Code traffic. Overlap is by design (defense in depth), but in
  enforce mode users get two different block UXs and the console counts twice. Pick the
  primary plane per surface, or accept the duplication knowingly.
- [ ] **Subscription-first is the default posture**: developers stay signed in on their
  Pro/Max/Enterprise Claude seats; hooks + proxy/extension govern without touching
  sign-in or billing, and no Anthropic API account is needed for capture. The gateway
  route is for orgs that deliberately want API-key billing. For the LLM judge, the
  enterprise options are the org's cloud contract (`JUDGE_PROVIDER=vertex|bedrock`) or
  BYOK, developer seats are never used for judging (ToS).

## 5. Fail-open is a policy statement

- [ ] The proxy **fails open** on scan-backend failure: repeated timeouts trip a 5-minute
  cooldown; a revoked capture key trips a 1-hour stand-down. Availability is preserved,
  DLP is silently suspended. Security teams must know this is the tradeoff.
  *Continuous:* `scan_fail_open` and `capture_key_revoked`, alert when a meaningful
  fraction of the fleet reports either (many at once = backend outage, not device issues).

## 6. Coverage gaps the network plane can't see

- [ ] **Containers and WSL** don't inherit the system proxy or CA, AI tools inside them
  bypass the network plane entirely (not broken, just ungoverned). The filesystem hooks
  (Route C) still apply where the home directory is shared.
  *Continuous:* `coverage_gap` inventories devices with Docker/WSL present (informational).
- [ ] **Host-list drift:** an AI tool that moves its API domain silently drops out of
  interception until `AI_HOST_SUFFIXES` catches up. Watch release notes; add interim
  domains via `PALIVANE_PROXY_INTERCEPT_EXTRA`.

## 7. Backend capacity (especially small environments)

- [ ] Scans are concurrent per device (bounded ~32); size the backend for
  `fleet × burst`, not one-at-a-time. A backend pushed past the scan timeout trips
  fail-open fleet-wide, which looks "fine" until you check findings volume.
- [ ] **Postgres, not SQLite**, for anything beyond a single-machine demo (concurrent
  ingest writes will lock SQLite).
- [ ] **Internal CA on the backend host:** `scan()` verifies TLS. If Palivane is served
  under a private CA, that CA must be in the proxy host's trust store, otherwise every
  scan fails and the fleet runs permanently fail-open while looking healthy.
- [ ] Self-update pulls changed files fleet-wide after each release; fine at most scales,
  but budget for the burst on a small backend.

## 8. Supply-chain integrity

- [ ] `/cli/manifest.sig` must return **200** (release signing provisioned). When it does,
  freshly generated installers are fail-closed: signature verified before install, every
  file hash-checked during staging, and a mismatch aborts with **zero** files installed.
- [ ] Verify independently on any machine:
  `openssl dgst -sha256 -verify pub.pem -signature sig.der digest`
  (see [Verifying what you install](/docs/verifying-downloads)).

## 9. Privacy & legal (frequently the real blocker)

- [ ] TLS-inspecting AI prompts captures potentially personal content on managed devices.
  Document for legal review **before** rollout: interception scope (the AI host list only,
  not `PALIVANE_PROXY_INTERCEPT_ALL`), what is stored (verdicts and findings vs. raw
  prompts), retention, and who can read findings. EU / works-council environments
  typically require sign-off on exactly these four.
- [ ] BYOD / personal accounts on managed devices: decide and disclose whether personal
  claude.ai/ChatGPT sessions are in scope.

## 10. Pre-rollout verification

- [ ] Run the [pilot smoke test](/docs/pilot) on one device per platform.
- [ ] `palivane-posture --dry-run` on a pilot device, confirm the device-posture report
  reflects reality (proxy listening, breaker clear, expected gaps only).
- [ ] Start in **monitor mode**, watch findings for a week, tune Policies, then flip
  enforce, with the fail-open semantics from §5 understood and alerting in place.
