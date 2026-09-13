# Deploying alongside your existing proxy or VPN

If your fleet already runs a VPN (Tailscale, WireGuard, Cloudflare WARP) or a secure web
gateway (Zscaler, Netskope, Palo Alto Prisma, Cisco Umbrella, or any corporate SWG/SASE),
Palivane fits in without ripping any of it out. This page is the one decision you make
before rollout, split by what you already run.

## The short version

Only **one** Palivane plane touches the network path: the **egress proxy**, which covers
desktop AI apps (Claude/ChatGPT desktop) and anything else that won't take a base-URL
override. Everything else (the browser extension, the CLI coding-tool hooks, CI scanning,
the gateway, and at-rest connectors) needs **no system proxy and no CA**, so your VPN or
SWG never interacts with them at all.

So the only question is how the egress proxy coexists with what you have. If you don't
deploy the egress proxy, there's nothing to reconcile.

**The one question that decides everything:** does your client **inspect TLS** (decrypt
HTTPS with its own root CA), or does it only **route packets**? Route-only is free, with no
interaction at all. TLS inspection needs one config line, because otherwise our connection
*to* the AI host is itself intercepted and fails certificate verification. Vendor names are
a poor guide here: the same product does both depending on how you licensed it. Check
whether you pushed a root CA to your fleet. If you did, you're inspecting.

## If you run Cloudflare WARP

**Depends on your mode**, and this is the case people get wrong most often. WARP is
WireGuard-based, so it reads like "just a VPN", but Zero Trust turns it into an inspecting
gateway.

| WARP mode | What to do |
| --- | --- |
| Gateway with DoH (DNS filtering only) | **Nothing.** No TLS inspection, no proxy. |
| WARP tunnel, no Gateway HTTP policies | **Nothing.** L3 tunnel; behaves exactly like Tailscale below. |
| **Gateway with WARP + HTTP policies / TLS decryption on** | **One config line (see below).** |

In that third mode WARP decrypts HTTPS and re-signs it with the Cloudflare Zero Trust root.
Our proxy's *upstream* connection to `api.anthropic.com` then presents a Cloudflare-signed
certificate that the public trust store doesn't recognize, the handshake fails, and **every
AI tool on the device breaks with a certificate error**. Palivane detects this exact state
and logs the vendor plus the fix rather than an opaque TLS error, but it can't repair it for
you. Pick one:

**Preferred: exempt the AI hosts from WARP's inspection.** In Zero Trust -> Gateway -> HTTP
policies, add a **Do Not Inspect** rule for the hosts in Palivane's intercept list
(`api.anthropic.com`, `claude.ai`, `chatgpt.com`, `api.openai.com`, ...; the full list is
`AI_HOST_SUFFIXES` in `proxy/palivane_addon.py`). Palivane owns inspection for AI traffic,
Cloudflare owns everything else, so there's no double decryption and clean forensics.

**Or: trust the Cloudflare root on our upstream leg.** Download your account's Zero Trust
root certificate and:

```
PALIVANE_UPSTREAM_CA=/path/to/cloudflare-zero-trust-root.pem
```

Note there is **no `PALIVANE_UPSTREAM_PROXY` here**: WARP intercepts at layer 3 and is not
an HTTP proxy, so there's nothing to chain to. The CA setting stands alone deliberately, and
the installer merges your root *into* the system public roots rather than replacing them, so
non-inspected hosts keep working.

Everything else about WARP is a non-issue: it sets no system HTTP proxy, so unlike Zscaler
Client Connector it never fights Palivane for that setting; loopback isn't routed through
the tunnel, so the local proxy is reachable; and WARP's own control plane is never in
Palivane's intercept list, so it's never decrypted.

The same applies to any client that inspects TLS without offering a proxy to chain to,
such as **Netskope and Prisma in tunnel mode, Cisco Umbrella's roaming client**: use
`PALIVANE_UPSTREAM_CA` on its own, not the Option A chaining below.

## If you run Tailscale or a WireGuard VPN

**Nothing to do: they coexist.** Tailscale and WireGuard route IP packets at the network
layer; they are not HTTP proxies and they don't inspect TLS. Palivane's egress proxy sits
above them as an explicit HTTP(S) proxy, and captured traffic still egresses through your
mesh (including an exit node, if you use one). Different layers, no collision, no CA
conflict.

The only thing to know: if you use Tailscale purely to *route* to a corporate gateway,
then it's that gateway, not Tailscale, that Palivane coexists with. See the next section.

## If you run Zscaler, Netskope, or a corporate SWG/SASE

These **do** overlap with Palivane's proxy: both want to be the system proxy and both do
TLS inspection with their own CA. That's expected, and there are two supported ways to run
alongside them. Pick one per fleet (or per device group).

### Option A: chain Palivane in front (recommended when devices can't reach the internet directly)

Run Palivane's egress proxy in **upstream mode** so it sits in front of your gateway:

```
PALIVANE_UPSTREAM_PROXY=http://corp-proxy:port
# if the gateway inspects TLS, point Palivane at its CA so the upstream leg is trusted
# (merged with the system public roots, so normal trust is preserved):
PALIVANE_UPSTREAM_CA=/path/to/corp-proxy-ca.pem
# if the gateway requires proxy auth:
PALIVANE_UPSTREAM_AUTH=user:pass
```

Traffic then flows **app → Palivane (inspects AI content) → your gateway (corporate egress
control) → internet**. Enforcement, streaming, and agentic/MCP blocking all hold through
the chain; it's verified end to end.

One tuning note: **exempt the AI hosts from your gateway's own TLS inspection**
(`api.anthropic.com`, `claude.ai`, `chatgpt.com`, and the rest of Palivane's intercept
list). Double-decrypting the same traffic works but doubles latency and muddies incident
forensics: let Palivane own inspection for those hosts and your gateway own everything
else.

### Option B: skip the system proxy entirely (recommended where a SASE client fights back)

Zscaler Client Connector and similar agents re-assert the system proxy periodically, and
IT-pushed **PAC files** can silently override the proxy setting Palivane installs. Rather
than fight for a machine-wide setting you won't reliably win, deploy Palivane in
**CLI-shim mode**: per-tool `HTTPS_PROXY` environment variables, no system proxy at all.
You cover the AI coding tools and SDKs cleanly and leave the SASE client's system-proxy
ownership untouched. (This mode doesn't cover desktop GUI apps; if you need those under a
combative SASE client, use Option A instead.)

## What Palivane tells you if it goes wrong

You don't have to get this perfect on the first try. The coexistence failures are caught
continuously, not discovered months later:

- **`proxy_port_conflict`**: another process (a dev server, another agent) owns Palivane's
  port. Configurable via `PALIVANE_PROXY_PORT`; probe before rollout on developer machines.
- **`proxy_dead`**: the system proxy points at Palivane but nothing is listening. This is
  the dangerous state: every AI tool on the device fails *and* nothing is inspected. Fires
  the moment it happens.
- **Sensor gone dark**: if a SASE client quietly reclaims the proxy and Palivane stops
  seeing traffic, the fleet health alert pages you rather than leaving you silently blind.
- **Upstream TLS inspected by someone else**: the proxy logs the *vendor* it detected
  (Cloudflare, Zscaler, Netskope, ...) and the two ways to fix it, instead of a bare
  "certificate verify failed" that looks like Palivane broke the network.

The first three surface in **Fleet** and can alert to your webhook; the checks are tunable
in **Policies → Checks**. The fourth is local: it lands in the proxy's own log on the
device, because at that point the device can't reach us to report it.

## A note on PAC files and effective proxy

Setting a system proxy and *having it take effect* are different things when a PAC file is
in play. On a pilot device, confirm the **effective** proxy is Palivane, not just the
configured setting, before you roll to the fleet. A PAC file that routes AI hosts around
Palivane is invisible until you check.

## Rule of thumb

| You run | Do this |
| --- | --- |
| Tailscale / WireGuard | Nothing: deploy Palivane normally |
| Cloudflare WARP, DNS-only or tunnel without HTTP policies | Nothing: deploy Palivane normally |
| Cloudflare WARP with Gateway TLS inspection | Do-Not-Inspect rule for the AI hosts, **or** `PALIVANE_UPSTREAM_CA` alone |
| Any L3 TLS-inspecting client (Netskope/Prisma tunnel, Umbrella roaming) | `PALIVANE_UPSTREAM_CA` alone (no upstream proxy to chain to) |
| Zscaler / Netskope / SWG, devices can reach internet via it | Option A: chain upstream |
| SASE client that re-asserts the system proxy | Option B: CLI-shim, skip system proxy |
| No egress proxy deployed (browser + CLI + gateway only) | Nothing: no network-path overlap exists |

For the full pre-rollout list, see the [corporate deployment checklist](corporate-deployment-checklist.md).
