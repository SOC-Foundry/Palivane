# Deploying alongside your existing proxy or VPN

If your fleet already runs a VPN (Tailscale, WireGuard) or a secure web gateway
(Zscaler, Netskope, Palo Alto Prisma, Cisco Umbrella, or any corporate SWG/SASE),
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
# if the gateway inspects TLS, point Palivane at its CA so the upstream leg is trusted:
ssl_verify_upstream_trusted_ca = /path/to/corp-proxy-ca.pem
# if the gateway requires proxy auth:
--upstream-auth user:pass
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

All three surface in **Fleet** and can alert to your webhook; the checks are tunable in
**Policies → Checks**.

## A note on PAC files and effective proxy

Setting a system proxy and *having it take effect* are different things when a PAC file is
in play. On a pilot device, confirm the **effective** proxy is Palivane, not just the
configured setting, before you roll to the fleet. A PAC file that routes AI hosts around
Palivane is invisible until you check.

## Rule of thumb

| You run | Do this |
| --- | --- |
| Tailscale / WireGuard | Nothing: deploy Palivane normally |
| Zscaler / Netskope / SWG, devices can reach internet via it | Option A: chain upstream |
| SASE client that re-asserts the system proxy | Option B: CLI-shim, skip system proxy |
| No egress proxy deployed (browser + CLI + gateway only) | Nothing: no network-path overlap exists |

For the full pre-rollout list, see the [corporate deployment checklist](corporate-deployment-checklist.md).
