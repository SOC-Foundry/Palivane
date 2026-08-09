"""Device-posture detector: capture-plane health and coverage gaps.

The proxy/hook planes only govern what they can see — and the field failure modes are
structural, not content-based: the egress proxy dead while the system proxy still points
at it (every AI tool hard-down AND governance off), another process squatting the proxy
port, the scan circuit breaker failing open (backend outage or a revoked capture key
silently suspends DLP), and traffic sources the network plane can't reach (WSL, Docker
containers don't inherit the system proxy or CA).

`palivane-posture` reports the raw device state as a small JSON document; THIS detector
turns it into findings, so the rules live server-side and reach the whole fleet the
moment the backend deploys. Each issue carries its own `check` key so the Policies
console can tune or disable them individually.
"""

from __future__ import annotations

import json

from .base import AnalysisInput, Category, Signal, Surface

_PALIVANE_LISTENERS = ("mitmdump", "mitmproxy", "palivane")


def _report(item: AnalysisInput) -> dict | None:
    if (item.metadata or {}).get("kind") != "device_posture":
        return None
    try:
        data = json.loads(item.content)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


class DevicePostureDetector:
    name = "device_posture"
    surfaces = {Surface.DEVICE}

    def analyze(self, item: AnalysisInput) -> list[Signal]:
        data = _report(item)
        if data is None:
            return []
        signals: list[Signal] = []
        proxy = data.get("proxy") or {}
        breaker = data.get("breaker") or {}
        gaps = data.get("gaps") or {}
        port = proxy.get("port", "?")

        # Proxy dead while the environment still routes through it: every AI tool on the
        # device is hard-down (users report "Claude is broken") and nothing is governed.
        if proxy.get("env_points_local") and not proxy.get("listening"):
            signals.append(Signal(
                category=Category.POSTURE_GAP, check="proxy_dead",
                title="Egress proxy down but still routed",
                detail=f"HTTP(S)_PROXY points at 127.0.0.1:{port} but nothing is "
                       "listening — AI tools on this device are failing and no traffic "
                       "is being inspected. Restart the Palivane proxy or clear the "
                       "proxy setting.",
                weight=0.8, confidence=0.95, detector=self.name))

        # Something else owns the proxy port: our proxy can't bind (a silent coverage
        # loss), or another agent (SASE client, dev tool) is fighting us for it.
        listener = str(proxy.get("listener") or "")
        if (proxy.get("listening") and listener
                and not any(p in listener.lower() for p in _PALIVANE_LISTENERS)):
            signals.append(Signal(
                category=Category.POSTURE_GAP, check="proxy_port_conflict",
                title="Proxy port owned by another process",
                detail=f"Port {port} is listening but the process is '{listener}', not "
                       "the Palivane proxy — a port collision (SASE client, dev tool) is "
                       "displacing the capture plane. Move Palivane to a free port or "
                       "resolve the conflict.",
                weight=0.6, confidence=0.8, detector=self.name,
                evidence=listener[:200]))

        # Circuit breaker states: the proxy is deliberately failing OPEN — availability
        # preserved, but DLP is suspended and nobody notices without this finding.
        if breaker.get("deauth_active"):
            signals.append(Signal(
                category=Category.POSTURE_GAP, check="capture_key_revoked",
                title="Capture key rejected — scans suspended",
                detail="The device's capture key was rejected (revoked or invalid); the "
                       "proxy is standing down for up to an hour and passing traffic "
                       "UNINSPECTED. Re-issue the key (`palivane connect`).",
                weight=0.8, confidence=0.9, detector=self.name))
        elif breaker.get("cooldown_active"):
            signals.append(Signal(
                category=Category.POSTURE_GAP, check="scan_fail_open",
                title="Scan backend unreachable — failing open",
                detail="Repeated scan timeouts/errors tripped the transient-failure "
                       "breaker; the proxy is passing AI traffic uninspected until the "
                       "cooldown expires. If many devices report this, the backend is "
                       "down or overloaded.",
                weight=0.5, confidence=0.9, detector=self.name))

        # Coverage gaps: traffic sources the network plane can't see. Informational —
        # low weight so a gap alone never blocks, but the console can inventory them.
        gap_srcs = [s for s, present in (("WSL", gaps.get("wsl")),
                                         ("Docker", gaps.get("docker_present")))
                    if present and not gaps.get("in_container")]
        if gap_srcs:
            signals.append(Signal(
                category=Category.POSTURE_GAP, check="coverage_gap",
                title=f"Ungoverned traffic paths present: {', '.join(gap_srcs)}",
                detail="This device runs environments that do not inherit the system "
                       "proxy or CA (containers/WSL); AI tools inside them bypass the "
                       "network capture plane. Hook-based coverage (Route C) still "
                       "applies where the filesystem is shared.",
                weight=0.15, confidence=0.6, detector=self.name))

        return signals
