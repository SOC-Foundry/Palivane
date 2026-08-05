"""MCP server reputation / provenance — beyond the allowlist and TOFU pinning.

The allowlist answers "is this server approved?"; the palivane-mcp binary pin answers "did
this server change since first run?". Neither catches the **postmark-mcp** shape: a
*trusted, named* package whose ownership is taken over and a malicious version published —
the config looks unchanged and the pin is first-seen. This adds provenance + freshness
signals at config-scan time:

- **known-bad** (offline, `MCP_SERVER_DENYLIST`) — a server name or package the org (or a
  future shared feed) marks malicious;
- **non-registry source** (offline) — launched from a git ref / URL / tarball / local path
  rather than a pinned registry package: a mutable, unreviewable supply chain;
- **freshly (re)published** (opt-in registry lookup, `MCP_REPUTATION_ENABLED`) — a
  brand-new package, or an old package whose latest version shipped in the last few days
  (the trusted-then-trojaned freshness tell). Network, best-effort, always fail-open.

Pure functions + one gated network call, so it's unit-testable offline.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .config import settings

_URL_MARKERS = ("://", "git+", "github:", "gitlab:", "bitbucket:", "http:", "https:", ".git",
                ".tgz", ".tar.gz")


def _denylist() -> set[str]:
    return {x.strip().lower() for x in (settings.mcp_server_denylist or "").split(",") if x.strip()}


def non_registry_source(command: str, args: list) -> str | None:
    """If a package runner (npx/uvx/…) is fetching from a URL/git/tarball/path instead of a
    named registry package, return that token. `extract_mcp_packages` returns [] for these,
    which is why an unresolved runner launch is the tell."""
    from .detectors.dep_guard import _NPM_RUNNERS, _PY_RUNNERS, _RUNNER_FLAGS
    cmd = (command or "").strip().lower().split("/")[-1]
    if cmd not in _NPM_RUNNERS and cmd not in _PY_RUNNERS:
        return None
    for tok in (str(a).strip() for a in (args or []) if str(a).strip()):
        low = tok.lower()
        if low in _RUNNER_FLAGS or tok.startswith("-"):
            continue
        if any(m in low for m in _URL_MARKERS):
            return tok
        return None   # first real token is a normal package spec — registry-sourced
    return None


def registry_freshness(eco: str, name: str, timeout: float = 4.0) -> dict | None:
    """Opt-in npm-registry lookup: {age_days, days_since_publish, republished}. `republished`
    = an established package (created long ago) whose latest version shipped within the
    freshness window — the postmark-mcp takeover shape. None on any error (fail open).
    npm only for now; PyPI freshness is a future addition."""
    if eco != "npm" or not name:
        return None
    try:
        url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}"
        req = urllib.request.Request(url, headers={"User-Agent": "palivane-mcp-reputation/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            doc = json.loads(r.read())
        times = doc.get("time") or {}
        created = times.get("created")
        latest = (doc.get("dist-tags") or {}).get("latest")
        modified = times.get(latest) or times.get("modified")
        now = datetime.now(timezone.utc)

        def _age(ts):
            if not ts:
                return None
            try:
                return (now - datetime.fromisoformat(ts.replace("Z", "+00:00"))).days
            except ValueError:
                return None

        age = _age(created)
        since = _age(modified)
        fresh = settings.mcp_reputation_fresh_days
        return {"age_days": age, "days_since_publish": since,
                "republished": bool(age is not None and since is not None
                                    and age > 90 and since <= fresh)}
    except Exception:
        return None


def assess(server_name: str, command: str, args: list,
           packages: list[tuple[str, str, str]], check_registry: bool | None = None) -> list[dict]:
    """Reputation signals for one MCP server. `packages` is extract_mcp_packages() output
    [(eco, name, version), …]. Returns a list of signal dicts (category mcp_reputation)."""
    signals: list[dict] = []
    deny = _denylist()
    pkg_names = {p[1].lower() for p in packages if p[1]}

    # 1. Known-bad denylist (server name or any resolved package).
    hit = ({server_name.lower()} | pkg_names) & deny if deny else set()
    if hit:
        signals.append({
            "category": "mcp_reputation", "check": "mcp_reputation",
            "title": "Known-bad MCP server",
            "detail": f"'{', '.join(sorted(hit))}' is on the org's MCP denylist — do not connect this server.",
            "weight": 0.95, "confidence": 0.98, "detector": "mcp_reputation",
            "evidence": ", ".join(sorted(hit))})

    # 2. Non-registry (mutable) source.
    src = non_registry_source(command, args)
    if src:
        signals.append({
            "category": "mcp_reputation", "check": "mcp_reputation",
            "title": "MCP server from a non-registry source",
            "detail": ("This server is fetched-and-run from a URL/git/tarball/path, not a "
                       "pinned registry package — a mutable, unreviewable supply chain."),
            "weight": 0.6, "confidence": 0.8, "detector": "mcp_reputation",
            "evidence": src[:120]})

    # 3. Freshly (re)published — opt-in registry lookup.
    use_registry = settings.mcp_reputation_enabled if check_registry is None else check_registry
    if use_registry:
        for eco, name, _ver in packages:
            info = registry_freshness(eco, name)
            if not info:
                continue
            if info["republished"]:
                signals.append({
                    "category": "mcp_reputation", "check": "mcp_reputation",
                    "title": "MCP server package recently republished",
                    "detail": (f"{name}: an established package (~{info['age_days']}d old) shipped a "
                               f"new version {info['days_since_publish']}d ago — the trusted-then-"
                               "trojaned takeover pattern. Re-vet before connecting."),
                    "weight": 0.75, "confidence": 0.7, "detector": "mcp_reputation",
                    "evidence": f"{name} republished {info['days_since_publish']}d ago"})
            elif info["age_days"] is not None and info["age_days"] <= settings.mcp_reputation_fresh_days:
                signals.append({
                    "category": "mcp_reputation", "check": "mcp_reputation",
                    "title": "Brand-new MCP server package",
                    "detail": (f"{name} was first published only {info['age_days']}d ago — little "
                               "track record; treat an unproven MCP server with caution."),
                    "weight": 0.5, "confidence": 0.65, "detector": "mcp_reputation",
                    "evidence": f"{name} published {info['age_days']}d ago"})
    return signals
