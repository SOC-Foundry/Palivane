#!/usr/bin/env python3
"""Build the scored MCP-server reputation feed (backend/data/mcp_reputation.json) from
public metadata, so app/mcp_feed.py has a real dataset to consume.

Sources, in order:
  1. the official MCP registry (registry.modelcontextprotocol.io, latest version of every
     server, paginated) — the population, the publisher namespace and the package refs;
  2. npm and PyPI metadata for the packages those servers reference — age, last release,
     deprecation/yank, source repository;
  3. OSV.dev — `MAL-` (malicious-package) advisories on the package name, and any
     advisory affecting the latest release;
  4. optionally (--github), unauthenticated GitHub repo metadata — archived repos. Off by
     default: 60 requests/hour does not cover the registry, so it only spot-checks.
Plus two in-repo inputs: the curated starter set (data/mcp-reputation-starter.json, human-
reviewed, wins over computed rows) and Palivane's built-in dependency denylist.

Scoring (SCORING_VERSION) is deliberately conservative and every row's `reason` lists the
signals that produced it:
  - malicious — ONLY hard evidence: an OSV MAL- advisory affecting the latest release, or
                a denylist/curated incident. MAL- only on earlier versions (a hijacked,
                since-cleaned package) is caution with the advisory named.
  - trusted   — every positive check passes: active registry listing; a verified publisher
                (a DNS-verified reverse-domain namespace, or io.github.<owner> whose source
                repo belongs to <owner>); each package exists, has a source repo, is >= 30
                days old, released within a year, not deprecated/yanked, no advisories, not
                a near-miss of a well-known name. A remote-only server has no package to
                inspect, so it is never trusted (at best unverified 65, on its own domain).
  - caution   — a concrete risk signal: deprecated/yanked/delisted, missing from its
                registry, first published under 30 days ago, no release in a year, known
                advisories, earlier malicious versions, an archived repo, or a near-miss of
                a well-known name. This is the tier that produces a finding.
  - unverified — no risk signal, but not enough evidence for trusted either: remote-only
                (nothing to inspect), a package type this feed doesn't check, no source
                repo, a publisher that doesn't own its repo. Absence of evidence, not
                evidence of risk, so the app reports nothing for it. Never trusted.

    python tools/mcp_feed_build.py                 # from backend/; writes data/mcp_reputation.json
    python tools/mcp_feed_build.py --github        # also spot-check archived repos

Network failures fail the run rather than shrinking the dataset: lookup errors above a small
ratio abort, and so does a registry count well below the previous file's (--min-ratio).
Stdlib only, so CI can run it without installing the backend's requirements.
"""
from __future__ import annotations

import argparse
import ast
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

SCORING_VERSION = "2"
BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = os.path.join(BACKEND, "data", "mcp_reputation.json")
DEFAULT_CURATED = os.path.join(BACKEND, "data", "mcp-reputation-starter.json")
DEP_GUARD = os.path.join(BACKEND, "app", "detectors", "dep_guard.py")

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"
NPM_URL = "https://registry.npmjs.org/"
PYPI_URL = "https://pypi.org/pypi/{}/json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
GITHUB_API = "https://api.github.com/repos/"
UA = "palivane-mcp-feed-build/1 (+https://palivane.io)"

NEW_DAYS = 30          # first published less than this long ago = little track record
STALE_DAYS = 365       # no release in this long = not "active"
MAX_ERROR_RATIO = 0.02  # package-lookup errors (not 404s) above this abort the run
_TIER_RANK = {"malicious": 0, "caution": 1, "unverified": 2, "trusted": 3}
_ECO = {"npm": "npm", "pypi": "PyPI"}
_CODE_HOSTS = ("github.com/", "gitlab.com/", "bitbucket.org/", "codeberg.org/", "sr.ht/")


class SourceError(RuntimeError):
    """A source failed in a way that would silently shrink or skew the dataset."""


# --- HTTP ------------------------------------------------------------------------------

class Http:
    """Tiny JSON client: retries 429/5xx/network errors with backoff, honours Retry-After.
    `get_json` returns None on 404 (absent is an answer, not an error)."""

    def __init__(self, timeout: float = 30.0, retries: int = 4, backoff: float = 2.0):
        self.timeout, self.retries, self.backoff = timeout, retries, backoff

    def _open(self, req):
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return r.status, dict(r.headers), r.read()
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return 404, dict(e.headers or {}), b""
                if e.code == 403 and "api.github.com" in req.full_url:
                    return 403, dict(e.headers or {}), b""   # rate limit — caller stops
                if e.code != 429 and e.code < 500:
                    raise SourceError(f"{req.full_url}: HTTP {e.code}") from e
                last = e
                wait = (e.headers or {}).get("Retry-After")
                delay = float(wait) if wait and wait.isdigit() else self.backoff * 2 ** attempt
            except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as e:
                last, delay = e, self.backoff * 2 ** attempt
            if attempt < self.retries:
                time.sleep(min(delay, 60))
        raise SourceError(f"{req.full_url}: {last}")

    def get_json(self, url: str, headers: dict | None = None):
        status, hdrs, body = self._open(urllib.request.Request(
            url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})}))
        if status in (403, 404):
            return None
        return json.loads(body)

    def get_json_headers(self, url: str):
        status, hdrs, body = self._open(urllib.request.Request(
            url, headers={"User-Agent": UA, "Accept": "application/json"}))
        return status, hdrs, (json.loads(body) if status == 200 else None)

    def post_json(self, url: str, payload: dict):
        _status, _h, body = self._open(urllib.request.Request(
            url, method="POST", data=json.dumps(payload).encode(),
            headers={"User-Agent": UA, "content-type": "application/json"}))
        return json.loads(body)


# --- sources ---------------------------------------------------------------------------

def fetch_registry(http: Http, base: str = REGISTRY_URL, page: int = 100,
                   max_servers: int | None = None) -> list[dict]:
    """Latest version of every server in the official registry (cursor pagination)."""
    out: dict[str, dict] = {}
    cursor = None
    while True:
        q = {"limit": str(page), "version": "latest"}
        if cursor:
            q["cursor"] = cursor
        doc = http.get_json(f"{base}?{urllib.parse.urlencode(q)}")
        if not isinstance(doc, dict):
            raise SourceError("registry: unexpected response")
        for item in doc.get("servers") or []:
            srv = item.get("server") or {}
            meta = (item.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
            # version=latest should return one row per server; if a registry ever ignores
            # the filter, keep the row it marks latest rather than whichever came last.
            if srv.get("name") and (meta.get("isLatest", True) or srv["name"] not in out):
                out[srv["name"]] = {"server": srv, "official": meta}
        cursor = (doc.get("metadata") or {}).get("nextCursor")
        if not cursor or (max_servers and len(out) >= max_servers):
            break
    return [out[k] for k in sorted(out)][:max_servers or None]


def _ts(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _repo_url(value) -> str | None:
    """Normalise a repository reference to 'host/owner/repo' when it points at a code host."""
    if isinstance(value, dict):
        value = value.get("url")
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip().lower()
    v = re.sub(r"^(git\+)?(https?|git|ssh)://(git@)?", "", v)
    v = re.sub(r"^git@([^:]+):", r"\1/", v)
    if v.startswith("github:"):
        v = "github.com/" + v[len("github:"):]
    v = v.split("#")[0].removesuffix(".git").rstrip("/")
    if not any(v.startswith(h) for h in _CODE_HOSTS):
        return None
    parts = v.split("/")
    return "/".join(parts[:3]) if len(parts) >= 3 and parts[2] else None


def npm_info(http: Http, name: str) -> dict | None:
    doc = http.get_json(NPM_URL + urllib.parse.quote(name, safe="@"))
    if doc is None:
        return None
    times = doc.get("time") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    ver = (doc.get("versions") or {}).get(latest) or {}
    return {
        "created": _ts(times.get("created")),
        "last_release": _ts(times.get(latest)) if latest else _ts(times.get("modified")),
        "latest": latest,
        "deprecated": bool(ver.get("deprecated")) or (not latest and "unpublished" in times),
        "repo": _repo_url(ver.get("repository")) or _repo_url(doc.get("repository")),
    }


def pypi_info(http: Http, name: str) -> dict | None:
    doc = http.get_json(PYPI_URL.format(urllib.parse.quote(name)))
    if doc is None:
        return None
    info = doc.get("info") or {}
    uploads = [_ts(f.get("upload_time_iso_8601")) for files in (doc.get("releases") or {}).values()
               for f in files or []]
    uploads = [u for u in uploads if u]
    latest_files = (doc.get("releases") or {}).get(info.get("version")) or doc.get("urls") or []
    latest_up = [_ts(f.get("upload_time_iso_8601")) for f in latest_files]
    latest_up = [u for u in latest_up if u]
    urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page")]
    repo = next((r for r in (_repo_url(u) for u in urls) if r), None)
    return {
        "created": min(uploads) if uploads else None,
        "last_release": max(latest_up) if latest_up else (max(uploads) if uploads else None),
        "latest": info.get("version"),
        "deprecated": bool(info.get("yanked")),
        "repo": repo,
    }


def osv_lookup(http: Http, pkgs: list[tuple[str, str, str | None]],
               chunk: int = 500) -> dict[tuple[str, str], dict]:
    """{(eco, name): {"mal": [ids], "mal_past": [ids], "vulns": [ids]}}. `mal` = MAL-
    advisories affecting the latest release (or, with no known version, the name at all):
    malicious. `mal_past` = MAL- advisories on the name that the latest release is clear of —
    a hijacked-then-cleaned package (the 2025 npm worm waves hit several vendor MCP servers),
    which is a caution, not a verdict on today's code. `vulns` = other advisories on latest."""
    out: dict[tuple[str, str], dict] = {(e, n): {"mal": [], "mal_past": [], "vulns": []}
                                        for e, n, _v in pkgs}
    versioned = {(e, n) for e, n, v in pkgs if v}
    queries: list[tuple[str, tuple[str, str], dict]] = []
    for eco, name, ver in pkgs:
        base = {"package": {"name": name, "ecosystem": _ECO[eco]}}
        queries.append(("mal", (eco, name), base))
        if ver:
            queries.append(("vulns", (eco, name), {**base, "version": ver}))
    for i in range(0, len(queries), chunk):
        part = queries[i:i + chunk]
        doc = http.post_json(OSV_BATCH_URL, {"queries": [q for _k, _p, q in part]})
        results = doc.get("results") or []
        if len(results) != len(part):
            raise SourceError(f"osv: {len(results)} results for {len(part)} queries")
        for (kind, key, _q), res in zip(part, results):
            ids = sorted({v.get("id") for v in (res or {}).get("vulns") or [] if v.get("id")})
            if kind == "mal":
                out[key]["mal_past"] = [x for x in ids if x.startswith("MAL-")]
            else:
                out[key]["mal"] = [x for x in ids if x.startswith("MAL-")]
                out[key]["vulns"] = [x for x in ids if not x.startswith("MAL-")]
    for key, o in out.items():
        if key not in versioned:
            o["mal"], o["mal_past"] = o["mal_past"], []
        else:
            o["mal_past"] = [x for x in o["mal_past"] if x not in o["mal"]]
    return out


def github_archived(http: Http, repos: list[str], max_calls: int) -> dict[str, bool]:
    """Unauthenticated spot-check of github.com repos; stops at the rate limit."""
    out: dict[str, bool] = {}
    for repo in repos[:max_calls]:
        if not repo.startswith("github.com/"):
            continue
        status, hdrs, doc = http.get_json_headers(GITHUB_API + repo[len("github.com/"):])
        if status == 403:
            break
        if doc is not None:
            out[repo] = bool(doc.get("archived"))
        if str(hdrs.get("X-RateLimit-Remaining", hdrs.get("x-ratelimit-remaining", "1"))) == "0":
            break
    return out


# --- in-repo inputs --------------------------------------------------------------------

def builtin_denylist(path: str = DEP_GUARD) -> set[str]:
    """dep_guard's _BUILTIN_DENYLIST, read with ast so this script needs no app imports."""
    try:
        tree = ast.parse(open(path).read())
    except OSError:
        return set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_BUILTIN_DENYLIST" for t in node.targets):
            return {str(x).lower() for x in ast.literal_eval(node.value)}
    return set()


def load_curated(path: str) -> dict[str, dict]:
    try:
        raw = json.load(open(path))
    except (OSError, ValueError):
        return {}
    return {k.strip().lower(): v for k, v in raw.items()
            if not k.startswith("_") and isinstance(v, dict) and v.get("tier") in _TIER_RANK}


# --- scoring ---------------------------------------------------------------------------

def _dl(a: str, b: str, cap: int) -> int:
    """Optimal-string-alignment (Damerau-Levenshtein) distance, early exit above `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


def _scope(name: str) -> str:
    return name.split("/")[0] if name.startswith("@") and "/" in name else ""


_GENERIC = {"mcp", "server", "srv"}


def _stem(name: str) -> str:
    """The distinctive part of a package name: generic tokens (mcp, server) dropped, so
    'ha-mcp-server' is not read as a near miss of 'exa-mcp-server' — they share only filler."""
    return "".join(t for t in re.split(r"[@/\-_.]+", name.lower()) if t and t not in _GENERIC)


def typosquat_of(name: str, famous: set[str]) -> str | None:
    """The well-known name `name` is a near miss of: distinctive stems 1 edit apart (2 for
    long stems) but neither a prefix of the other (a reused generic word like "memory" or
    "context" is not a squat), excluding the same npm scope — only the scope owner can
    publish there."""
    n, ns = name.lower(), _stem(name)
    for ref in sorted(famous):
        rs = _stem(ref)
        if (n == ref or len(rs) < 6 or ns.startswith(rs) or rs.startswith(ns)
                or (_scope(n) and _scope(n) == _scope(ref))):
            continue
        cap = 2 if len(rs) >= 12 else 1
        if _dl(ns, rs, cap) <= cap:
            return ref
    return None


def _namespace(server_name: str) -> tuple[str, str]:
    """('domain', 'example.com') for a reverse-DNS namespace, ('github', owner) for
    io.github.<owner>/…; the registry verifies both kinds before it accepts a publish."""
    ns = server_name.split("/")[0].lower()
    if ns.startswith("io.github."):
        return "github", ns[len("io.github."):]
    return "domain", ".".join(reversed(ns.split(".")))


def _host(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def score_server(entry: dict, pkg_info: dict, osv: dict, now: datetime, famous: set[str],
                 deny: set[str], archived: dict[str, bool] | None = None) -> dict:
    """Score one registry server. `pkg_info`: {(eco, name): info|None}, `osv`: {(eco,
    name): {mal, vulns}}. Returns {tier, score, reason, keys}."""
    srv, official = entry["server"], entry.get("official") or {}
    name = srv["name"]
    kind, owner = _namespace(name)
    status = (official.get("status") or "active").lower()
    archived = archived or {}
    pkgs = [(p.get("registryType", "").lower(), p.get("identifier", ""))
            for p in srv.get("packages") or [] if p.get("identifier")]
    keys = [name.lower()] + [n.lower() for e, n in pkgs if e in _ECO]

    hard: list[str] = []      # malicious evidence
    bad: list[str] = []       # risk signals: caution
    gaps: list[str] = []      # couldn't verify: unverified unless there is also a risk
    good: list[str] = []      # evidence toward trusted
    penalty = 0
    bonus: set[str] = set()   # track-record evidence that lifts a trusted score above 80

    for k in keys:
        if k in deny:
            hard.append(f"{k} is on Palivane's denylist")
    if status != "active":
        bad.append(f"registry status {status}")
        penalty += 35
    srv_repo = _repo_url(srv.get("repository"))

    repos = {srv_repo} if srv_repo else set()
    for eco, pname in pkgs:
        if eco not in _ECO:
            gaps.append(f"{eco} package not verified by this feed")
            penalty += 15
            continue
        tag = f"{eco} {pname}"
        o = osv.get((eco, pname)) or {}
        if o.get("mal"):
            hard.append(f"{tag}: OSV {', '.join(o['mal'][:3])}")
        if o.get("mal_past"):
            bad.append(f"{tag}: earlier versions malicious (OSV {', '.join(o['mal_past'][:3])}), "
                       "pin past them")
            penalty += 30
        info = pkg_info.get((eco, pname))
        if info is None:
            bad.append(f"{tag} not found on {eco}")
            penalty += 40
            continue
        if info.get("repo"):
            repos.add(info["repo"])
        if info.get("deprecated"):
            bad.append(f"{tag} latest release deprecated/yanked")
            penalty += 35
        created, last = info.get("created"), info.get("last_release")
        if created and now - created < timedelta(days=NEW_DAYS):
            bad.append(f"{tag} first published {created.date()} (<{NEW_DAYS}d)")
            penalty += 20
        elif not created:
            gaps.append(f"{tag} publish date unknown")
            penalty += 10
        if created and now - created > timedelta(days=365):
            bonus.add("established")
        if last and now - last <= timedelta(days=90):
            bonus.add("maintained")
        if last and now - last > timedelta(days=STALE_DAYS):
            bad.append(f"{tag} no release since {last.date()}")
            penalty += 15
        if o.get("vulns"):
            bad.append(f"{tag}@{info.get('latest')}: {len(o['vulns'])} known advisories "
                       f"({', '.join(o['vulns'][:3])})")
            penalty += min(20 + 5 * (len(o["vulns"]) - 1), 35)
        squat = typosquat_of(pname, famous)
        if squat:
            bad.append(f"{tag} is a near-miss of well-known {squat}")
            penalty += 40

    if pkgs and not repos:
        gaps.append("no source repository")
        penalty += 25
    for r in sorted(repos):
        if archived.get(r):
            bad.append(f"repo {r} archived")
            penalty += 30

    # publisher verification
    if kind == "domain":
        good.append(f"domain-verified publisher {owner}")
        bonus.add("domain")
    elif any(r.startswith(f"github.com/{owner}/") for r in repos):
        good.append(f"GitHub publisher {owner} owns the source repo")
    else:
        gaps.append(f"publisher io.github.{owner} does not own the source repo")
        penalty += 10

    remotes = [r.get("url", "") for r in srv.get("remotes") or [] if r.get("url")]
    if not pkgs:
        if not remotes:
            gaps.append("no package or remote endpoint")
            penalty += 30
        elif kind == "domain" and all(
                _host(u) == owner or _host(u).endswith("." + owner) for u in remotes):
            # The best a remote-only server can show — but there is no package to inspect,
            # so it stays below trusted rather than being waved through on a domain alone.
            gaps.append("remote-only (no package to inspect), on publisher's domain")
            penalty += 5
        else:
            gaps.append("remote-only (no package to inspect), off publisher's domain")
            penalty += 25
    elif repos:
        good.append("sourced " + ", ".join(sorted(repos)[:2]))

    if hard:
        reason = "; ".join(sorted(set(hard)))
        return {"tier": "malicious", "score": 0, "reason": reason, "keys": keys}
    if not bad and not gaps:
        tier, score = "trusted", min(95, 80 + 5 * len(bonus))
        reason = "registry-listed; " + "; ".join(good) + "; no advisories"
    else:
        # Risks first: they are why a caution row is one, and the reason is truncated.
        tier = "caution" if bad else "unverified"
        score = max(10, min(65, 70 - penalty))
        reason = "; ".join(dict.fromkeys(bad + gaps))   # two mcpb bundles = one signal
    return {"tier": tier, "score": score, "reason": reason[:400], "keys": keys}


def _worse(a: dict, b: dict) -> dict:
    ka = (_TIER_RANK[a["tier"]], a["score"], a["reason"])
    kb = (_TIER_RANK[b["tier"]], b["score"], b["reason"])
    return a if ka <= kb else b


def build_entries(servers: list[dict], pkg_info: dict, osv: dict, now: datetime,
                  curated: dict[str, dict], deny: set[str],
                  archived: dict[str, bool] | None = None) -> dict[str, dict]:
    """Score every server, key rows by server name + each package name (worst row wins a
    key collision), then lay the curated set over the top: a human-reviewed row beats a
    computed one, except that computed hard evidence (malicious) is never overridden."""
    famous = {k for k, v in curated.items() if v.get("tier") == "trusted"}
    deny = deny | {k for k, v in curated.items() if v.get("tier") == "malicious"}
    rows: dict[str, dict] = {}
    for entry in servers:
        s = score_server(entry, pkg_info, osv, now, famous, deny, archived)
        row = {"tier": s["tier"], "score": s["score"], "reason": s["reason"]}
        for k in s["keys"]:
            rows[k] = _worse(rows[k], row) if k in rows else row
    for k, v in curated.items():
        if k in rows and rows[k]["tier"] == "malicious" and v["tier"] != "malicious":
            continue
        rows[k] = {"tier": v["tier"], "score": v.get("score"),
                   "reason": "curated: " + str(v.get("reason", ""))}
    return rows


# --- output ----------------------------------------------------------------------------

def render(meta: dict, rows: dict[str, dict]) -> str:
    """Deterministic, compact, one row per line (so the weekly PR diff is readable)."""
    lines = [f'"_meta":{json.dumps(meta, sort_keys=True, separators=(",", ":"))}']
    for k in sorted(rows):
        lines.append(f"{json.dumps(k, ensure_ascii=False)}:"
                     f"{json.dumps(rows[k], sort_keys=True, separators=(',', ':'), ensure_ascii=False)}")
    return "{\n" + ",\n".join(lines) + "\n}\n"


def load_previous(path: str) -> tuple[dict, dict]:
    try:
        raw = json.load(open(path))
    except (OSError, ValueError):
        return {}, {}
    meta = raw.get("_meta") if isinstance(raw.get("_meta"), dict) else {}
    return meta, {k: v for k, v in raw.items() if not k.startswith("_")}


def check_shrink(prev_meta: dict, n_servers: int, min_ratio: float) -> None:
    prev = ((prev_meta.get("sources") or {}).get("registry_servers")) or 0
    if prev and n_servers < prev * min_ratio:
        raise SourceError(f"registry returned {n_servers} servers, previous run had {prev} "
                          f"(< {min_ratio:.0%}); refusing to write a truncated dataset "
                          "(--allow-shrink to override)")


def lookup_packages(http: Http, pkgs: list[tuple[str, str]], workers: int,
                    log=None) -> tuple[dict, int]:
    """{(eco, name): info|None} plus the count of lookups that errored (not 404)."""
    def one(p):
        eco, name = p
        try:
            return p, (npm_info if eco == "npm" else pypi_info)(http, name), False
        except (SourceError, ValueError):
            return p, None, True
    out: dict = {}
    errors = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, (p, info, err) in enumerate(pool.map(one, pkgs), 1):
            errors += err
            if not err:
                out[p] = info
            if log and i % 2000 == 0:
                log(f"packages: {i}/{len(pkgs)} ({errors} errors)")
    return out, errors


def main(argv: list[str] | None = None, http: Http | None = None,
         now: datetime | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--curated", default=DEFAULT_CURATED)
    ap.add_argument("--registry-url", default=REGISTRY_URL)
    ap.add_argument("--max-servers", type=int, default=None, help="dev: stop after N servers")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--min-ratio", type=float, default=0.8)
    ap.add_argument("--allow-shrink", action="store_true")
    ap.add_argument("--github", action="store_true", help="spot-check archived repos (no token)")
    ap.add_argument("--github-max", type=int, default=50)
    args = ap.parse_args(argv)
    http = http or Http()
    now = now or datetime.now(timezone.utc)
    log = lambda m: print(m, file=sys.stderr)  # noqa: E731

    try:
        prev_meta, prev_rows = load_previous(args.out)
        servers = fetch_registry(http, args.registry_url, max_servers=args.max_servers)
        log(f"registry: {len(servers)} servers")
        if not args.allow_shrink:
            check_shrink(prev_meta, len(servers), args.min_ratio)

        pkgs = sorted({(p.get("registryType", "").lower(), p["identifier"])
                       for s in servers for p in s["server"].get("packages") or []
                       if p.get("identifier") and p.get("registryType", "").lower() in _ECO})
        info, errors = lookup_packages(http, pkgs, args.workers, log)
        log(f"packages: {len(pkgs)} looked up, {errors} errors")
        if pkgs and errors > max(2, len(pkgs) * MAX_ERROR_RATIO):
            raise SourceError(f"{errors}/{len(pkgs)} package lookups failed")
        # Errored lookups are retried once, serially, so a flaky minute cannot turn a real
        # package into "not found".
        for p in pkgs:
            if p not in info:
                info[p] = (npm_info if p[0] == "npm" else pypi_info)(http, p[1])

        osv = osv_lookup(http, [(e, n, (info.get((e, n)) or {}).get("latest")) for e, n in pkgs])
        archived: dict[str, bool] = {}
        if args.github:
            repos = sorted({i["repo"] for i in info.values() if i and i.get("repo")})
            archived = github_archived(http, repos, args.github_max)
            log(f"github: {len(archived)} repos checked")
    except SourceError as e:
        log(f"mcp_feed_build: {e}")
        return 1

    curated = load_curated(args.curated)
    rows = build_entries(servers, info, osv, now, curated,
                         builtin_denylist() | {x.strip().lower() for x in
                                               os.getenv("MCP_SERVER_DENYLIST", "").split(",") if x.strip()},
                         archived)
    tiers = {t: sum(1 for r in rows.values() if r["tier"] == t) for t in sorted(_TIER_RANK)}
    meta = {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scoring_version": SCORING_VERSION,
        "sources": {"registry_servers": len(servers),
                    "npm_packages": sum(1 for e, _ in pkgs if e == "npm"),
                    "pypi_packages": sum(1 for e, _ in pkgs if e == "pypi"),
                    "osv_malicious": sum(1 for v in osv.values() if v["mal"]),
                    "github_repos_checked": len(archived),
                    "curated": len(curated)},
        "tiers": tiers,
        "entries": len(rows),
    }
    if rows == prev_rows and prev_meta.get("scoring_version") == SCORING_VERSION:
        meta = prev_meta   # nothing changed: keep the old stamp so the weekly job has no diff
    with open(args.out, "w") as f:
        f.write(render(meta, rows))
    log(f"wrote {args.out}: {len(rows)} entries {tiers}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
