"""Does this package exist, and how old is it? One guarded, cached lookup per ecosystem.

Used by the phantom-dependency check (detectors/phantom_deps.py): a model suggests
`pip install foo`, and the question is whether `foo` is real, and if so whether it appeared
last week (the slopsquatting shape: someone registered the name a model keeps inventing).
PyPI, npm, crates.io, RubyGems and the Go module proxy, each through the SSRF-pinned
transport, with a short timeout, an in-process TTL cache, and fail-open on any error: a
registry outage must never make a response look suspicious.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

TIMEOUT = 2.5
TTL = 6 * 3600
_UA = "palivane-registry-lookup/1.0"
_cache: dict[tuple[str, str], tuple[float, dict | None]] = {}
_lock = threading.Lock()

ECOSYSTEMS = ("pypi", "npm", "crates", "gem", "go")


def _get(url: str) -> tuple[int, dict | str | None]:
    """(status, parsed body). 404/410 are answers, not errors; anything else raises."""
    from .netguard import safe_urlopen
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        resp = safe_urlopen(req, TIMEOUT)
    except Exception as e:  # noqa: BLE001 - safe_urlopen raises on non-2xx with the status in the message
        msg = str(e)
        for code in ("404", "410"):
            if code in msg:
                return int(code), None
        raise
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, resp.text


def _age_days(ts: str | None) -> int | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return None


def _pypi(name: str) -> dict | None:
    st, doc = _get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if st in (404, 410):
        return {"exists": False}
    if not isinstance(doc, dict):
        return None
    first = None
    for files in (doc.get("releases") or {}).values():
        for f in files or []:
            t = f.get("upload_time_iso_8601") or f.get("upload_time")
            if t and (first is None or t < first):
                first = t
    return {"exists": True, "age_days": _age_days(first)}


def _npm(name: str) -> dict | None:
    st, doc = _get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}")
    if st in (404, 410):
        return {"exists": False}
    if not isinstance(doc, dict):
        return None
    return {"exists": True, "age_days": _age_days((doc.get("time") or {}).get("created"))}


def _crates(name: str) -> dict | None:
    st, doc = _get(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}")
    if st in (404, 410):
        return {"exists": False}
    if not isinstance(doc, dict):
        return None
    return {"exists": True, "age_days": _age_days((doc.get("crate") or {}).get("created_at"))}


def _gem(name: str) -> dict | None:
    st, doc = _get(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json")
    if st in (404, 410):
        return {"exists": False}
    if not isinstance(doc, dict):
        return None
    st2, versions = _get(f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(name)}.json")
    first = None
    if isinstance(versions, list):
        for v in versions:
            t = v.get("created_at")
            if t and (first is None or t < first):
                first = t
    return {"exists": True, "age_days": _age_days(first)}


def _go(module: str) -> dict | None:
    # The proxy lower-cases with ! escapes for capitals; module paths in suggestions are
    # usually already lower-case. 404/410 = unknown module.
    esc = "".join(("!" + c.lower()) if c.isupper() else c for c in module)
    st, doc = _get(f"https://proxy.golang.org/{esc}/@v/list")
    if st in (404, 410):
        return {"exists": False}
    return {"exists": True, "age_days": None}


_FN = {"pypi": _pypi, "npm": _npm, "crates": _crates, "gem": _gem, "go": _go}


def lookup(eco: str, name: str) -> dict | None:
    """{"exists": bool, "age_days": int | None} or None when the registry could not be asked."""
    fn = _FN.get(eco)
    if fn is None or not name:
        return None
    key = (eco, name.lower())
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    try:
        out = fn(name)
    except Exception:  # noqa: BLE001 - fail open: the registry is a courtesy, not a gate
        out = None
    with _lock:
        _cache[key] = (now + (TTL if out is not None else 300), out)
    return out


def clear_cache() -> None:
    with _lock:
        _cache.clear()
