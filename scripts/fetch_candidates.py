"""Fetch candidate AI-tool hosts from the recurring sources for the catalog growth pipeline.

The network half of catalog sourcing (parsing lives in app.catalog_sourcing): download each
list in scripts/catalog_sources.txt, extract candidate hosts, drop ones the catalog already
knows, DNS-verify the rest, and print one host per line — ready for grow_catalog.py /
merge_catalog_rows.py. Run weekly by .github/workflows/catalog-growth.yml, or by hand:

    python scripts/fetch_candidates.py --limit 40 > candidates.txt

The cap keeps the resulting review PR a human-sized diff; anything dropped is reported on
stderr, never silently.
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))
from app.ai_catalog import classify          # noqa: E402
from app.catalog_sourcing import extract_hosts   # noqa: E402

SOURCES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog_sources.txt")


def _fetch(url: str) -> str | None:
    """GET a source list; on a 404 of a raw.githubusercontent.com URL, retry with the other
    default-branch name (master <-> main). None (with a stderr warning) on failure."""
    for attempt_url in (url, _swap_branch(url)):
        if not attempt_url:
            continue
        try:
            with urllib.request.urlopen(attempt_url, timeout=20) as r:
                return r.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError) as e:
            err = e
    print(f"warn: source unavailable, skipping: {url} ({err})", file=sys.stderr)
    return None


def _swap_branch(url: str) -> str | None:
    if "raw.githubusercontent.com" not in url:
        return None
    if "/master/" in url:
        return url.replace("/master/", "/main/", 1)
    if "/main/" in url:
        return url.replace("/main/", "/master/", 1)
    return None


def _resolves(host: str) -> bool:
    socket.setdefaulttimeout(4)
    for h in (host, "www." + host):
        try:
            socket.getaddrinfo(h, 443)
            return True
        except OSError:
            pass
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=40,
                    help="max candidates to emit (keeps the review PR reviewable)")
    ap.add_argument("--sources", default=SOURCES_FILE)
    args = ap.parse_args()

    urls = [l.strip() for l in open(args.sources)
            if l.strip() and not l.strip().startswith("#")]
    hosts: list[str] = []
    seen: set[str] = set()
    for url in urls:
        body = _fetch(url)
        for h in extract_hosts(body or ""):
            if h not in seen:
                seen.add(h)
                hosts.append(h)

    fresh = [h for h in hosts if classify(h) is None]
    emitted = 0
    dead = 0
    for h in fresh:
        if emitted >= args.limit:
            break
        if not _resolves(h):
            dead += 1
            continue
        print(h)
        emitted += 1

    overflow = max(0, len(fresh) - dead - emitted)
    print(f"sources: {len(urls)}  extracted: {len(hosts)}  already-known: "
          f"{len(hosts) - len(fresh)}  dns-failed: {dead}  emitted: {emitted}"
          + (f"  deferred-to-next-run: {overflow}" if overflow else ""),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
