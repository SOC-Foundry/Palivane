"""CLI for the catalog growth pipeline — classify candidate AI-tool hosts into proposed
CATALOG rows.

Sourcing candidates is the operator's data step (this does NOT crawl): feed it a list of
hosts — a CASB/SWG export, DNS logs of AI destinations that didn't match the catalog, or a
"top AI tools" list. It dedupes against the live catalog, guesses a category, and prints
paste-ready rows for a human to drop into backend/app/ai_catalog.py.

    # one host per line (optionally  host,name,category)
    printf 'poe.com\nv0.dev,v0,coding\n' | python scripts/grow_catalog.py
    python scripts/grow_catalog.py candidates.txt
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))
from app.catalog_pipeline import as_catalog_lines, propose   # noqa: E402


def _parse(lines) -> list[dict]:
    out = []
    for raw in lines:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        parts = [p.strip() for p in raw.split(",")]
        c = {"host": parts[0]}
        if len(parts) > 1 and parts[1]:
            c["name"] = parts[1]
        if len(parts) > 2 and parts[2]:
            c["category"] = parts[2]
        out.append(c)
    return out


def main() -> int:
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    result = propose(_parse(src))
    c = result["counts"]
    print(f"# {c['new']} new, {c['known']} already covered, {c['invalid']} invalid\n",
          file=sys.stderr)
    if result["new"]:
        print("    # --- proposed additions (review before merging) ---")
        print(as_catalog_lines(result["new"]))
    else:
        print("# nothing new to add.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
