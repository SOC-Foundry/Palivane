"""Land candidate hosts in backend/app/ai_catalog.py — classify + dedupe via the growth
pipeline, insert each new row at the end of its category section, and keep README's
catalog-size claim honest. Prints a markdown summary of what changed (the auto-PR body).

    python scripts/fetch_candidates.py > candidates.txt      # or any host[,name[,category]] file
    python scripts/merge_catalog_rows.py candidates.txt

The edit is a proposal, not a decision: run this on a branch and review the diff — the
category guesses and default names are heuristics to pre-fill review, never the last word.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))
from app.catalog_pipeline import propose            # noqa: E402
from app.catalog_sourcing import insert_rows, update_readme_count  # noqa: E402
from grow_catalog import _parse                     # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG_PY = os.path.join(ROOT, "backend", "app", "ai_catalog.py")
README = os.path.join(ROOT, "README.md")


def main() -> int:
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    result = propose(_parse(src))
    rows = result["new"]
    if not rows:
        print("No new catalog rows — nothing to merge.")
        return 0

    source = open(CATALOG_PY).read()
    open(CATALOG_PY, "w").write(insert_rows(source, rows))

    # re-import cleanly for the post-merge count (this process imported the pre-merge dict)
    ns: dict = {}
    exec(compile(open(CATALOG_PY).read(), CATALOG_PY, "exec"), ns)
    n_tools = len({v[0] for v in ns["CATALOG"].values()})
    readme = open(README).read()
    open(README, "w").write(update_readme_count(readme, n_tools))

    print(f"Proposed {len(rows)} new catalog rows "
          f"({result['counts']['known']} already covered, "
          f"{result['counts']['invalid']} invalid); catalog now ~{n_tools} tools.\n")
    print("| host | proposed name | category |\n|---|---|---|")
    for r in rows:
        print(f"| `{r['host']}` | {r['name']} | {r['category']} |")
    print("\nNames and categories are pipeline guesses — fix any that are wrong before merging.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
