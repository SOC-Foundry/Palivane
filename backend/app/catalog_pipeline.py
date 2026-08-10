"""Catalog growth pipeline — turn a list of candidate AI-tool hosts into proposed catalog
rows, so keeping pace with new tools isn't purely manual.

This is the *classification + dedupe* half of catalog growth. It takes candidates —
{host, name?, category?} — dedupes them against the live CATALOG, guesses a category from
name/host keywords when one isn't given, and returns proposed rows for review. It does NOT
crawl the web: sourcing the candidate list (a CASB/SWG export, a "top AI tools" feed, DNS
logs of unmatched destinations) is a data step the operator runs and points this at. That
keeps the network side out of the app and the review gate human.

    from app.catalog_pipeline import propose
    propose([{"host": "poe.com"}, {"host": "v0.dev", "name": "v0"}])

`scripts/grow_catalog.py` wraps this for CLI use (reads candidates from a file/stdin, prints
paste-ready CATALOG lines).
"""
from __future__ import annotations

from .ai_catalog import CATALOG, CATEGORY_LABEL, classify

# Category guess: first keyword group that matches the host or name wins. Order matters —
# more specific categories first. This is a heuristic to pre-fill review, never the last word.
_CATEGORY_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("coding", ("code", "dev", "copilot", "cursor", "codeium", "tabnine", "replit", "v0", "bolt")),
    ("image_video", ("image", "img", "video", "vid", "art", "diffusion", "midjourney",
                     "runway", "sora", "pika", "eleven", "voice", "audio", "music")),
    ("meeting", ("meet", "notetaker", "otter", "fireflies", "fathom", "granola", "transcri")),
    ("search", ("search", "perplex", "phind", "you.com")),
    ("writing", ("write", "writer", "grammar", "copy", "jasper", "notion", "docs")),
    ("ml_platform", ("huggingface", "replicate", "sagemaker", "vertex", "bedrock",
                     "together", "modal", "banana", "ml", "train")),
    ("api", ("api.", "openrouter", "endpoint")),
    ("agent", ("agent", "auto", "devin", "manus", "flow", "orchestr", "n8n", "zapier")),
]


def _norm_host(host: str) -> str:
    h = (host or "").strip().lower()
    for p in ("https://", "http://"):
        if h.startswith(p):
            h = h[len(p):]
    return h.split("/")[0].strip("/")


def guess_category(host: str, name: str = "") -> str:
    hay = f"{host} {name}".lower()
    for cat, kws in _CATEGORY_HINTS:
        if any(k in hay for k in kws):
            return cat
    return "assistant"   # the safe default for a general AI destination


def propose(candidates: list[dict]) -> dict:
    """Classify + dedupe candidates. Returns {new: [...], known: [...], invalid: [...]}.
    A `new` row is {host, name, category, category_label} ready to add to CATALOG after a
    human glance."""
    new: list[dict] = []
    known: list[dict] = []
    invalid: list[dict] = []
    seen_new: set[str] = set()
    for c in candidates:
        host = _norm_host(c.get("host", ""))
        if not host or "." not in host:
            invalid.append({"input": c, "reason": "not a host"})
            continue
        hit = classify(host)               # already in the catalog (or a substring match)?
        if hit:
            known.append({"host": host, "tool": hit["tool"], "category": hit["category"]})
            continue
        if host in CATALOG or host in seen_new:
            known.append({"host": host, "tool": CATALOG.get(host, ("?",))[0],
                          "category": CATALOG.get(host, ("", ""))[1]})
            continue
        cat = (c.get("category") or "").strip() or guess_category(host, c.get("name", ""))
        if cat not in CATEGORY_LABEL:
            cat = "assistant"
        name = (c.get("name") or "").strip() or _default_name(host)
        seen_new.add(host)
        new.append({"host": host, "name": name, "category": cat,
                    "category_label": CATEGORY_LABEL[cat]})
    return {"new": new, "known": known, "invalid": invalid,
            "counts": {"new": len(new), "known": len(known), "invalid": len(invalid)}}


def _default_name(host: str) -> str:
    """A readable name from a host: the second-level label, title-cased ('poe.com' -> 'Poe')."""
    parts = host.split(".")
    label = parts[-2] if len(parts) >= 2 else parts[0]
    return label.replace("-", " ").title()


def as_catalog_lines(new_rows: list[dict]) -> str:
    """Render proposed rows as paste-ready CATALOG source lines."""
    return "\n".join(
        f'    "{r["host"]}": ({r["name"]!r}, {r["category"]!r}),' for r in new_rows)
