"""Catalog growth sourcing — the parsing half of turning a public "top AI tools" feed into
candidate hosts, plus the merge half of landing reviewed rows in ai_catalog.py.

This module is pure text-in/text-out so it stays testable and keeps the network side out of
the app (the same split as catalog_pipeline): `scripts/fetch_candidates.py` does the
fetching + DNS verification and calls extract_hosts(); `scripts/merge_catalog_rows.py`
calls insert_rows() to place proposed rows under the right category section. The recurring
loop is .github/workflows/catalog-growth.yml, which runs both on a schedule and opens a PR
— the PR review is the human gate the pipeline requires.
"""
from __future__ import annotations

import re

# Hosts that appear constantly in link lists but are never AI-tool destinations themselves:
# code forges, socials, package registries, badges, funding pages, publishing platforms.
# Matched by exact host or dot-suffix ("gist.github.com" is dropped by "github.com").
HOST_DENYLIST: frozenset[str] = frozenset({
    "github.com", "raw.githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org",
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "instagram.com", "tiktok.com",
    "youtube.com", "youtu.be", "reddit.com", "medium.com", "substack.com", "dev.to",
    "wikipedia.org", "arxiv.org", "news.ycombinator.com", "producthunt.com",
    "discord.com", "discord.gg", "t.me", "slack.com",
    "npmjs.com", "pypi.org", "crates.io", "hub.docker.com",
    "google.com", "docs.google.com", "play.google.com", "apps.apple.com", "itunes.apple.com",
    "shields.io", "img.shields.io", "badge.fury.io", "awesome.re",
    "buymeacoffee.com", "patreon.com", "opencollective.com", "ko-fi.com",
    "stackoverflow.com", "stackexchange.com", "mailto",
    # press / research / VC — tools lists cite these constantly, but they are reading
    # material, not AI destinations an employee pastes data into
    "nytimes.com", "wsj.com", "wired.com", "bloomberg.com", "forbes.com", "reuters.com",
    "ft.com", "economist.com", "theinformation.com", "businessinsider.com", "cnbc.com",
    "bbc.com", "bbc.co.uk", "theguardian.com", "techcrunch.com", "theverge.com",
    "venturebeat.com", "arstechnica.com", "zdnet.com", "engadget.com", "axios.com",
    "semafor.com", "github.blog", "blogs.microsoft.com", "blog.google",
    "sequoiacap.com", "a16z.com", "ycombinator.com",
})

_URL_RE = re.compile(r"https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", re.I)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _denied(host: str) -> bool:
    if host.endswith(".edu") or ".ac." in host or host.endswith(".gov"):
        return True   # universities / government: research pages, not tool destinations
    return any(host == d or host.endswith("." + d) for d in HOST_DENYLIST)


def extract_hosts(text: str) -> list[str]:
    """Pull candidate hosts out of a markdown/HTML tools list: every http(s) link's host,
    lowercased, www.-stripped, minus IPs and HOST_DENYLIST noise. Order-preserving dedupe —
    feed order is roughly 'most notable first', which the per-run cap relies on."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _URL_RE.finditer(text or ""):
        host = m.group(1).lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        if not host or "." not in host or _IP_RE.match(host) or _denied(host):
            continue
        if host not in seen:
            seen.add(host)
            out.append(host)
    return out


# Category -> the section comment it lands under in ai_catalog.py. "api" rows share the
# ML-platforms section (its heading covers "API providers").
_SECTION_ANCHOR: dict[str, str] = {
    "assistant":   "# --- General assistants / chatbots ---",
    "search":      "# --- Search / answer engines ---",
    "coding":      "# --- Coding assistants / agents ---",
    "agent":       "# --- Agents / automation ---",
    "writing":     "# --- Writing / productivity ---",
    "image_video": "# --- Image / video / audio ---",
    "meeting":     "# --- Meeting / transcription notetakers (high data-exposure risk) ---",
    "ml_platform": "# --- ML platforms / model hubs / API providers ---",
    "api":         "# --- ML platforms / model hubs / API providers ---",
}


def insert_rows(source: str, rows: list[dict]) -> str:
    """Insert proposed rows ({host, name, category}, catalog_pipeline.propose() shape) into
    ai_catalog.py source text, each at the end of its category's section. Pure text
    transform; raises if a section anchor is missing so a reorganized file fails loudly."""
    lines = source.splitlines(keepends=True)

    def section_end(start: int) -> int:
        last_row = start
        for i in range(start + 1, len(lines)):
            s = lines[i].strip()
            if s.startswith("# ---") or s == "}":
                return last_row + 1
            if s:
                last_row = i
        raise ValueError("unterminated CATALOG section")

    by_anchor: dict[str, list[str]] = {}
    for r in rows:
        anchor = _SECTION_ANCHOR[r["category"]]
        by_anchor.setdefault(anchor, []).append(
            f'    "{r["host"]}": ("{r["name"]}", "{r["category"]}"),\n')

    for anchor, new_lines in by_anchor.items():
        start = next((i for i, l in enumerate(lines) if anchor in l), None)
        if start is None:
            raise ValueError(f"section anchor not found: {anchor}")
        end = section_end(start)
        lines[end:end] = new_lines
    return "".join(lines)


def update_readme_count(readme: str, n_tools: int) -> str:
    """Keep README's '~N-tool catalog' claim honest as the catalog grows (rounded down to
    the nearest 10). Returns the text unchanged if the claim isn't present."""
    return re.sub(r"~\d+-tool catalog", f"~{n_tools // 10 * 10}-tool catalog", readme)
