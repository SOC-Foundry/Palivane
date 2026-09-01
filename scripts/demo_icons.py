"""Tool glyphs for the hero video's scene chrome.

Most of these are SIMPLIFIED, hand-drawn marks — a radial burst for Claude, a four-point
spark for Gemini, a knot for OpenAI, a cube for Cursor — not the official brand assets.
They exist so a scene reads as "this is Claude" at 26px instead of showing an anonymous
coloured square, which is the whole point of the frame.

Two are the real thing: `brand-icons/gdrive.svg` and `brand-icons/slack.svg` are Google's
and Slack's own marks, in their own colours. The connector scenes name those products, and
a hand-drawn approximation of a logo reads as a knock-off in a way a hand-drawn abstract
mark does not.

To swap in a real asset for any other key, drop an SVG at `scripts/brand-icons/<key>.svg`
(keys below) and it is used verbatim — no code change, only fitted to the box. Check the
vendor's brand terms before you do: referring unmodified to a product you interoperate with
is normally fine, restyling their mark is not — which is why `color` is ignored for these.
"""
from __future__ import annotations

import math
import os
import re

ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand-icons")


def _claude(size: int, color: str) -> str:
    """Radial burst: tapered spokes around a common centre."""
    spokes = []
    for i in range(11):
        a = (i / 11) * 2 * math.pi - math.pi / 2
        x1, y1 = 12 + 2.0 * math.cos(a), 12 + 2.0 * math.sin(a)
        x2, y2 = 12 + 9.6 * math.cos(a), 12 + 9.6 * math.sin(a)
        spokes.append(f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
                      f'stroke="{color}" stroke-width="2.5" stroke-linecap="round"/>')
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none">'
            + "".join(spokes) + "</svg>")


def _gemini(size: int, color: str) -> str:
    """Four-point spark with concave sides."""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24">'
            f'<path d="M12 1.5 C12.9 7.2 16.8 11.1 22.5 12 C16.8 12.9 12.9 16.8 12 22.5 '
            f'C11.1 16.8 7.2 12.9 1.5 12 C7.2 11.1 11.1 7.2 12 1.5 Z" fill="{color}"/></svg>')


def _openai(size: int, color: str) -> str:
    """Interlocking hexagonal knot, reduced to two offset hex outlines."""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="1.7" stroke-linejoin="round">'
            f'<path d="M12 2.6 L20.1 7.3 L20.1 16.7 L12 21.4 L3.9 16.7 L3.9 7.3 Z"/>'
            f'<path d="M12 7.4 L16 9.7 L16 14.3 L12 16.6 L8 14.3 L8 9.7 Z"/>'
            f'<path d="M12 2.6 L12 7.4 M20.1 16.7 L16 14.3 M3.9 16.7 L8 14.3"/></svg>')


def _cursor(size: int, color: str) -> str:
    """Isometric cube."""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24">'
            f'<path d="M12 2 L21 7.2 L21 16.8 L12 22 L3 16.8 L3 7.2 Z" fill="{color}" '
            f'opacity=".35"/>'
            f'<path d="M12 2 L21 7.2 L12 12.5 Z" fill="{color}"/>'
            f'<path d="M12 12.5 L21 7.2 L21 16.8 L12 22 Z" fill="{color}" opacity=".75"/>'
            f'<path d="M3 7.2 L12 12.5 L12 22 L3 16.8 Z" fill="{color}" opacity=".5"/></svg>')


def _github(size: int, color: str) -> str:
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="{color}">'
            f'<path d="M12 1.6a10.4 10.4 0 0 0-3.29 20.27c.52.1.71-.23.71-.5v-1.75c-2.9.63-3.51-1.4-3.51-1.4'
            f'-.47-1.21-1.16-1.53-1.16-1.53-.95-.65.07-.64.07-.64 1.05.08 1.6 1.08 1.6 1.08.93 1.6 2.45 1.14 3.05.87'
            f'.09-.68.36-1.14.66-1.4-2.32-.27-4.76-1.16-4.76-5.16 0-1.14.41-2.07 1.07-2.8-.11-.27-.47-1.33.1-2.77'
            f'0 0 .88-.28 2.87 1.07a9.9 9.9 0 0 1 5.22 0c1.99-1.35 2.87-1.07 2.87-1.07.57 1.44.21 2.5.1 2.77'
            f'.67.73 1.07 1.66 1.07 2.8 0 4.01-2.44 4.89-4.77 5.15.38.32.71.96.71 1.94v2.87c0 .28.19.61.72.5A10.4 '
            f'10.4 0 0 0 12 1.6Z"/></svg>')


def _aws(size: int, color: str) -> str:
    """Wordmark-free stand-in: the smile arc over a cube."""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none">'
            f'<path d="M3 15.5 C7.5 19.5 16.5 19.5 21 15.5" stroke="{color}" stroke-width="2.2" '
            f'stroke-linecap="round"/>'
            f'<path d="M6.5 12.5 L9 5.5 L11 5.5 L13.5 12.5" stroke="{color}" stroke-width="1.9" '
            f'stroke-linecap="round" stroke-linejoin="round"/>'
            f'<path d="M15 5.5 L16.6 12.5 L18.2 8 L19.8 12.5 L21 5.5" stroke="{color}" '
            f'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def _connector(size: int, color: str) -> str:
    """Neutral stand-in for a SaaS connector: a cloud with a plug.

    Deliberately anonymous. Drive and Slack map here so that a missing brand asset
    degrades to "some connector" rather than to another vendor's mark.
    """
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="{color}" stroke-width="1.8" stroke-linecap="round" '
            f'stroke-linejoin="round">'
            f'<path d="M7.2 16.5a4.2 4.2 0 0 1-.3-8.39 5.6 5.6 0 0 1 10.66 1.6 '
            f'3.6 3.6 0 0 1-.86 7.09z"/>'
            f'<path d="M12 13.4 L12 21.2 M9.4 18.6 L12 21.2 L14.6 18.6"/></svg>')


# key -> (drawer, default colour)
GLYPHS = {
    "claude": (_claude, "#d97757"),
    "chatgpt": (_openai, "#10a37f"),
    "codex": (_openai, "#e8eefc"),
    "gemini": (_gemini, "#4285f4"),
    "cursor": (_cursor, "#8b93ff"),
    "github": (_github, "#e8eefc"),
    "aws": (_aws, "#ff9900"),
    "claudecode": (_claude, "#d97757"),
    "gdrive": (_connector, "#4285f4"),
    "slack": (_connector, "#e01e5a"),
}


_SVG_TAG = re.compile(r"<svg\b[^>]*>", re.I)
_DIM_ATTR = re.compile(r'\s(?:width|height)\s*=\s*"[^"]*"', re.I)
_VIEWBOX = re.compile(r'viewBox\s*=\s*"\s*[-\d.eE]+[,\s]+[-\d.eE]+[,\s]+'
                      r'([-\d.eE]+)[,\s]+([-\d.eE]+)\s*"', re.I)


def _fit(svg: str, size: int) -> str:
    """Scale an official asset to fit a size x size box, keeping its aspect ratio.

    Brand marks are not all square — Drive's viewBox is 87.3x78 — so stamping
    width=height=size on the root tag stretches the artwork. Derive both from the
    viewBox instead, and drop any width/height the vendor shipped so ours is the
    only one the parser sees.
    """
    tag = _SVG_TAG.search(svg)
    if not tag:                                    # not an SVG we understand; leave it be
        return svg
    w = h = float(size)
    box = _VIEWBOX.search(tag.group(0))
    if box:
        vw, vh = float(box.group(1)), float(box.group(2))
        if vw > 0 and vh > 0:
            scale = size / max(vw, vh)
            w, h = vw * scale, vh * scale
    sized = _DIM_ATTR.sub("", tag.group(0))
    sized = sized.replace("<svg", f'<svg width="{w:.2f}" height="{h:.2f}"', 1)
    return svg[:tag.start()] + sized + svg[tag.end():]


def icon(key: str, size: int = 26, color: str | None = None) -> str:
    """Inline SVG for `key`. An official asset at scripts/brand-icons/<key>.svg wins.

    `color` is ignored for an official asset: recolouring a vendor's mark is exactly
    what their brand terms forbid, and the marks carry their own palette anyway.
    """
    override = os.path.join(ICON_DIR, f"{key}.svg")
    if os.path.isfile(override):
        with open(override) as f:
            return _fit(f.read(), size)
    drawer, default = GLYPHS.get(key, (_connector, "#9aa4b8"))
    return drawer(size, color or default)
