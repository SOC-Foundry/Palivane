"""Tool glyphs for the hero video's scene chrome.

These are SIMPLIFIED, hand-drawn marks — a radial burst for Claude, a four-point spark for
Gemini, a knot for OpenAI, a cube for Cursor — not the official brand assets. They exist so
a scene reads as "this is Claude" at 26px instead of showing an anonymous coloured square,
which is the whole point of the frame.

To use the real thing instead, drop an SVG at `scripts/brand-icons/<key>.svg` (keys below)
and it is used verbatim — no code change. Check the vendor's brand terms before you do:
referring to a product you interoperate with is normally fine, restyling their mark is not.
"""
from __future__ import annotations

import math
import os

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
}


def icon(key: str, size: int = 26, color: str | None = None) -> str:
    """Inline SVG for `key`. An official asset at scripts/brand-icons/<key>.svg wins."""
    override = os.path.join(ICON_DIR, f"{key}.svg")
    if os.path.isfile(override):
        with open(override) as f:
            svg = f.read()
        # size it without touching the artwork
        return svg.replace("<svg", f'<svg width="{size}" height="{size}"', 1)
    drawer, default = GLYPHS.get(key, (_openai, "#9aa4b8"))
    return drawer(size, color or default)
