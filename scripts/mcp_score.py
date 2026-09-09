"""Lofi score for the MCP demo clip (scripts/mcp_video.py renders the picture).

Reuses demo_score.render — the same Rhodes/plucked-bass/vinyl bed as the hero and setup
cuts, so this clip sits in the same sonic family. Sections track the ~26s storyboard: title
card, four asks (each a small lift), then a settle under the closing card.

    <venv-with-numpy-scipy>/bin/python scripts/mcp_score.py     # -> marketing/mcp-demo-score.wav
Then mux with the video (see the tail of this file / the PR).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import demo_score as M   # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.getenv("MCP_SCORE_OUT", f"{REPO}/marketing/mcp-demo-score.wav")
DUR = float(os.getenv("MCP_VIDEO_SECONDS", "26"))

# (t0, t1, chords, intensity) — the ii-V-I-vi turnaround, lifting through the middle asks
# and settling home under the closing card. Boundaries roughly follow mcp_video.py's turns.
M.render(DUR, [
    (0.0,  2.4,  ["C"],                    0.15),   # title card
    (2.4,  7.0,  ["Dm", "G"],              0.50),   # ask 1 — findings
    (7.0,  11.8, ["C", "Am"],              0.62),   # ask 2 — shadow-AI inventory
    (11.8, 16.4, ["Dm", "G"],              0.60),   # ask 3 — triage
    (16.4, 22.6, ["F", "Em", "Dm", "G"],   0.72),   # ask 4 — OWASP coverage (build)
    (22.6, DUR,  ["C", "Am"],              0.28),   # closing card — settle home
], OUT)
print("wrote", OUT)
