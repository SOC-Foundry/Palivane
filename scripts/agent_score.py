"""Lofi score for the agent-suite demo clip (scripts/agent_video.py renders the picture).

Reuses demo_score.render — the same Rhodes/plucked-bass/vinyl bed as the hero, setup and MCP
cuts, so this clip sits in the same sonic family. Sections track the ~27s storyboard: title
card, three scenes (analyst → attestation → A2A, each a small lift, the graph building), then
a settle under the closing card.

    <venv-with-numpy-scipy>/bin/python scripts/agent_score.py     # -> marketing/agent-demo-score.wav
Then mux with the video:
    ffmpeg -y -i marketing/agent-demo.mp4 -i marketing/agent-demo-score.wav \
      -map 0:v -map 1:a -c:v copy -c:a aac -movflags +faststart -shortest marketing/agent-demo.mp4
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import demo_score as M   # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.getenv("AGENT_SCORE_OUT", f"{REPO}/marketing/agent-demo-score.wav")
DUR = float(os.getenv("AGENT_VIDEO_SECONDS", "27"))

# (t0, t1, chords, intensity) — ii-V-I-vi turnaround, lifting through the three scenes and
# settling home under the closing card. Boundaries follow agent_video.py's scene timeline
# (title 2.6s, then ~5.5s per scene, then the closing card).
M.render(DUR, [
    (0.0,  2.6,  ["C"],                   0.15),   # title card
    (2.6,  8.1,  ["Dm", "G"],             0.52),   # scene 1 — the analyst
    (8.1,  13.6, ["C", "Am"],             0.64),   # scene 2 — attestation
    (13.6, 19.1, ["F", "Em", "Dm", "G"],  0.72),   # scene 3 — A2A graph (build)
    (19.1, DUR,  ["C", "Am"],             0.26),   # closing card — settle home
], OUT)
print("wrote", OUT)
