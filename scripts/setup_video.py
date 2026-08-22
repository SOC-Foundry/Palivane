"""Render the setup-page video (frontend/public/shots/setupN.mp4).

The previous cut (setup4.mp4) was produced ad hoc and only the .mp4 was committed — this
script makes it reproducible, same as the hero rig. Storyboard (mirrors setup4): a title
card, the LIVE Connect page, the one-command install terminal, the LIVE Settings page, a
second title card, the MDM push terminal, the LIVE Findings page, and a closing brand card.

    # local stack (frontend built; backend serving it):
    #   PALIVANE_STATIC_DIR=frontend/dist DATABASE_URL=sqlite:///<db> \
    #     backend/.venv/bin/uvicorn app.main:app --port 8088
    #   (seed first: backend/.venv/bin/python -m app.seed)
    backend/.venv/bin/python scripts/demo_capture.py     # optional: populates findings
    backend/.venv/bin/python scripts/setup_video.py      # -> $DEMO_WORK/setup_silent.mp4

Audio: the score is carried over from the previous cut (it is unbranded lofi) — extract it
before replacing the file, then mux:
    ffmpeg -i frontend/public/shots/setup4.mp4 -vn -c:a copy /tmp/palivane-demo/setup-score.m4a
    ffmpeg -i setup_silent.mp4 -i setup-score.m4a -map 0:v -map 1:a -c:v copy -c:a copy \
      -shortest -movflags +faststart frontend/public/shots/setupN.mp4
If the cut's length changes materially, synthesize a new bed with demo_score.py instead
(match its section map to the new duration). Same output constraints as the hero video:
1280x800, 25 fps, h264 + faststart, and a NEW filename every re-cut (Cloudflare caches by
path) with Setup.jsx bumped.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import demo_scenes as S      # noqa: E402
from demo_video import (     # noqa: E402
    FPS, W, H, BASE, EMAIL, PASSWORD, WORK, REPO,
    render_scene, encode_segment, concat_with_xfade,
)

OUT = os.getenv("SETUP_OUT", f"{WORK}/setup_silent.mp4")
XFADE = 0.4


def _num_badge(n: int, title: str, sub: str) -> str:
    """Numbered step badge (the setup video counts steps; the hero badges are tool marks)."""
    return (
        '<div class="badge" style="left:28px;right:auto;padding:9px 16px 9px 10px">'
        f'<span style="display:grid;place-items:center;width:24px;height:24px;'
        f'border-radius:50%;border:1.6px solid #9db4ff;color:#cdd9ff;font-size:12.5px;'
        f'font-weight:800">{n}</span>'
        f'<span><div style="font-weight:800">{html.escape(title)}</div>'
        f'<div style="font-size:11px;color:#9BA6A0;font-weight:600">{html.escape(sub)}</div>'
        '</span></div>')


def terminal_scene_numbered(title: str, lines: list[tuple[str, str]],
                            n: int, badge_title: str, badge_sub: str) -> str:
    """S.terminal_scene with its tool-mark badge swapped for a numbered step badge."""
    scene = S.terminal_scene(title, lines, "claudecode", badge_title)
    return re.sub(r'<div class="badge">.*?</div>', _num_badge(n, badge_title, badge_sub),
                  scene, count=1, flags=re.S)


def closing_scene() -> str:
    return f"""<!doctype html><meta charset="utf-8"><style>{S.BASE_CSS}</style>
<div class="scene" style="background:#0E100F">
  <div id="wrap" style="position:absolute;inset:0;display:flex;flex-direction:column;
      align-items:center;justify-content:center;gap:22px;opacity:0">
    <img src="palivane-emblem.png" style="height:150px;width:auto" />
    <div style="color:#FFFFFF;font-size:46px;font-weight:800;letter-spacing:.42em;
        margin-left:.42em">PALIVANE</div>
    <div style="color:#9BA6A0;font-size:16px;font-weight:700;letter-spacing:.18em">
      AI SECURITY GATEWAY</div>
  </div>
</div>
<script>
const wrap = document.getElementById('wrap');
function setT(t) {{
  const inP = Math.min(1, t / 0.3);
  wrap.style.opacity = inP;                     // holds to the end — it's the last frame
  wrap.style.transform = `scale(${{0.97 + inP * 0.03}})`;
}}
setT(0);
</script>"""


def console_page_frames(pw, tab: str, seconds: float, out_dir: str) -> int:
    """Capture ONE live console page with a slow scroll drift (same idea as the hero's
    console tour, but a single tab per segment)."""
    import urllib.request
    req = urllib.request.Request(
        BASE + "/api/auth/login", method="POST",
        data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
        headers={"content-type": "application/json"})
    token = json.loads(urllib.request.urlopen(req, timeout=30).read())["access_token"]
    b = pw.chromium.launch(args=["--disable-dev-shm-usage", "--no-sandbox"])
    page = b.new_context(viewport={"width": W, "height": H}).new_page()
    page.add_init_script(f"localStorage.setItem('palivane_token', {json.dumps(token)})")
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(1200)
    try:
        page.get_by_role("button", name=tab, exact=True).click()
        page.wait_for_timeout(700)
    except Exception as e:
        print(f"  console page: could not open {tab} ({str(e)[:60]})")
        b.close()
        return 0
    frames = int(seconds * FPS)
    for i in range(frames):
        page.mouse.wheel(0, 6)                   # slow drift so the screen isn't static
        page.screenshot(path=f"{out_dir}/f{i:05d}.png")
    b.close()
    return frames


def build_scenes() -> list[tuple[str, str, float]]:
    connect_lines = [
        ("cmd", "$ palivane-connect https://app.palivane.io"),
        ("ok", "✓ Signed in as dev@acme.com · Acme, Inc."),
        ("ok", "✓ Claude Code → gateway configured (managed-settings.json)"),
        ("ok", "✓ Cursor → gateway configured"),
        ("ok", "✓ Tool-call hooks installed (monitor mode)"),
        ("ok", "✓ Browser extension → finish here: …/extension-connect"),
        ("dim", "Every AI request from this machine now routes through Palivane."),
    ]
    mdm_lines = [
        ("dim", "# push the Palivane policy pack via Jamf · Intune · GPO"),
        ("cmd", '$ intune push palivane-policy-pack.json --group "All Corp Devices"'),
        ("ok", "✓ Extension force-install → 248 devices"),
        ("ok", "✓ Gateway + hooks config → 248 devices"),
        ("dim", "No agent to install. The pack carries every setting."),
    ]
    return [
        ("title1", S.title_scene("GET STARTED", "Set up Palivane",
                                 "Part 1 · for you & your team"), 4.5),
        ("term1", terminal_scene_numbered("zsh - acme-laptop", connect_lines,
                                          1, "One command", "self-serve · any machine"), 9.5),
        ("title2", S.title_scene("SCALE IT", "Roll out to your whole org",
                                 "Part 2 · one pack, your entire fleet via MDM"), 4.5),
        ("term2", terminal_scene_numbered("admin - mdm-console", mdm_lines,
                                          2, "Push it fleet-wide", "agentless · via your MDM"), 9.5),
        ("closing", closing_scene(), 5.4),
    ]


# (name, tab, seconds, insert-after-scene) — the live console segments between the cards.
CONSOLE_SEGMENTS = [
    ("connect", "Connect", 9.5, "title1"),
    ("settings", "Settings", 9.5, "term1"),
    ("findings", "Findings", 9.5, "term2"),
]


def main() -> int:
    os.makedirs(WORK, exist_ok=True)
    from playwright.sync_api import sync_playwright

    scenes = build_scenes()
    anchors = {a: (f"console_{n}", t, s) for n, t, s, a in CONSOLE_SEGMENTS}

    segments = []
    with sync_playwright() as pw:
        for name, html_doc, secs in scenes:
            fd = f"{WORK}/sframes_{name}"
            shutil.rmtree(fd, ignore_errors=True)
            os.makedirs(fd)
            n = render_scene(pw, name, html_doc, secs, fd)
            seg = f"{WORK}/sseg_{name}.mp4"
            encode_segment(fd, seg)
            segments.append(seg)
            print(f"  {name:11s} {n:4d} frames  {secs:4.1f}s")
            if name in anchors:                      # live console page after this card
                cname, tab, csecs = anchors[name]
                fd = f"{WORK}/sframes_{cname}"
                shutil.rmtree(fd, ignore_errors=True)
                os.makedirs(fd)
                n = console_page_frames(pw, tab, csecs, fd)
                if n:
                    seg = f"{WORK}/sseg_{cname}.mp4"
                    encode_segment(fd, seg)
                    segments.append(seg)
                    print(f"  {cname:11s} {n:4d} frames  {csecs:4.1f}s (live)")

    concat_with_xfade(segments, OUT)
    dur = float(subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", OUT],
        capture_output=True, text=True, check=True).stdout.strip())
    print(f"\nvideo: {dur:.2f}s -> {OUT}  (see module docstring for the audio mux)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
