# scripts/

Operational and content-production scripts. `e2e.py` and `shots.py` are documented in
their own headers; the demo-video rig is below.

## The landing-page hero video

Three scripts rebuild `frontend/public/shots/demo12.mp4` from scratch. They exist because
the previous video (and its score) were produced ad hoc and only the `.mp4` was committed —
so every re-cut started over. Everything here is reproducible.

```bash
./run-local.sh                                              # terminal 1: a local Warden
PALIVANE_URL=http://localhost:8088 \
  backend/.venv/bin/python scripts/demo_capture.py          # real verdicts -> JSON
PALIVANE_URL=http://localhost:8088 \
  backend/.venv/bin/python scripts/demo_video.py            # scenes -> silent.mp4
python scripts/demo_score.py                                # score.wav (needs numpy+scipy)
ffmpeg -i /tmp/warden-demo/silent.mp4 -i /tmp/warden-demo/score.wav \
  -map 0:v -map 1:a -c:v copy -c:a aac -b:a 192k -shortest \
  -movflags +faststart frontend/public/shots/demoN.mp4
```

| Script | Does |
| --- | --- |
| `demo_capture.py` | Drives a live backend over its real endpoints and writes every verdict the video shows. Refuses any non-localhost `PALIVANE_URL` (it records findings). |
| `demo_scenes.py` | The HTML for each scene. Each page exposes `setT(t)`, `t` in 0..1. |
| `demo_icons.py` | Simplified tool marks (Claude, Gemini, OpenAI, Cursor, GitHub, AWS). Drop a real SVG at `scripts/brand-icons/<key>.svg` to override — check the vendor's brand terms first. |
| `demo_video.py` | Steps `setT` frame by frame, screenshots, encodes each scene, crossfades them, and captures the closing console tour against the live console. |
| `demo_score.py` | Synthesizes the lofi bed. Section map at the bottom — match it to the cut's length. |

**What is real and what is not.** Every risk score, signal, evidence string, remediation
line, gateway error and CLI output in the video is live output from a running Warden — that
is the point of `demo_capture.py`, and why the title card can claim it. The third-party app
frames (the Claude / ChatGPT / Gemini chat windows) are simplified illustrations drawn in
`demo_scenes.py`, not screenshots of those products. Keep it that way: never make a scene
that could pass for a real screenshot of someone else's product.

**Constraints the output must hit** (`SiteChrome.jsx`'s `Clip` hard-codes 16:10, and
Cloudflare caches media by path):

- 1280x800, 25 fps, h264 + `faststart`, AAC 44.1 kHz stereo
- a **new filename** every re-cut (`demo11.mp4` → `demo12.mp4`), with `Landing.jsx` bumped
- regenerate the poster from the new file: `ffmpeg -ss 12.0 -i demoN.mp4 -frames:v 1 demo-posterN.png`
