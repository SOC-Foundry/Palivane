# Warden hero video generator

Self-contained pipeline that produces the landing-page hero clip
(`frontend/public/shots/demo12.mp4`, ~40s) — the one that shows a secret, customer PII, and
source code each being **blocked as someone pastes it into Claude, Gemini, and ChatGPT**,
then landing in the Warden console.

Everything is synthesized/animated in code (no screen recordings, no audio samples), so a
re-render is deterministic and the whole thing is editable.

## Files

| File | What it is |
|------|------------|
| `hero.html` | The animation. A fixed 1280×800 stage driven by a deterministic `render(t)` timeline (scenes, cursor, typing, block banners, console). Loops live in a browser; `?capture=1&t=<s>` renders one fixed frame. |
| `soundtrack.py` | The lo-fi score — Rhodes EP on a ii–V–I–vi loop, swung boom-bap drums, sub bass, vinyl crackle, tape low-pass + sidechain. Writes `soundtrack.wav`. Needs numpy. |
| `render.mjs` | Drives system Chrome frame-by-frame (puppeteer-core), screenshots each frame, then ffmpeg-encodes the PNG sequence + `soundtrack.wav` into `hero.mp4`. |
| `make-artifact.mjs` | Rewrites `hero.html` into `hero.artifact.html` (body-only + responsive scaler) for previewing the animation in a Claude Artifact. |
| `make-preview.mjs` | Inlines an mp4 as a base64 data-URI HTML page, to review the final (with audio) before shipping. |

## Rebuild

```bash
python3 -m venv .venv && .venv/bin/pip install numpy   # first time
npm install                                            # first time (puppeteer-core)

.venv/bin/python soundtrack.py     # -> soundtrack.wav
node render.mjs                    # -> hero.mp4  (frames in ./frames)
```

Then copy into the site (bump the number to bust the CDN cache) and grab a poster frame:

```bash
cp hero.mp4 ../../frontend/public/shots/demo12.mp4
cp frames/f_00186.png ../../frontend/public/shots/demo-poster9.png   # ~t=6.2, the Claude block
# update the <Clip src/poster> in frontend/src/components/Landing.jsx
```

## Editing the content

- **Scenes / copy / leak examples:** the `AI` array and `CON` rows near the top of the
  `<script>` in `hero.html`. Timings are `start` + `SCENE_DUR`; total is `S.DURATION`.
- **Music:** `PROG` (chords), `BPM`, and the per-instrument synths in `soundtrack.py`.
- Keep `soundtrack.py`'s `DUR` and `hero.html`'s `S.DURATION` in sync.

Build artifacts (`node_modules/`, `.venv/`, `frames/`, `*.wav`, `hero.mp4`, the generated
preview HTML) are git-ignored — only the source is committed.
