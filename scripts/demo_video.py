"""Render the landing-page hero video.

Deterministic: each scene page exposes `setT(t)`; we step t frame by frame and screenshot,
so nothing depends on animation timing or machine speed. Frames go to ffmpeg, which
concatenates with short crossfades and mixes the score.

    ./run-local.sh                                             # terminal 1
    backend/.venv/bin/python scripts/demo_capture.py           # real verdicts
    backend/.venv/bin/python scripts/demo_video.py             # this
    # -> /tmp/palivane-demo/demo.mp4  (1280x800, 25fps, h264+faststart, AAC)

The console tour at the end is captured against the LIVE local console, not a mock.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import demo_scenes as S   # noqa: E402

FPS = 25
W, H = S.W, S.H
BASE = os.getenv("PALIVANE_URL", "http://localhost:8088").rstrip("/")
EMAIL = os.getenv("SEED_ADMIN_EMAIL", "admin@demo.local")
PASSWORD = os.getenv("SEED_ADMIN_PASSWORD", "changeme123")
WORK = os.getenv("DEMO_WORK", "/tmp/palivane-demo")
DATA = os.getenv("DEMO_DATA", f"{WORK}/verdicts.json")
OUT = os.getenv("DEMO_OUT", f"{WORK}/demo.mp4")
XFADE = 0.4           # crossfade between scenes
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def gateway_message(v: dict) -> str:
    return v.get("body", {}).get("error", {}).get("message", "")


def build_scenes(d: dict) -> list[tuple[str, str, float]]:
    """(name, html, seconds). Order tells the story: people → agents → infrastructure."""
    inputs = d["_inputs"]
    short_prompt = inputs["browser_prompt"].strip()
    scenes: list[tuple[str, str, float]] = []

    # Subtitle claims only what is true: the verdicts, scores and remediation are real
    # output from a live backend. The third-party app frames are illustrative.
    scenes.append(("title", S.title_scene(
        "PALIVANE", "One policy. Everywhere AI touches your data.",
        "Every verdict in this video came from a live Palivane instance."), 4.0))

    # 1-3 · the browser planes
    for key, brand, accent, bg, panel, items in (
        ("claude", "Claude", "#d97757", "#262624", "#30302e",
         ["Q3 revenue model", "Migration plan", "Support macros"]),
        ("chatgpt", "ChatGPT", "#10a37f", "#212121", "#2a2b32",
         ["Export totals", "SQL tuning", "Standup notes"]),
        ("gemini", "Gemini", "#4285f4", "#1b1c1d", "#242628",
         ["Billing recon", "Schema diff", "Launch checklist"]),
    ):
        scenes.append((key, S.browser_scene(
            brand, accent, bg, panel, items, short_prompt, d[key],
            key, f"{brand} in the browser"), 9.5))

    # 4 · Claude Code — the real gateway 400
    msg = gateway_message(d["claudecode"])
    scenes.append(("claudecode", S.terminal_scene(
        "dana@laptop — claude", [
            ("cmd", "$ claude \"fix the failing test in billing/reconcile.py\""),
            ("dim", ""),
            ("out", "● Reading billing/reconcile.py…"),
            ("out", "● Reading config/production.env…"),
            ("dim", ""),
            ("err", f"API Error 400: {msg}"),
            ("dim", ""),
            ("dim", "  The prompt never reached Anthropic. Palivane scored it at the"),
            ("dim", "  gateway and refused the request."),
        ], "claudecode", "Claude Code", "#d97757"), 10.0))

    # 5 · Codex CLI — the local hook blocks before anything is sent
    cx = d["codex"]
    cats = ", ".join(dict.fromkeys(s["category"] for s in cx.get("signals", [])))
    fixes = (cx.get("remediation") or [])[:2]
    scenes.append(("codex", S.terminal_scene(
        "dana@laptop — codex", [
            ("cmd", "$ codex \"wire the billing reconciler up to prod\""),
            ("dim", ""),
            ("err", f"Blocked by Palivane: {cats} in your prompt — "
                    f"risk {cx.get('risk_score')}/{cx.get('severity')}."),
            ("err", "The prompt was not sent."),
            ("dim", ""),
            ("warn", "How to fix:"),
            *[("out", f"  • {f}") for f in fixes],
        ], "codex", "Codex CLI"), 9.5))

    # 6 · Cursor — same gateway, inside the editor
    scenes.append(("cursor", S.terminal_scene(
        "billing/reconcile.py — Cursor", [
            ("cmd", "⌘K  make this read the production credentials"),
            ("dim", ""),
            ("out", "Cursor · composer"),
            ("dim", ""),
            ("err", f"Request failed: {gateway_message(d['cursor'])}"),
            ("dim", ""),
            ("dim", "  Same gateway, same policy — the editor is not a way around it."),
        ], "cursor", "Cursor", "#8b93ff"), 9.5))

    # 7 · AWS — a public bucket, scanned at rest
    aws = d["aws"]
    obj_lines = []
    for o in aws.get("objects", []):
        cats = ", ".join(dict.fromkeys(s.get("category", "") for s in o.get("signals", [])))
        ev = "; ".join(s.get("evidence", "") for s in o.get("signals", []) if s.get("evidence"))
        mark = "🔴 BLOCK" if o.get("action") == "block" else "🟠 WARN "
        obj_lines.append(("err" if o.get("action") == "block" else "warn",
                          f"  {mark}  {o.get('key')}  [{cats}]" + (f"  — {ev}" if ev else "")))
    scenes.append(("aws", S.terminal_scene(
        "ops@bastion — palivane-s3-scan", [
            ("cmd", "$ palivane-s3-scan northgate-data-exports --record"),
            ("dim", ""),
            ("warn", f"Bucket: s3://{aws.get('bucket')}  [⚠ PUBLIC BUCKET — world-readable]"),
            ("out", f"Listed {aws.get('scanned')} object(s); scanning {aws.get('scanned')}."),
            ("dim", ""),
            ("err", "  🔴 This bucket is PUBLIC and holds sensitive data — the crown-jewel case."),
            ("dim", ""),
            ("warn", f"  ⚠ Palivane flagged {len(aws.get('objects', []))} object(s):"),
            *obj_lines,
        ], "aws", "AWS S3 at rest", "#ff9900"), 10.0))

    # 8 · GitHub — an agent running in CI with production credentials
    gh = d["github"]
    wf = (gh.get("workflows") or [{}])[0]
    sig_lines = [("err", f"       · {s.get('title')} — {s.get('evidence','')}")
                 for s in wf.get("signals", [])[:5]]
    scenes.append(("github", S.terminal_scene(
        "github-actions · palivane-ci-scan", [
            ("cmd", "$ palivane-ci-scan --path . --github-oidc --fail-closed"),
            ("dim", ""),
            ("out", "  authenticating with the runner's GitHub OIDC token…"),
            ("dim", ""),
            ("warn", f"  ⚠ northgate/billing: 1 risky workflow ({wf.get('severity')}):"),
            ("err", f"    🔴 {wf.get('workflow')}"),
            *sig_lines,
        ], "github", "GitHub Actions"), 10.5))

    return scenes


def console_tour_frames(pw, out_dir: str, seconds: float) -> int:
    """Capture the LIVE console: every real tab, cursor-driven, gently scrolled."""
    import urllib.request
    req = urllib.request.Request(
        BASE + "/api/auth/login", method="POST",
        data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
        headers={"content-type": "application/json"})
    token = json.loads(urllib.request.urlopen(req, timeout=30).read())["access_token"]

    # The whole console, in the order an evaluator would click through it. Every screen is
    # the real thing rendered against the findings the earlier scenes just produced.
    tabs = ["Findings", "Discovery", "Coverage", "Fleet", "Scan log", "Agents",
            "Policies", "Simulator", "Report", "Settings", "Audit"]
    per = seconds / len(tabs)
    frames_per = max(1, int(per * FPS))
    b = pw.chromium.launch(args=["--disable-dev-shm-usage", "--no-sandbox"])   # tiny /dev/shm in CI/sandboxes breaks captureScreenshot
    page = b.new_context(viewport={"width": W, "height": H}).new_page()
    # 'palivane_token' is deliberate: it is still api.js's TOKEN_KEY. The rebrand left it
    # alone because renaming it would sign out every existing session — don't "fix" it here
    # without changing the app first.
    page.add_init_script(f"localStorage.setItem('palivane_token', {json.dumps(token)})")
    # A drawn cursor that glides to each tab, so the tour reads as someone using the app.
    page.add_init_script("""
      window.__cur = () => {
        if (document.getElementById('demo-cursor')) return;
        const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        s.id = 'demo-cursor'; s.setAttribute('viewBox', '0 0 20 26');
        s.style.cssText = 'position:fixed;z-index:2147483647;width:20px;height:26px;' +
          'pointer-events:none;filter:drop-shadow(0 2px 3px rgba(0,0,0,.6));' +
          'transition:left .45s cubic-bezier(.4,0,.2,1),top .45s cubic-bezier(.4,0,.2,1)';
        s.innerHTML = '<path d="M2 1 L2 20 L7 15.5 L10.5 23 L13.5 21.5 L10 14.5 L17 14 Z" ' +
          'fill="#fff" stroke="#111" stroke-width="1.4" stroke-linejoin="round"/>';
        document.body.appendChild(s);
      };
      window.__move = (x, y) => { window.__cur();
        const c = document.getElementById('demo-cursor');
        c.style.left = x + 'px'; c.style.top = y + 'px'; };
    """)
    page.goto(BASE, wait_until="networkidle")
    page.wait_for_timeout(1200)
    n = 0
    for tab in tabs:
        try:
            btn = page.get_by_role("button", name=tab, exact=True)
            box = btn.bounding_box()
            if box:
                page.evaluate(f"__move({box['x'] + 18}, {box['y'] + 12})")
                page.wait_for_timeout(260)           # let the cursor glide before the click
            btn.click()
            page.wait_for_timeout(500)
        except Exception as e:                       # a tab that isn't there shouldn't kill the run
            print(f"  console tour: skipping {tab} ({str(e)[:60]})")
            continue
        for i in range(frames_per):
            page.mouse.wheel(0, 7)                   # slow drift so the screen isn't static
            page.screenshot(path=f"{out_dir}/f{n:05d}.png")
            n += 1
    b.close()
    return n


def render_scene(pw, name: str, html: str, seconds: float, out_dir: str) -> int:
    path = f"{WORK}/scene_{name}.html"
    with open(path, "w") as f:
        f.write(html)
    # the emblem is referenced relatively by the title card
    shutil.copy(f"{REPO}/frontend/public/palivane-emblem.png", f"{WORK}/palivane-emblem.png")
    b = pw.chromium.launch(args=["--disable-dev-shm-usage", "--no-sandbox"])   # tiny /dev/shm in CI/sandboxes breaks captureScreenshot
    page = b.new_context(viewport={"width": W, "height": H}).new_page()
    page.goto("file://" + path)
    page.wait_for_timeout(250)
    frames = int(seconds * FPS)
    for i in range(frames):
        page.evaluate(f"setT({i / max(1, frames - 1)})")
        page.screenshot(path=f"{out_dir}/f{i:05d}.png")
    b.close()
    return frames


def encode_segment(frame_dir: str, out: str) -> None:
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-framerate", str(FPS),
                    "-i", f"{frame_dir}/f%05d.png", "-c:v", "libx264", "-preset", "medium",
                    "-crf", "20", "-pix_fmt", "yuv420p", out], check=True)


def concat_with_xfade(segments: list[str], out: str) -> None:
    """Chain xfade across every segment (ffmpeg's xfade is pairwise)."""
    if len(segments) == 1:
        shutil.copy(segments[0], out)
        return
    durs = [float(subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", s],
        capture_output=True, text=True, check=True).stdout.strip()) for s in segments]
    inputs = []
    for s in segments:
        inputs += ["-i", s]
    parts, prev, offset = [], "0:v", 0.0
    for i in range(1, len(segments)):
        offset += durs[i - 1] - XFADE
        label = f"v{i}"
        parts.append(f"[{prev}][{i}:v]xfade=transition=fade:duration={XFADE}:"
                     f"offset={offset:.3f}[{label}]")
        prev = label
    subprocess.run(["ffmpeg", "-y", "-v", "error", *inputs,
                    "-filter_complex", ";".join(parts), "-map", f"[{prev}]",
                    "-c:v", "libx264", "-preset", "medium", "-crf", "20",
                    "-pix_fmt", "yuv420p", out], check=True)


def main() -> int:
    if not os.path.exists(DATA):
        print(f"missing {DATA} — run scripts/demo_capture.py first", file=sys.stderr)
        return 1
    with open(DATA) as f:
        data = json.load(f)
    os.makedirs(WORK, exist_ok=True)
    from playwright.sync_api import sync_playwright

    scenes = build_scenes(data)
    segments = []
    with sync_playwright() as pw:
        for name, html, secs in scenes:
            fd = f"{WORK}/frames_{name}"
            shutil.rmtree(fd, ignore_errors=True)
            os.makedirs(fd)
            n = render_scene(pw, name, html, secs, fd)
            seg = f"{WORK}/seg_{name}.mp4"
            encode_segment(fd, seg)
            segments.append(seg)
            print(f"  {name:11s} {n:4d} frames  {secs:4.1f}s")
        # live console tour
        fd = f"{WORK}/frames_console"
        shutil.rmtree(fd, ignore_errors=True)
        os.makedirs(fd)
        n = console_tour_frames(pw, fd, 26.0)
        if n:
            seg = f"{WORK}/seg_console.mp4"
            encode_segment(fd, seg)
            segments.append(seg)
            print(f"  {'console':11s} {n:4d} frames  {n / FPS:4.1f}s (live)")

    silent = f"{WORK}/silent.mp4"
    concat_with_xfade(segments, silent)
    dur = float(subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", silent],
        capture_output=True, text=True, check=True).stdout.strip())
    print(f"\nvideo: {dur:.2f}s -> {silent}")
    print(f"now score it to {dur:.2f}s and mux:\n"
          f"  ffmpeg -i {silent} -i <score.wav> -map 0:v -map 1:a -c:v copy "
          f"-c:a aac -b:a 192k -shortest -movflags +faststart {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
