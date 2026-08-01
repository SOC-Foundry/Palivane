"""HTML for each hero-video scene.

Every scene is a self-contained page rendered at 1280x800 and driven by one global,
`setT(t)`, where t is 0..1 through the scene — so the recorder can step frames
deterministically instead of racing a CSS animation.

The block UI is the extension's OWN markup (see extension/content.js showBlockModal) and
the terminal text is the backend's real response, so what the video shows is what the
product does. Only the third-party app frames around them are drawn here: recognisable
enough to place the scene, deliberately simplified, never pixel-copies of someone else's
product.
"""
from __future__ import annotations

import html
import json

from demo_icons import icon

W, H = 1280, 800

CATEGORY_LABELS = {   # mirrors extension/content.js
    "secret_leak": "Credentials / secrets",
    "pii_exposure": "Personal data (PII)",
    "source_code_leak": "Proprietary code / confidential material",
    "confidential_data": "Confidential business data",
    "prompt_injection": "Prompt injection",
    "jailbreak": "Jailbreak attempt",
    "data_exfiltration": "Data-exfiltration attempt",
    "unsanctioned_ai": "Unsanctioned AI tool",
    "unsafe_autonomy": "Unsafe agent autonomy (YOLO)",
    "dangerous_command": "Dangerous command",
    "agent_authz": "Agent acted outside its role",
    "ci_workflow_risk": "CI workflow risk",
    "credential_at_rest": "Credential at rest",
}

BASE_CSS = f"""
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ width: {W}px; height: {H}px; overflow: hidden;
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }}
.scene {{ position: relative; width: {W}px; height: {H}px; }}
.badge {{ position: absolute; right: 28px; top: 24px; z-index: 60; display: flex;
  align-items: center; gap: 9px; padding: 8px 15px 8px 9px; border-radius: 999px;
  background: rgba(9,13,21,.82); border: 1px solid rgba(255,255,255,.16);
  color: #e8eefc; font-size: 13.5px; font-weight: 650; backdrop-filter: blur(6px); }}
.badge .bicon {{ display: grid; place-items: center; width: 22px; height: 22px; }}
.cursor {{ position: absolute; z-index: 90; width: 20px; height: 26px; pointer-events: none;
  filter: drop-shadow(0 2px 3px rgba(0,0,0,.6)); }}
.fadein {{ opacity: 0; }}
"""

# The extension's real modal, transplanted verbatim in structure/styling.
def block_modal(verdict: dict) -> str:
    seen, sigs = set(), []
    for s in verdict.get("signals", []):
        c = s.get("category")
        if c and c not in seen:
            seen.add(c)
            sigs.append(s)
    sigs.sort(key=lambda s: 1 if s["category"] == "unsanctioned_ai" else 0)
    rows = "".join(
        f'<li style="margin:4px 0">{html.escape(CATEGORY_LABELS.get(s["category"], s["category"]))}'
        + (f' — <span style="opacity:.7">{html.escape(s.get("evidence", ""))}</span>'
           if s.get("evidence") else "") + "</li>"
        for s in sigs)
    labels = [CATEGORY_LABELS.get(s["category"], s["category"]).lower()
              for s in sigs if s["category"] != "unsanctioned_ai"]
    reason = ("sensitive content" if not labels else labels[0] if len(labels) == 1
              else ", ".join(labels[:-1]) + " and " + labels[-1])
    fixes = (verdict.get("remediation") or [])[:3]
    fix = ("" if not fixes else
           '<div style="margin-top:14px;padding:11px 13px;background:rgba(77,163,255,.08);'
           'border:1px solid rgba(77,163,255,.32);border-radius:10px">'
           '<div style="font-weight:700;color:#9ecbff;font-size:13px">How to fix</div>'
           '<ul style="margin:6px 0 0;padding-left:18px;color:#c4ccdb;font-size:12.5px">'
           + "".join(f'<li style="margin:3px 0">{html.escape(f)}</li>' for f in fixes)
           + "</ul></div>")
    risk = f'{verdict.get("risk_score", "?")}/{str(verdict.get("severity", "")).upper()}'
    return f"""
    <div id="modal" style="position:absolute;inset:0;z-index:70;background:rgba(10,12,18,.55);
        backdrop-filter:blur(2px);display:flex;align-items:center;justify-content:center;
        opacity:0">
      <div id="modalcard" style="width:460px;background:#151926;color:#e6e9f0;
          border:1px solid #2a3346;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);
          padding:22px 24px;transform:translateY(10px) scale(.97)">
        <div style="display:flex;align-items:center;gap:10px;font-size:17px;font-weight:800">
          <span style="color:#ff5d6c">&#128737;</span> Warden blocked this message
        </div>
        <p style="color:#c4ccdb;margin:12px 0 6px">
          It was <strong>not sent</strong> to the AI tool because it contained {html.escape(reason)}.
        </p>
        <ul style="margin:8px 0 4px;padding-left:18px;color:#e6e9f0">{rows}</ul>
        {fix}
        <div style="color:#8a93a6;font-size:12px;margin-top:12px">
          risk {risk} · the AI tool may show a "failed to send" error — that's the block working.
        </div>
        <div style="display:flex;gap:8px;margin-top:18px">
          <div style="flex:1;padding:11px;border-radius:8px;background:#4da3ff;color:#04101f;
              font-weight:700;font-size:14px;text-align:center">Edit my message</div>
          <div style="padding:11px 14px;border:1px solid #2a3346;border-radius:8px;
              color:#c4ccdb;font-size:13px">Request exception</div>
        </div>
      </div>
    </div>"""


CURSOR_SVG = """<svg class="cursor" id="cur" viewBox="0 0 20 26" style="left:0;top:0">
  <path d="M2 1 L2 20 L7 15.5 L10.5 23 L13.5 21.5 L10 14.5 L17 14 Z"
        fill="#fff" stroke="#111" stroke-width="1.4" stroke-linejoin="round"/></svg>"""


def _chat_app(brand: str, accent: str, bg: str, panel: str, sidebar_items: list[str],
              placeholder: str, icon_key: str = "") -> str:
    """A generic assistant-app frame: sidebar, thread, composer. Recognisable by name and
    accent colour, intentionally not a facsimile of anyone's product."""
    items = "".join(
        f'<div style="padding:8px 11px;border-radius:8px;color:#9aa4b8;font-size:13px;'
        f'{"background:rgba(255,255,255,.06);color:#e8eefc" if i == 0 else ""}">{html.escape(s)}</div>'
        for i, s in enumerate(sidebar_items))
    return f"""
    <div style="position:absolute;inset:0;background:{bg};display:flex">
      <div style="width:236px;background:{panel};border-right:1px solid rgba(255,255,255,.07);
          padding:16px 12px;display:flex;flex-direction:column;gap:6px">
        <div style="display:flex;align-items:center;gap:9px;padding:4px 6px 14px">
          <div style="width:26px;height:26px;display:grid;place-items:center">
            {icon(icon_key or "chatgpt", 24, accent)}</div>
          <div style="color:#e8eefc;font-weight:700;font-size:14.5px">{html.escape(brand)}</div>
        </div>
        <div style="padding:9px 11px;border:1px solid rgba(255,255,255,.14);border-radius:9px;
            color:#c9d3e6;font-size:13px;margin-bottom:8px">+ New chat</div>
        {items}
      </div>
      <div style="flex:1;display:flex;flex-direction:column">
        <div style="flex:1;padding:34px 60px;overflow:hidden">
          <div style="max-width:720px;margin:0 auto">
            <div style="display:flex;gap:12px;margin-bottom:22px">
              <div style="width:28px;height:28px;flex:none;display:grid;place-items:center">
                {icon(icon_key or "chatgpt", 24, accent)}</div>
              <div style="color:#c9d3e6;font-size:14.5px;line-height:1.65">
                Sure — paste the export and I'll take a look at the totals.</div>
            </div>
          </div>
        </div>
        <div style="padding:0 60px 40px">
          <div style="max-width:720px;margin:0 auto;border:1px solid rgba(255,255,255,.14);
              border-radius:14px;background:{panel};padding:15px 17px;min-height:118px">
            <div id="typed" style="color:#e8eefc;font-size:13.5px;white-space:pre-wrap;
                font-family:ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.55"></div>
            <div id="ph" style="color:#6b7689;font-size:14px">{html.escape(placeholder)}</div>
            <div style="display:flex;justify-content:flex-end;margin-top:12px">
              <div id="send" style="width:32px;height:32px;border-radius:8px;background:{accent};
                  display:grid;place-items:center;color:#fff;font-size:15px">&#8593;</div>
            </div>
          </div>
        </div>
      </div>
    </div>"""


def _badge(icon_key: str, label: str, accent: str = "#e8eefc") -> str:
    return (f'<div class="badge"><span class="bicon">{icon(icon_key, 20, accent)}</span>'
            f'{html.escape(label)}</div>')


def browser_scene(brand: str, accent: str, bg: str, panel: str, items: list[str],
                  prompt: str, verdict: dict, icon_key: str, badge_label: str) -> str:
    """Typing a sensitive prompt into an assistant, then the extension's block modal."""
    return f"""<!doctype html><meta charset="utf-8"><style>{BASE_CSS}</style>
<div class="scene" style="background:{bg}">
  {_chat_app(brand, accent, bg, panel, items, "Message " + brand + "…", icon_key)}
  {block_modal(verdict)}
  {_badge(icon_key, badge_label, accent)}
  {CURSOR_SVG}
</div>
<script>
const PROMPT = {json.dumps(prompt)};
const typed = document.getElementById('typed'), ph = document.getElementById('ph');
const modal = document.getElementById('modal'), card = document.getElementById('modalcard');
const cur = document.getElementById('cur'), send = document.getElementById('send');
function ease(x) {{ return x < .5 ? 2*x*x : 1 - Math.pow(-2*x+2, 2)/2; }}
function setT(t) {{
  // 0.00-0.55 type · 0.55-0.62 cursor to send · 0.62-0.70 click · 0.70-1.0 modal
  const typeP = Math.min(1, t / 0.55);
  const n = Math.floor(ease(typeP) * PROMPT.length);
  typed.textContent = PROMPT.slice(0, n);
  ph.style.display = n > 0 ? 'none' : 'block';
  const sr = send.getBoundingClientRect();
  const p0 = {{x: 250, y: 600}}, p1 = {{x: sr.left + 14, y: sr.top + 14}};
  const mv = Math.max(0, Math.min(1, (t - 0.55) / 0.09));
  cur.style.left = (p0.x + (p1.x - p0.x) * ease(mv)) + 'px';
  cur.style.top  = (p0.y + (p1.y - p0.y) * ease(mv)) + 'px';
  send.style.transform = (t > 0.645 && t < 0.70) ? 'scale(.9)' : 'scale(1)';
  const m = Math.max(0, Math.min(1, (t - 0.68) / 0.10));
  modal.style.opacity = m;
  card.style.transform = `translateY(${{10 * (1 - ease(m))}}px) scale(${{0.97 + 0.03 * ease(m)}})`;
  cur.style.opacity = t > 0.72 ? 0 : 1;
}}
setT(0);
</script>"""


def terminal_scene(title: str, lines: list[tuple[str, str]], icon_key: str,
                   badge_label: str, accent: str = "#e8eefc") -> str:
    """A terminal that types its command, then prints real output line by line.
    `lines` is (kind, text): kind in {cmd, out, err, ok, dim}."""
    palette = {"cmd": "#e8eefc", "out": "#c4ccdb", "err": "#ff8a8a", "ok": "#6ee7a8",
               "dim": "#8a93a6", "warn": "#ffcf6b"}
    rendered = "".join(
        f'<div class="ln" data-kind="{k}" style="color:{palette[k]};white-space:pre-wrap">'
        f'{html.escape(t) if t else "&nbsp;"}</div>' for k, t in lines)
    return f"""<!doctype html><meta charset="utf-8"><style>{BASE_CSS}
/* Height follows the content (min 300px) and the window is centred, so a short scan
   doesn't leave two-thirds of the frame empty. */
.term {{ position:absolute; left:46px; right:46px; top:50%; transform:translateY(-50%);
  min-height:300px; max-height:700px; background:#0b0f17;
  border:1px solid #222a3a; border-radius:12px; box-shadow:0 24px 70px rgba(0,0,0,.55);
  display:flex; flex-direction:column; overflow:hidden; }}
.tbar {{ display:flex; align-items:center; gap:8px; padding:11px 14px;
  background:#121826; border-bottom:1px solid #222a3a; }}
.tbar i {{ width:11px; height:11px; border-radius:50%; display:block; }}
.tbody {{ padding:18px 22px; font:13.5px/1.62 ui-monospace,SFMono-Regular,Menlo,monospace;
  overflow:hidden; flex:1; }}
.ln {{ opacity:0; }}
</style>
<div class="scene" style="background:#070a11">
  <div class="term">
    <div class="tbar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i>
      <i style="background:#28c840"></i>
      <span style="color:#8a93a6;font-size:12.5px;margin-left:8px">{html.escape(title)}</span></div>
    <div class="tbody" id="body">{rendered}</div>
  </div>
  {_badge(icon_key, badge_label, accent)}
</div>
<script>
const lns = [...document.querySelectorAll('.ln')];
// The command line types out; output lines appear one after another.
const cmdEl = lns[0], cmdText = cmdEl.textContent;
cmdEl.textContent = '';
function setT(t) {{
  const typeP = Math.min(1, t / 0.18);
  cmdEl.style.opacity = 1;
  cmdEl.textContent = cmdText.slice(0, Math.floor(typeP * cmdText.length));
  const rest = lns.slice(1);
  const revealFrom = 0.21, revealTo = 0.78;
  const p = Math.max(0, Math.min(1, (t - revealFrom) / (revealTo - revealFrom)));
  const shown = Math.round(p * rest.length);
  rest.forEach((el, i) => {{ el.style.opacity = i < shown ? 1 : 0; }});
}}
setT(0);
</script>"""


def title_scene(kicker: str, headline: str, sub: str) -> str:
    return f"""<!doctype html><meta charset="utf-8"><style>{BASE_CSS}</style>
<div class="scene" style="background:radial-gradient(1100px 620px at 50% 40%,#161d33,#080b13)">
  <div id="wrap" style="position:absolute;inset:0;display:flex;flex-direction:column;
      align-items:center;justify-content:center;gap:16px;opacity:0">
    <img src="warden-emblem.png" style="height:76px;width:auto" />
    <div style="color:#7c6cff;font-size:13px;font-weight:800;letter-spacing:.22em">
      {html.escape(kicker)}</div>
    <div style="color:#eef2ff;font-size:44px;font-weight:800;letter-spacing:-1px;text-align:center">
      {html.escape(headline)}</div>
    <div style="color:#9aa4b8;font-size:17px;text-align:center;max-width:760px">
      {html.escape(sub)}</div>
  </div>
</div>
<script>
const wrap = document.getElementById('wrap');
function setT(t) {{
  const inP = Math.min(1, t / 0.22), outP = Math.max(0, (t - 0.84) / 0.16);
  wrap.style.opacity = Math.min(inP, 1 - outP);
  wrap.style.transform = `translateY(${{(1 - inP) * 14}}px)`;
}}
setT(0);
</script>"""
