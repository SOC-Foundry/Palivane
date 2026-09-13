"""Render the agent-suite demo clip for the gallery.

Same technique as mcp_video.py / demo_video.py: one HTML scene exposes setT(t) (t = 0..1
through the clip); Playwright steps it frame by frame and screenshots; ffmpeg concatenates
to h264. A faithful *rendered mockup* of Palivane's agent features — the field names, action
verbs, and result shapes are the real ones (InvestigationReport from app/analyst.py, the
agent_attestation signal from app/main.py, the A2A graph from app/agent_graph.py); the frame
around them is drawn here, not a live screen capture.

    backend/.venv/bin/python scripts/agent_video.py
    # -> marketing/agent-demo.mp4  (1920x1080, 25fps, h264+faststart, silent)
"""
from __future__ import annotations

import os
import shutil
import subprocess

FPS = 25
SECONDS = float(os.getenv("AGENT_VIDEO_SECONDS", "27"))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.getenv("AGENT_VIDEO_WORK", "/tmp/palivane-agent-video")
OUT = os.getenv("AGENT_VIDEO_OUT", f"{REPO}/marketing/agent-demo.mp4")

HTML = r"""<!doctype html><html><head><meta charset="utf-8"><style>
  :root{
    --bg:#0E100F; --bg2:#131614; --text:#E9EDEB; --heading:#FFFFFF; --muted:#9BA6A0;
    --muted2:#6E7873; --accent:#239D74; --accent2:#2FBF8F; --soft:#16241E; --line:#22271F;
    --crit:#ff8a8a; --critbg:#2a1618; --critln:#4a2226;
    --high:#ffc07a; --highbg:#2a2113; --highln:#4a3a1f;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{width:1280px;height:720px;background:var(--bg);color:var(--text);overflow:hidden;
    font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    -webkit-font-smoothing:antialiased}
  .stage{position:relative;width:1280px;height:720px}
  .glow{position:absolute;inset:0;background:radial-gradient(60% 55% at 18% 12%,
     rgba(47,191,143,.14),transparent 60%);pointer-events:none}

  /* --- cards (title / closing) --- */
  .card{position:absolute;inset:0;display:flex;flex-direction:column;justify-content:center;
    padding:0 120px;opacity:0}
  .kicker{font:600 15px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.28em;
    text-transform:uppercase;color:var(--accent2);margin-bottom:26px;display:flex;
    align-items:center;gap:12px}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--accent2);
    box-shadow:0 0 14px var(--accent2)}
  .card h1{font-size:60px;line-height:1.07;letter-spacing:-.02em;color:var(--heading);
    font-weight:800;max-width:980px}
  .card h1 em{font-style:normal;color:var(--accent2)}
  .card .sub{margin-top:26px;font-size:23px;color:var(--muted);max-width:760px}
  .brandrow{display:flex;align-items:center;gap:16px;margin-bottom:30px}
  .mark{width:52px;height:52px;border-radius:13px;background:linear-gradient(150deg,#2FBF8F,#239D74);
    display:flex;align-items:center;justify-content:center;box-shadow:0 10px 34px rgba(35,157,116,.4)}
  .mark svg{width:30px;height:30px}
  .word{font-size:40px;font-weight:800;letter-spacing:-.02em;color:var(--heading)}
  .meta{margin-top:40px;display:flex;align-items:center;gap:20px;font-size:20px;color:var(--muted)}
  .chip{font:600 18px/1 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent2);
    background:var(--soft);border:1px solid #244a3b;border-radius:8px;padding:11px 15px;letter-spacing:.02em}

  /* --- scene shell --- */
  .scene{position:absolute;inset:0;opacity:0;display:flex;flex-direction:column;padding:54px 90px}
  .scene .eyebrow{font:600 14px/1 ui-monospace,monospace;letter-spacing:.22em;text-transform:uppercase;
    color:var(--accent2);display:flex;align-items:center;gap:11px;margin-bottom:14px}
  .scene h2{font-size:34px;font-weight:800;letter-spacing:-.02em;color:var(--heading);margin-bottom:26px}
  .scene h2 span{color:var(--muted);font-weight:600}

  /* panel + rows shared */
  .panel{background:var(--bg2);border:1px solid var(--line);border-radius:16px;overflow:hidden}
  .panel .head{font:600 12.5px/1 ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase;
    color:var(--muted2);padding:14px 20px;border-bottom:1px solid var(--line);display:flex;
    align-items:center;gap:12px}
  .sev{font:700 11px/1 ui-monospace,monospace;letter-spacing:.08em;padding:5px 8px;border-radius:6px;flex:none}
  .sev.crit{color:var(--crit);background:var(--critbg);border:1px solid var(--critln)}
  .sev.high{color:var(--high);background:var(--highbg);border:1px solid var(--highln)}

  /* scene 1: analyst report */
  .finding{display:flex;align-items:center;gap:14px;font-size:21px;color:var(--heading)}
  .finding .who{color:var(--muted);font-size:17px;margin-left:auto}
  .report{margin-top:18px}
  .report .field{padding:15px 20px;border-bottom:1px solid var(--line);opacity:0;transform:translateY(6px)}
  .report .field:last-child{border-bottom:none}
  .report .k{font:600 12px/1 ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;
    color:var(--muted2);margin-bottom:7px}
  .report .v{font-size:18.5px;line-height:1.45;color:var(--text)}
  .rec{display:flex;align-items:center;gap:14px}
  .rec .verb{font:700 15px/1 ui-monospace,monospace;letter-spacing:.06em;padding:8px 12px;border-radius:8px;
    color:var(--accent2);background:var(--soft);border:1px solid #244a3b;text-transform:uppercase}
  .rec .conf{margin-left:auto;font-size:15px;color:var(--muted)}
  .conf b{color:var(--accent2)}

  /* scene 2: attestation calls */
  .calls{display:flex;flex-direction:column;gap:16px}
  .call{display:flex;align-items:center;gap:16px;padding:18px 22px;border-radius:14px;
    background:var(--bg2);border:1px solid var(--line);opacity:0;transform:translateX(-8px)}
  .call .agent{font:600 19px/1.2 ui-sans-serif;color:var(--heading);min-width:250px}
  .call .agent small{display:block;font:500 14px/1.5 ui-monospace,monospace;color:var(--muted);margin-top:6px}
  .call .att{font:600 13px/1 ui-monospace,monospace;padding:7px 11px;border-radius:20px}
  .att.ok{color:var(--accent2);background:var(--soft);border:1px solid #244a3b}
  .att.no{color:var(--high);background:var(--highbg);border:1px solid var(--highln)}
  .verdict{margin-left:auto;font:700 15px/1 ui-monospace,monospace;letter-spacing:.04em;
    display:flex;align-items:center;gap:9px}
  .verdict.allow{color:var(--accent2)} .verdict.block{color:var(--crit)}
  .verdict .pill{width:9px;height:9px;border-radius:50%}
  .verdict.allow .pill{background:var(--accent2);box-shadow:0 0 10px var(--accent2)}
  .verdict.block .pill{background:var(--crit);box-shadow:0 0 10px var(--crit)}
  .enforce{margin-top:20px;font-size:16px;color:var(--muted);opacity:0;display:flex;align-items:center;gap:10px}
  .enforce b{color:var(--accent2)}

  /* scene 3: a2a graph */
  .graph{display:flex;flex-direction:column;gap:14px;margin-top:6px}
  .flow{display:flex;align-items:center;gap:16px;padding:16px 22px;border-radius:14px;
    background:var(--bg2);border:1px solid var(--line);opacity:0;transform:translateY(8px)}
  .node{font:600 18px/1 ui-sans-serif;color:var(--heading);display:flex;align-items:center;gap:10px}
  .node .ic{width:30px;height:30px;border-radius:8px;background:linear-gradient(150deg,#2FBF8F,#239D74);
    display:flex;align-items:center;justify-content:center;font-size:15px;color:#06130E;flex:none}
  .arrow{color:var(--muted2);font-size:22px;font-family:ui-monospace,monospace}
  .flow .cats{margin-left:auto;font-size:15px;color:var(--muted);font-family:ui-monospace,monospace}
  .flow .msgs{font-size:14px;color:var(--muted2);font-family:ui-monospace,monospace;min-width:96px;text-align:right}

  /* caption strip */
  .cap{position:absolute;left:0;right:0;bottom:0;padding:22px 90px 30px;
    background:linear-gradient(to top,rgba(14,16,15,.94),transparent);
    font-size:22px;color:var(--heading);font-weight:600;opacity:0}
  .cap em{color:var(--accent2);font-style:normal}
</style></head><body>
<div class="stage">
  <div class="glow"></div>

  <div class="card" id="titleCard">
    <div class="kicker"><span class="dot"></span>Palivane · Agents</div>
    <h1>Your agents are taking actions. Which ones should you <em>worry about?</em></h1>
    <div class="sub">Palivane investigates, attests, and maps every agent hop.</div>
  </div>

  <!-- Scene 1: the analyst -->
  <div class="scene" id="s1">
    <div class="eyebrow"><span class="dot"></span>The analyst · read-only</div>
    <h2>It investigates a finding <span>— and recommends an action.</span></h2>
    <div class="panel">
      <div class="head"><span class="sev crit">CRIT</span> finding #4821 · agent tool call</div>
      <div style="padding:18px 20px" class="finding">
        AWS secret key → external MCP tool<span class="who">agent: billing-reconciler · via ag_ token</span>
      </div>
    </div>
    <div class="panel report" id="rep">
      <div class="field"><div class="k">Summary</div><div class="v">A named agent passed an AWS secret key as a tool argument to an external MCP server during a billing run.</div></div>
      <div class="field"><div class="k">Assessment</div><div class="v">High impact: a live credential left the boundary to an unvetted tool. Treat the key as exposed.</div></div>
      <div class="field"><div class="k">Related activity</div><div class="v">Same agent had 2 prior secret-in-argument flags this week; no human approval recorded on any.</div></div>
      <div class="field"><div class="k">Recommended action</div>
        <div class="v rec"><span class="verb">keep_open</span><span class="conf">confidence <b>0.86</b></span></div></div>
    </div>
  </div>

  <!-- Scene 2: attestation -->
  <div class="scene" id="s2">
    <div class="eyebrow"><span class="dot"></span>Agent identity · attestation</div>
    <h2>Only attested agents act. <span>The rest are flagged — or blocked.</span></h2>
    <div class="calls">
      <div class="call" id="c1">
        <div class="agent">deploy-bot<small>tool: cloud_run.deploy</small></div>
        <span class="att ok">OIDC-attested</span>
        <span class="verdict allow"><span class="pill"></span>ALLOW</span>
      </div>
      <div class="call" id="c2">
        <div class="agent">billing-reconciler<small>tool: mcp.read_file · ag_ bearer token</small></div>
        <span class="att no">not OIDC-attested</span>
        <span class="verdict block"><span class="pill"></span>BLOCK</span>
      </div>
    </div>
    <div class="enforce" id="enf">
      <span>▸</span><span>Enforcement on: <b>agent_attestation</b> hard-blocks any tool call that isn't workload-identity attested.</span>
    </div>
  </div>

  <!-- Scene 3: a2a graph -->
  <div class="scene" id="s3">
    <div class="eyebrow"><span class="dot"></span>Agent-to-agent · flow graph</div>
    <h2>Which agent fed which — <span>and where risk crossed the hop.</span></h2>
    <div class="graph">
      <div class="flow" id="f1">
        <div class="node"><span class="ic">▲</span>research-agent</div><span class="arrow">→</span>
        <div class="node">summarizer</div>
        <span class="cats"><span class="sev high">HIGH</span> pii_exposure</span>
        <span class="msgs">142 msgs</span>
      </div>
      <div class="flow" id="f2">
        <div class="node"><span class="ic">▲</span>billing-reconciler</div><span class="arrow">→</span>
        <div class="node">external MCP</div>
        <span class="cats"><span class="sev crit">CRIT</span> secret_leak</span>
        <span class="msgs">7 msgs</span>
      </div>
      <div class="flow" id="f3">
        <div class="node"><span class="ic">▲</span>planner</div><span class="arrow">→</span>
        <div class="node">deploy-bot</div>
        <span class="cats">benign</span>
        <span class="msgs">61 msgs</span>
      </div>
    </div>
  </div>

  <div class="card" id="endCard">
    <div class="brandrow">
      <svg class="emblem" width="52" height="52" viewBox="0 0 100 100" aria-label="Palivane"><defs><linearGradient id="pf" x1="14" y1="6" x2="86" y2="94" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#68D6AC"/><stop offset="1" stop-color="#2C9E77"/></linearGradient><linearGradient id="pg" x1="0" y1="0" x2="0" y2="30" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#ffffff" stop-opacity=".40"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/></linearGradient><filter id="pw" x="-25%" y="-20%" width="150%" height="140%"><feDropShadow dx="0" dy="0" stdDeviation="1" flood-color="#4FD69D" flood-opacity=".35"/></filter><clipPath id="pc"><rect x="16.5" y="6" width="14" height="88" rx="7"/><rect x="34.5" y="6" width="14" height="45" rx="7"/><circle cx="58.5" cy="10" r="4.5"/><circle cx="58.5" cy="47" r="4.5"/><rect x="69.5" y="14" width="14" height="30" rx="7"/></clipPath></defs><g filter="url(#pw)" fill="url(#pf)"><rect x="16.5" y="6" width="14" height="88" rx="7"/><rect x="34.5" y="6" width="14" height="45" rx="7"/><circle cx="58.5" cy="10" r="4.5"/><circle cx="58.5" cy="47" r="4.5"/><rect x="69.5" y="14" width="14" height="30" rx="7"/></g><rect x="0" y="0" width="100" height="30" fill="url(#pg)" clip-path="url(#pc)"/></svg>
      <span class="word">Palivane</span>
    </div>
    <h1 style="font-size:52px">AI security for the <em>agent era.</em></h1>
    <div class="meta"><span>palivane.io</span><span class="chip">PHLAUNCH30 · 30% off for 3 months</span></div>
  </div>

  <div class="cap" id="cap"></div>
</div>

<script>
// Scenes with their caption + how many staged children reveal over the scene body.
const SCENES = [
  { el:'s1', cap:'The <em>analyst</em> reads the context and recommends.', reveal:'#rep .field', n:4 },
  { el:'s2', cap:'Attested agents act. The rest are <em>blocked</em>.', reveal:'.call', n:2, extra:'#enf' },
  { el:'s3', cap:'See every hop — and <em>where risk crossed</em>.', reveal:'.flow', n:3 },
];
const T_TITLE=2.6, T_IN=0.5, T_BODY=3.6, T_HOLD=1.0, T_OUT=0.4, T_END=3.4;
const seg=[]; let acc=0;
function add(kind,dur,data){ seg.push({kind,dur,t0:acc,t1:acc+dur,...data}); acc+=dur; }
add('title',T_TITLE);
SCENES.forEach((s,i)=>{ add('in',T_IN,{i}); add('body',T_BODY,{i}); add('hold',T_HOLD,{i}); add('out',T_OUT,{i}); });
add('end',T_END);
const TOTAL=acc;
const clamp=(x)=>Math.max(0,Math.min(1,x));

function showScene(idx, bodyP, sceneOpacity){
  SCENES.forEach((s,i)=>{
    const el=document.getElementById(s.el);
    el.style.opacity = (i===idx)? sceneOpacity : 0;
    if(i!==idx) return;
    const items = el.querySelectorAll(s.reveal);
    items.forEach((it,k)=>{
      // stagger reveals across the first ~75% of the body
      const start = (k/s.n)*0.75;
      const on = clamp((bodyP-start)/0.18);
      it.style.opacity = on;
      it.style.transform = `translate(${(1-on)* (s.el==='s2'? -8:0)}px, ${(1-on)*(s.el==='s2'?0:7)}px)`;
    });
    if(s.extra){
      const ex=el.querySelector(s.extra);
      ex.style.opacity = clamp((bodyP-0.72)/0.16);
    }
  });
}

function setT(t){
  const gt = clamp(t)*TOTAL;
  const cur = seg.find(s=> gt>=s.t0 && gt<s.t1) || seg[seg.length-1];
  const p = (gt-cur.t0)/cur.dur;

  const titleCard=document.getElementById('titleCard'), endCard=document.getElementById('endCard'),
        cap=document.getElementById('cap');
  titleCard.style.opacity = cur.kind==='title' ? clamp(Math.min(p*3,(1-p)*3+0.2)) : 0;
  endCard.style.opacity   = cur.kind==='end'   ? clamp(p*3) : 0;

  if('i' in cur){
    const idx=cur.i, sc=SCENES[idx];
    let op=1, bodyP=0;
    if(cur.kind==='in'){ op=clamp(p); bodyP=0; }
    else if(cur.kind==='body'){ op=1; bodyP=p; }
    else if(cur.kind==='hold'){ op=1; bodyP=1; }
    else if(cur.kind==='out'){ op=clamp(1-p); bodyP=1; }
    showScene(idx, bodyP, op);
    cap.innerHTML = sc.cap;
    cap.style.opacity = (cur.kind==='in')? clamp(p) : (cur.kind==='out')? clamp(1-p) : 1;
  } else {
    showScene(-1,0,0);
    cap.style.opacity = 0;
  }
}
window.setT=setT; setT(0);
</script></body></html>"""


def main() -> None:
    from playwright.sync_api import sync_playwright

    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK, exist_ok=True)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)

    frames = int(SECONDS * FPS)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 720},
                                device_scale_factor=1.5)   # -> 1920x1080 screenshots
        page.set_content(HTML)
        page.wait_for_function("typeof window.setT === 'function'")
        for i in range(frames):
            page.evaluate(f"setT({i / max(1, frames - 1)})")
            page.screenshot(path=f"{WORK}/f_{i:05d}.png")
        browser.close()
    print(f"captured {frames} frames")

    subprocess.run(
        ["ffmpeg", "-y", "-v", "error", "-framerate", str(FPS),
         "-i", f"{WORK}/f_%05d.png",
         "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart", OUT],
        check=True)
    size = os.path.getsize(OUT)
    print(f"wrote {OUT} ({size/1e6:.1f} MB, {SECONDS:.0f}s, 1920x1080, {FPS}fps)")


if __name__ == "__main__":
    main()
