"""Render the MCP demo clip for the Product Hunt gallery.

Same technique as demo_video.py: a single HTML scene exposes setT(t) (t = 0..1 through the
clip); Playwright steps it frame by frame and screenshots; ffmpeg concatenates to h264. This
is a faithful *rendered mockup* of the Claude + Palivane-MCP chat — the tool names, prompts,
and result shapes are the real ones the server returns; the chat frame around them is drawn
here (like the illustrative app frames in the hero video), not a live screen capture.

    backend/.venv/bin/python scripts/mcp_video.py
    # -> marketing/mcp-demo.mp4  (1920x1080, 25fps, h264+faststart, silent)
"""
from __future__ import annotations

import os
import shutil
import subprocess

FPS = 25
SECONDS = float(os.getenv("MCP_VIDEO_SECONDS", "26"))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.getenv("MCP_VIDEO_WORK", "/tmp/palivane-mcp-video")
OUT = os.getenv("MCP_VIDEO_OUT", f"{REPO}/marketing/mcp-demo.mp4")

HTML = r"""<!doctype html><html><head><meta charset="utf-8"><style>
  :root{
    --bg:#0E100F; --bg2:#131614; --text:#E9EDEB; --heading:#FFFFFF; --muted:#9BA6A0;
    --muted2:#6E7873; --accent:#239D74; --accent2:#2FBF8F; --soft:#16241E; --line:#22271F;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{width:1280px;height:720px;background:var(--bg);color:var(--text);overflow:hidden;
    font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    -webkit-font-smoothing:antialiased}
  .stage{position:relative;width:1280px;height:720px}
  /* soft brand glow */
  .glow{position:absolute;inset:0;background:radial-gradient(60% 55% at 18% 12%,
     rgba(47,191,143,.14),transparent 60%);pointer-events:none}
  /* --- card layer (title/closing) --- */
  .card{position:absolute;inset:0;display:flex;flex-direction:column;justify-content:center;
    padding:0 120px;opacity:0}
  .kicker{font:600 15px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.28em;
    text-transform:uppercase;color:var(--accent2);margin-bottom:26px;display:flex;
    align-items:center;gap:12px}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--accent2);
    box-shadow:0 0 14px var(--accent2)}
  .card h1{font-size:62px;line-height:1.06;letter-spacing:-.02em;color:var(--heading);
    font-weight:800;max-width:960px}
  .card h1 em{font-style:normal;color:var(--accent2)}
  .card .sub{margin-top:26px;font-size:23px;color:var(--muted);max-width:720px}
  .brandrow{display:flex;align-items:center;gap:16px;margin-bottom:30px}
  .mark{width:52px;height:52px;border-radius:13px;background:linear-gradient(150deg,#2FBF8F,#239D74);
    display:flex;align-items:center;justify-content:center;box-shadow:0 10px 34px rgba(35,157,116,.4)}
  .mark svg{width:30px;height:30px}
  .word{font-size:40px;font-weight:800;letter-spacing:-.02em;color:var(--heading)}
  .meta{margin-top:40px;display:flex;align-items:center;gap:20px;font-size:20px;color:var(--muted)}
  .chip{font:600 18px/1 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent2);
    background:var(--soft);border:1px solid #244a3b;border-radius:8px;padding:11px 15px;letter-spacing:.02em}
  /* --- chat layer --- */
  .chat{position:absolute;inset:0;opacity:0;display:flex;flex-direction:column}
  .bar{height:54px;flex:none;display:flex;align-items:center;gap:12px;padding:0 22px;
    border-bottom:1px solid var(--line);background:var(--bg2)}
  .traffic{display:flex;gap:8px}.traffic i{width:12px;height:12px;border-radius:50%;background:#2a302b;display:block}
  .bar .who{margin-left:6px;font-size:14px;color:var(--muted)}
  .bar .srv{margin-left:auto;display:flex;align-items:center;gap:8px;font:600 13px/1 ui-monospace,monospace;
    color:var(--accent2);background:var(--soft);border:1px solid #244a3b;border-radius:20px;padding:7px 13px}
  .srv .live{width:8px;height:8px;border-radius:50%;background:var(--accent2);box-shadow:0 0 10px var(--accent2)}
  .scrollport{flex:1;overflow:hidden;position:relative}
  .feed{position:absolute;left:0;right:0;bottom:0;padding:26px 90px 30px;display:flex;
    flex-direction:column;gap:20px}
  .row{display:flex;gap:14px;align-items:flex-start}
  .row.u{justify-content:flex-end}
  .av{width:30px;height:30px;border-radius:8px;flex:none;display:flex;align-items:center;
    justify-content:center;font-size:15px;background:linear-gradient(150deg,#2FBF8F,#239D74)}
  .bubble{max-width:760px;font-size:21px;line-height:1.4}
  .u .bubble{background:#1b201c;border:1px solid var(--line);border-radius:14px 14px 4px 14px;
    padding:14px 18px;color:var(--heading)}
  .a .bubble{color:var(--text)}
  .cursor{display:inline-block;width:2px;height:22px;background:var(--accent2);
    margin-left:2px;vertical-align:-4px;animation:bl 1s steps(1) infinite}
  @keyframes bl{50%{opacity:0}}
  .toolchip{display:inline-flex;align-items:center;gap:9px;font:600 15px/1 ui-monospace,monospace;
    color:var(--accent2);background:var(--soft);border:1px solid #244a3b;border-radius:9px;
    padding:9px 13px;margin:2px 0 12px}
  .toolchip .plug{font-size:14px}
  .lead{font-size:19px;color:var(--muted);margin-bottom:12px}
  .result{background:var(--bg2);border:1px solid var(--line);border-radius:14px;overflow:hidden}
  .result .head{font:600 12.5px/1 ui-monospace,monospace;letter-spacing:.12em;text-transform:uppercase;
    color:var(--muted2);padding:12px 18px;border-bottom:1px solid var(--line)}
  .result ul{list-style:none;padding:8px 0}
  .result li{display:flex;align-items:center;gap:12px;padding:10px 18px;font-size:18px}
  .result li .g{color:var(--muted)}
  .sev{font:700 11px/1 ui-monospace,monospace;letter-spacing:.08em;padding:5px 8px;border-radius:6px;flex:none}
  .sev.crit{color:#ff8a8a;background:#2a1618;border:1px solid #4a2226}
  .sev.high{color:#ffc07a;background:#2a2113;border:1px solid #4a3a1f}
  .tick{color:var(--accent2);font-weight:800;flex:none;width:20px;text-align:center}
  .part{color:#ffc07a;font-weight:800;flex:none;width:20px;text-align:center}
  .foot{padding:11px 18px;font-size:15px;color:var(--muted);border-top:1px solid var(--line)}
</style></head><body>
<div class="stage">
  <div class="glow"></div>

  <div class="card" id="titleCard">
    <div class="kicker"><span class="dot"></span>Palivane · MCP</div>
    <h1>What if you never had to open the <em>security dashboard?</em></h1>
    <div class="sub">Govern AI security from the assistant you already use.</div>
  </div>

  <div class="chat" id="chat">
    <div class="bar">
      <div class="traffic"><i></i><i></i><i></i></div>
      <span class="who">Claude</span>
      <span class="srv"><span class="live"></span>palivane · MCP</span>
    </div>
    <div class="scrollport"><div class="feed" id="feed"></div></div>
  </div>

  <div class="card" id="endCard">
    <div class="brandrow">
      <span class="mark"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.5 8-8 11-4.5-3-8-6-8-11V5l8-3z" stroke="#06130E" stroke-width="1.6"/><path d="M8.5 12.2l2.5 2.5 4.5-5" stroke="#06130E" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      <span class="word">Palivane</span>
    </div>
    <h1 style="font-size:52px">AI security you run from <em>your assistant.</em></h1>
    <div class="meta"><span>palivane.io</span><span class="chip">PHLAUNCH30 · 30% off for 3 months</span></div>
  </div>
</div>

<script>
const TURNS = [
  { q:"What high-severity findings landed today, and who triggered them?",
    tool:"list_findings", lead:"Three high-severity events today:",
    head:"findings · today · severity ≥ high",
    rows:[
      ['<span class="sev crit">CRIT</span>','AWS secret key → ChatGPT','dana@acme.com · browser'],
      ['<span class="sev high">HIGH</span>','Customer PII export → Claude','sam@acme.com · browser'],
      ['<span class="sev high">HIGH</span>','Source: billing-svc → Cursor','lee@acme.com · coding tool'],
    ]},
  { q:"Which unsanctioned AI tools are in use, and what leaked to them?",
    tool:"ai_tool_inventory", lead:"Unsanctioned tools with exposure:",
    head:"shadow AI · unsanctioned",
    rows:[
      ['<span class="tick">•</span>','DeepSeek — 12 users','3 PII, 1 secret'],
      ['<span class="tick">•</span>','Perplexity — 8 users','source code ×2'],
      ['<span class="tick">•</span>','Poe — 5 users','none yet'],
    ]},
  { q:"Mark finding 4821 as triaged.",
    tool:"set_finding_status", lead:"Done.",
    head:"finding 4821",
    rows:[ ['<span class="tick">✓</span>','Status → triaged','recorded to audit'] ]},
  { q:"Are we covered for the OWASP LLM Top 10?",
    tool:"compliance_report", lead:"8 of 10 covered, 2 partial:",
    head:"OWASP LLM Top 10",
    rows:[
      ['<span class="tick">✓</span>','LLM01 Prompt Injection','covered'],
      ['<span class="tick">✓</span>','LLM02 Sensitive Disclosure','covered'],
      ['<span class="part">◐</span>','LLM06 Excessive Agency','partial'],
      ['<span class="tick">✓</span>','LLM10 Unbounded Consumption','covered'],
    ], foot:"8/10 covered · 2 partial · 0 gaps" },
];

// Timeline (seconds): title, then per turn [type Q, call, reveal, hold], then closing.
const T_TITLE=2.2, T_TYPE=1.7, T_CALL=0.6, T_REVEAL=1.7, T_HOLD=0.7, T_END=3.2;
const seg=[]; let acc=0;
function add(kind,dur,data){ seg.push({kind,dur,t0:acc,t1:acc+dur,...data}); acc+=dur; }
add('title',T_TITLE);
TURNS.forEach((tn,i)=>{ add('type',T_TYPE,{i}); add('call',T_CALL,{i}); add('reveal',T_REVEAL,{i}); add('hold',T_HOLD,{i}); });
add('end',T_END);
const TOTAL=acc;

function esc(s){return s.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function turnHTML(i, qChars, showLead, showResult, resultP){
  const tn=TURNS[i];
  const q = qChars>=tn.q.length ? esc(tn.q) : esc(tn.q.slice(0,qChars))+'<span class="cursor"></span>';
  let h = `<div class="row u"><div class="bubble">${q}</div></div>`;
  if(showLead){
    let res='';
    if(showResult){
      const rows = tn.rows.map((r,ri)=>{
        const on = (ri+1)/tn.rows.length <= resultP + 0.001;
        return on ? `<li>${r[0]}<span>${r[1]}</span><span class="g" style="margin-left:auto">${r[2]}</span></li>`:'';
      }).join('');
      const foot = (tn.foot && resultP>=0.999)?`<div class="foot">${tn.foot}</div>`:'';
      res = `<div class="result"><div class="head">${tn.head}</div><ul>${rows}</ul>${foot}</div>`;
    }
    h += `<div class="row a"><div class="av">✳</div><div class="bubble">`
       + `<div class="toolchip"><span class="plug">🔌</span>palivane · ${tn.tool}</div>`
       + `<div class="lead">${tn.lead}</div>${res}</div></div>`;
  }
  return h;
}

function setT(t){
  const gt = Math.max(0, Math.min(1, t)) * TOTAL;
  const cur = seg.find(s=> gt>=s.t0 && gt<s.t1) || seg[seg.length-1];
  const p = (gt - cur.t0)/cur.dur;                       // progress within segment

  // cards
  const titleCard=document.getElementById('titleCard'), endCard=document.getElementById('endCard'),
        chat=document.getElementById('chat');
  const fade=(x)=>Math.max(0,Math.min(1,x));
  titleCard.style.opacity = cur.kind==='title' ? fade(Math.min(p*3, (1-p)*3+0.2)) : 0;
  endCard.style.opacity   = cur.kind==='end'   ? fade(p*3) : 0;
  chat.style.opacity      = (cur.kind==='title') ? fade((p-0.7)*3)
                          : (cur.kind==='end')   ? fade(1-p*3) : 1;

  // build transcript up to the current turn
  const feed=document.getElementById('feed');
  let html='';
  const upto = ('i' in cur) ? cur.i : (cur.kind==='end'? TURNS.length-1 : -1);
  for(let i=0;i<=upto;i++){
    if(i<upto || cur.kind==='end' || cur.kind==='hold'){
      html+=turnHTML(i, TURNS[i].q.length, true, true, 1);        // fully shown
    } else if(cur.kind==='type'){
      html+=turnHTML(i, Math.floor(p*TURNS[i].q.length), false, false, 0);
    } else if(cur.kind==='call'){
      html+=turnHTML(i, TURNS[i].q.length, true, false, 0);
    } else if(cur.kind==='reveal'){
      html+=turnHTML(i, TURNS[i].q.length, true, true, p);
    }
  }
  feed.innerHTML=html;
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
