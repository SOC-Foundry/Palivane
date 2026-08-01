// Embed an mp4 as a base64 data URI into a self-contained HTML page, so the final
// video (with audio) can be reviewed in an Artifact before it's wired into the site.
//   node make-preview.mjs <video.mp4> <poster.png> <out.html>
import { readFileSync, writeFileSync } from "node:fs";

const [vid, poster, out] = process.argv.slice(2);
const v = readFileSync(vid).toString("base64");
const p = poster ? readFileSync(poster).toString("base64") : "";
writeFileSync(out, `<style>
  html,body{background:#05070c;margin:0;height:100%}
  .wrap{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;padding:24px}
  video{width:min(1100px,94vw);border-radius:14px;box-shadow:0 30px 80px rgba(0,0,0,.6);background:#000}
  .cap{color:#8a93a6;font:500 14px ui-sans-serif,system-ui;text-align:center}
  .cap b{color:#e6e9f0}
</style>
<div class="wrap">
  <video controls playsinline ${p ? 'poster="data:image/png;base64,' + p + '"' : ""}>
    <source src="data:video/mp4;base64,${v}" type="video/mp4">
  </video>
  <div class="cap"><b>Warden hero — final render with lo-fi score.</b> Press play (has audio). ~28s.</div>
</div>`);
console.log(`wrote ${out} (${(v.length / 1.33e6).toFixed(1)}MB inline)`);
