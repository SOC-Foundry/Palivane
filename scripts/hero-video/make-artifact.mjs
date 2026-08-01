// Transform hero.html (a standalone 1280x800 doc used for frame capture) into
// hero.artifact.html — body-content only (no doctype/head/body), wrapped in a
// responsive scaler so it previews at any width inside the Artifact skeleton.
import { readFileSync, writeFileSync } from "node:fs";

const src = readFileSync(new URL("./hero.html", import.meta.url), "utf8");
const head = src.split("<script>")[0];                 // everything before the JS
const style = head.match(/<style>[\s\S]*?<\/style>/)[0];
const stage = head.slice(head.indexOf('<div id="stage">')).trim();  // stage markup to EOF-of-head
const script = ("<script>" + src.split("<script>").slice(1).join("<script>"))
  .replace(/(?:\s*<\/(?:body|html)>)+\s*$/gi, "").trimEnd();

const out = `${style}
<style>
  html,body{background:#05070c}
  #fit{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;overflow:hidden}
  #fit #stage{transform-origin:center center}
  .hint{position:fixed;left:0;right:0;bottom:14px;text-align:center;color:#5b6577;
    font:500 13px ui-sans-serif,system-ui;letter-spacing:.02em}
</style>
<div id="fit">
  ${stage}
</div>
<div class="hint">Hero animation preview · loops automatically · 1280×800 · ~28s</div>
${script}
<script>
  // scale the fixed-size stage to fit the viewport
  const fit=()=>{const s=Math.min(innerWidth/1280,(innerHeight-40)/800);
    document.getElementById('stage').style.transform='scale('+s+')';};
  addEventListener('resize',fit); fit();
</script>
`;
writeFileSync(new URL("./hero.artifact.html", import.meta.url), out);
console.log("wrote hero.artifact.html");
