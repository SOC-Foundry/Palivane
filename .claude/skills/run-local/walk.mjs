// Walk every Palivane console tab as admin, capturing console errors, failed /api
// calls, headings, and a screenshot per tab. Writes walk-results.json + shots/ to cwd.
//   node walk.mjs            # BASE defaults to http://127.0.0.1:8099
//   BASE=http://127.0.0.1:9000 node walk.mjs
// Needs playwright-core (frontend/node_modules) + system Chrome.
import fs from "fs";
import path from "path";
import { createRequire } from "module";

// playwright-core isn't a repo dependency and ESM bare imports ignore cwd/NODE_PATH,
// so resolve it from whichever node_modules actually has it: an explicit PW_CORE anchor,
// the cwd, the repo's frontend/, or the machine's VS Code bundle. If none resolve, the
// hint below tells you to install it. Anchor a require at each candidate's node_modules
// parent; createRequire walks upward from there.
const skillDir = path.dirname(new URL(import.meta.url).pathname);
const repo = path.resolve(skillDir, "../../..");
function loadChromium() {
  const anchors = [
    process.env.PW_CORE,
    path.join(process.cwd(), "x.js"),
    path.join(repo, "frontend", "x.js"),
    "/usr/share/code/resources/app/x.js",
  ].filter(Boolean);
  for (const a of anchors) {
    try { return createRequire(a)("playwright-core").chromium; } catch { /* try next */ }
  }
  console.error("playwright-core not found. Install it, e.g.:  (cd frontend && npm i -D playwright-core)\n" +
                "or point PW_CORE at a node_modules that has it:  PW_CORE=/path/to/node_modules/x.js node walk.mjs");
  process.exit(2);
}
const chromium = loadChromium();

const BASE = process.env.BASE || "http://127.0.0.1:8099";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@demo.local";
const ADMIN_PW = process.env.ADMIN_PW || "changeme123";
const ORG = process.env.ORG || "demo";
const SHOTS = `${process.cwd()}/shots`;
fs.mkdirSync(SHOTS, { recursive: true });

// Connect's "no model provider key" notice uses .error styling but is informational
// and expected in local dev without an Anthropic key. Don't count it as a failure.
const BENIGN_UI = [/No model provider key set/i];

const b = await chromium.launch({ executablePath: "/usr/bin/google-chrome-stable", args: ["--no-sandbox", "--headless=new"] });
const ctx = await b.newContext({ viewport: { width: 1440, height: 950 } });
const page = await ctx.newPage();

const consoleErrs = [];
const netErrs = [];
page.on("console", (m) => { if (m.type() === "error") consoleErrs.push(m.text().slice(0, 200)); });
page.on("response", (r) => { if (r.url().includes("/api/") && r.status() >= 400) netErrs.push(`${r.status()} ${r.url().replace(BASE, "")}`); });

await page.goto(`${BASE}/#signin`, { waitUntil: "networkidle" });
await page.fill('input[placeholder*="organization"]', ORG);
await page.fill('input[type="email"]', ADMIN_EMAIL);
await page.fill('input[type="password"]', ADMIN_PW);
await page.click("button.primary-btn");
await page.waitForTimeout(2500);

const navCount = await page.$$eval(".nav-item", (els) => els.length).catch(() => 0);
if (!navCount) {
  const errText = await page.$eval(".error", (e) => e.textContent).catch(() => "(no .error)");
  console.log(JSON.stringify({ loginFailed: true, error: errText, url: page.url() }));
  await page.screenshot({ path: `${SHOTS}/login-fail.png` });
  await b.close();
  process.exit(1);
}

const navLabels = await page.$$eval(".nav-item", (els) => els.map((e) => e.textContent.trim()));
console.log(JSON.stringify({ login: "ok", tabs: navLabels }));

const results = [];
for (let i = 0; i < navLabels.length; i++) {
  const label = navLabels[i];
  const beforeC = consoleErrs.length, beforeN = netErrs.length;
  const items = await page.$$(".nav-item");
  await items[i].click();
  await page.waitForTimeout(1200);
  await page.waitForLoadState("networkidle").catch(() => {});
  const info = await page.evaluate(() => {
    const main = document.querySelector(".main, main, .content, .console-main") || document.body;
    const h = main.querySelector("h1,h2,h3");
    const err = [...document.querySelectorAll(".error, .banner-error")].map((e) => e.textContent.trim()).filter(Boolean);
    const empty = [...document.querySelectorAll(".empty")].map((e) => e.textContent.trim().slice(0, 80));
    return { heading: h ? h.textContent.trim().slice(0, 60) : "(none)", textLen: main.innerText.replace(/\s+/g, " ").trim().length, errors: err, empty };
  });
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  await page.screenshot({ path: `${SHOTS}/tab-${String(i).padStart(2, "0")}-${slug}.png` });
  const uiErrors = info.errors.filter((t) => !BENIGN_UI.some((re) => re.test(t)));
  const r = { label, heading: info.heading, textLen: info.textLen, uiErrors, empty: info.empty, consoleErr: consoleErrs.slice(beforeC), netErr: netErrs.slice(beforeN) };
  results.push(r);
  console.log(JSON.stringify({ tab: label, heading: info.heading, textLen: info.textLen, uiErrors, netErr: r.netErr, consoleErr: r.consoleErr.length }));
}

fs.writeFileSync(`${process.cwd()}/walk-results.json`, JSON.stringify(results, null, 2));
const bad = results.filter((r) => r.uiErrors.length || r.consoleErr.length || r.netErr.length || r.textLen < 40);
console.log("\n=== SUMMARY ===");
console.log(`tabs walked: ${results.length}`);
console.log(`tabs with issues: ${bad.length}`);
for (const r of bad) console.log(`  WARN ${r.label}: ui=${JSON.stringify(r.uiErrors)} net=${JSON.stringify(r.netErr)} console=${r.consoleErr.length} textLen=${r.textLen}`);

await b.close();
process.exit(bad.length ? 1 : 0);
