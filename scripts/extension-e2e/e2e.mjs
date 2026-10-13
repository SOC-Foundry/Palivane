#!/usr/bin/env node
// Real-browser regression test for the extension. It starts a throwaway Palivane backend, a fake
// claude.ai / chatgpt.com (the real hostnames, mapped to localhost with a throwaway certificate, so
// the shipped manifest injects exactly as it does in production), loads the UNMODIFIED extension
// into Chromium, and puts a message with an SSN through it in every way a person or a page can:
// each org setting, each way a page can build a request body, a slow or missing backend, and an
// extension that was updated under an open tab. It asserts both what the person sees and whether
// the message actually ARRIVED at the "AI site", because a block is only a block if it did not.
//
//   node scripts/extension-e2e/e2e.mjs
//
// Needs: the backend's Python environment (PALIVANE_PYTHON, default <repo>/.venv/bin/python), openssl,
// and a Chromium that can load an unpacked extension. Playwright's own works (`npx playwright install
// chromium` in frontend/); branded Chrome 137+ ignores --load-extension. Point PALIVANE_CHROMIUM at a
// specific binary if Playwright's default revision is not the one you have.
//
// Set PALIVANE_EXTENSION to a different extension folder to run the same checks against another build.
// Not wired into CI: it needs a browser download. Run it before shipping an extension change.
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const EXT = path.resolve(process.env.PALIVANE_EXTENSION || path.join(root, "extension"));   // override to test another build
const { chromium } = await import(path.join(root, "frontend/node_modules/playwright-core/index.mjs"));

const PY = process.env.PALIVANE_PYTHON || (fs.existsSync(path.join(root, ".venv/bin/python")) ? path.join(root, ".venv/bin/python") : "python3");
const CHROMIUM = process.env.PALIVANE_CHROMIUM || chromium.executablePath();
if (!fs.existsSync(CHROMIUM)) {
  console.error(`No Chromium at ${CHROMIUM}. Run \`npx playwright install chromium\` in frontend/, or set PALIVANE_CHROMIUM.`);
  process.exit(2);
}
const PORT = { palivane: 18099, slow: 18098, https: 18443, ctl: 18444 };
const PALI = `http://127.0.0.1:${PORT.palivane}`;
const SLOW = `http://127.0.0.1:${PORT.slow}`;
const CTL = `http://127.0.0.1:${PORT.ctl}`;
const SSN = "My SSN is 078-05-1120";           // the SSA's published example, not a real person
const AWS = "use AKIAIOSFODNN7EXAMPLE to deploy"; // AWS's documented example key

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "palivane-ext-e2e-"));
const children = [];
const results = [];
const check = (name, ok, extra = "") => { results.push({ name, ok: !!ok, extra }); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function start(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: ["ignore", "ignore", fs.openSync(path.join(tmp, "children.log"), "a")], ...opts });
  children.push(p);
  return p;
}
async function until(fn, what, ms = 30000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { try { if (await fn()) return; } catch (_) { /* not yet */ } await sleep(250); }
  throw new Error(`timed out waiting for ${what} (see ${path.join(tmp, "children.log")})`);
}
async function api(method, url, body, token) {
  const r = await fetch(PALI + url, { method, headers: { "content-type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error(`${method} ${url} -> ${r.status} ${await r.text()}`);
  return r.json();
}

let ctx;
try {
  // ---- the world: a backend, two fake sites, a slow proxy -----------------------------------
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(tmp, "key.pem"), "-out", path.join(tmp, "cert.pem"),
    "-days", "2", "-subj", "/CN=claude.ai", "-addext", "subjectAltName=DNS:claude.ai,DNS:chatgpt.com,DNS:gemini.google.com"], { stdio: "ignore" });
  const benv = { ...process.env, DATABASE_URL: `sqlite:///${tmp}/e2e.db`, PALIVANE_STATE_DIR: path.join(tmp, "state"), PALIVANE_STATIC_DIR: "" };
  const backend = path.join(root, "backend");
  execFileSync(PY, ["-m", "alembic", "upgrade", "head"], { cwd: backend, env: benv, stdio: "ignore" });
  execFileSync(PY, ["-m", "app.seed"], { cwd: backend, env: benv, stdio: "ignore" });
  start(PY, ["-m", "uvicorn", "app.main:app", "--port", String(PORT.palivane), "--log-level", "warning"], { cwd: backend, env: benv });
  start("python3", [path.join(here, "chat-site.py"), "--https-port", String(PORT.https), "--ctl-port", String(PORT.ctl),
    "--cert", path.join(tmp, "cert.pem"), "--key", path.join(tmp, "key.pem")]);
  start("python3", [path.join(here, "slow-proxy.py"), "--port", String(PORT.slow), "--target", PALI, "--delay", "5"]);
  await until(async () => (await fetch(PALI + "/api/health")).ok, "the backend");
  await until(async () => (await fetch(CTL + "/__log")).ok, "the fake site");

  const admin = (await api("POST", "/api/auth/login", { email: "admin@demo.local", password: "changeme123" })).access_token;
  const newKey = async (actor) => (await api("POST", "/api/apikeys", { label: "e2e", actor }, admin)).token;
  const key = await newKey("dev@demo.local");
  const tenant = (patch) => api("PATCH", "/api/tenant", patch, admin);
  await tenant({ sanctioned_ai_tools: "", redact_mode: "off", client_enforce: "inherit" });
  // the first scan on a fresh process is the slow one; warm it so the 4s budget is about the scenario
  await fetch(PALI + "/api/ingest/ai-usage", { method: "POST", headers: { "content-type": "application/json", "X-Palivane-Token": key }, body: JSON.stringify({ content: SSN, destination: "https://claude.ai" }) });

  // ---- the browser ---------------------------------------------------------------------------
  ctx = await chromium.launchPersistentContext(path.join(tmp, "profile"), {
    executablePath: CHROMIUM, headless: true,
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--ignore-certificate-errors",
      `--host-resolver-rules=MAP claude.ai 127.0.0.1:${PORT.https}, MAP chatgpt.com 127.0.0.1:${PORT.https}, MAP gemini.google.com 127.0.0.1:${PORT.https}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 20000 });
  const extId = sw.url().split("/")[2];
  const version = await sw.evaluate(() => chrome.runtime.getManifest().version);
  console.log(`extension ${version} loaded from ${path.relative(root, EXT)}`);

  // One message through the extension. Returns what the person saw and whether it got out.
  async function send(label, { host = "claude.ai", text = SSN, mode = "string", ext = {}, patch = null, extraWait = 0 } = {}) {
    if (patch) await tenant(patch);
    await fetch(CTL + "/__log", { method: "DELETE" });
    await sw.evaluate((c) => chrome.storage.sync.set(c), { backendUrl: PALI, token: key, user: "dev@demo.local", enforce: true, ...ext });
    await sw.evaluate(() => chrome.storage.local.set({ lastVerdict: null, lastSkip: null, blockCount: 0 }));
    const page = await ctx.newPage();
    await page.goto(`https://${host}/?mode=${mode}`);
    await page.fill("#prompt", text);
    await page.click("#send");
    await page.waitForFunction(() => document.getElementById("out").textContent !== "", null, { timeout: 20000 }).catch(() => {});
    await page.waitForTimeout(500 + extraWait);
    const ui = await page.evaluate(() => ({
      modal: !!document.getElementById("palivane-modal"),
      title: (document.querySelector("#palivane-modal [role=alertdialog] > div")?.innerText || "").replace(/\s+/g, " ").trim(),
      clean: document.getElementById("palivane-clean")?.innerText || "",
      banner: (document.getElementById("palivane-banner")?.innerText || "").replace(/\s+/g, " "),
      notice: (document.getElementById("palivane-notice")?.innerText || "").replace(/\s+/g, " "),
    }));
    const arrived = (await (await fetch(CTL + "/__log")).json()).some((x) => x.body.includes(text.slice(-10)));
    await page.close();
    return { label, ...ui, arrived };
  }
  const blocked = (r) => r.modal && !r.clean && /blocked/.test(r.title) && !r.arrived;
  const held = (r) => r.modal && /held/.test(r.title) && /redacted/.test(r.clean) && !r.clean.includes("078-05-1120") && !r.arrived;
  const wentOut = (r) => r.arrived && !r.modal;

  // ---- 1. the org's settings -----------------------------------------------------------------
  let r = await send("default org", { patch: { sanctioned_ai_tools: "", redact_mode: "off" } });
  check("an SSN is blocked and does not arrive", blocked(r), JSON.stringify(r));
  r = await send("secret", { text: AWS });
  check("an AWS key is blocked and does not arrive", blocked(r), JSON.stringify(r));
  r = await send("sanctioned", { patch: { sanctioned_ai_tools: "claude.ai,chatgpt.com" } });
  check("a sanctioned destination (no unsanctioned-AI boost, score 60) still blocks an SSN", blocked(r), JSON.stringify(r));
  r = await send("sanctioned, chatgpt.com", { host: "chatgpt.com" });
  check("same on chatgpt.com (a different request shape)", blocked(r), JSON.stringify(r));
  r = await send("extension in monitor", { ext: { enforce: false } });
  check("a confirmed PII leak blocks even with the extension in monitor mode", blocked(r), JSON.stringify(r));
  r = await send("benign", { text: "please summarise this paragraph for me" });
  check("a benign message goes through with no UI", wentOut(r) && !r.banner && !r.notice, JSON.stringify(r));

  // ---- 2. coaching: the org softens a block to a warning; the original must still not leave ---
  r = await send("coaching, sanctioned", { patch: { redact_mode: "on" } });
  check("COACHING: the message is held, not sent, and the cleaned copy is shown (no SSN in it)", held(r), JSON.stringify(r));
  r = await send("coaching, chatgpt.com", { host: "chatgpt.com" });
  check("COACHING on chatgpt.com: held with a cleaned copy", held(r), JSON.stringify(r));
  r = await send("coaching, secret", { text: AWS });
  check("COACHING: a secret is held with a cleaned copy too", held(r), JSON.stringify(r));
  r = await send("coaching, extension in monitor", { ext: { enforce: false } });
  check("COACHING with the extension in monitor mode falls back to the plain amber warning", r.arrived && /warning/i.test(r.banner), JSON.stringify(r));
  r = await send("coaching, benign", { text: "please summarise this paragraph for me" });
  check("COACHING leaves benign messages alone", wentOut(r) && !r.banner && !r.notice, JSON.stringify(r));
  r = await send("coaching off again", { patch: { redact_mode: "off" } });
  check("turning coaching off restores the hard block", blocked(r), JSON.stringify(r));

  // ---- 3. however the page builds its request ------------------------------------------------
  for (const [mode, what] of [["request", "a Request object"], ["blob", "a Blob body"], ["bytes", "a Uint8Array body"],
                              ["xhr", "an XMLHttpRequest string body"], ["xhrblob", "an XMLHttpRequest Blob body"]]) {
    r = await send(what, { mode });
    check(`a page that sends ${what} is still scanned and blocked`, blocked(r), JSON.stringify(r));
  }

  // ---- 4. when the check cannot happen: fail open, but say so --------------------------------
  r = await send("slow backend", { ext: { backendUrl: SLOW }, extraWait: 2500 });
  check("a backend slower than 4s lets the message out (fail open)...", r.arrived && !r.modal, JSON.stringify(r));
  check("...and the person is told the answer came too late", /answer arrived after the message was sent/.test(r.notice), r.notice);
  r = await send("not signed in", { ext: { token: "" } });
  check("not signed in: sent unchecked, with a visible notice", r.arrived && /could not check that message \(not signed in\)/.test(r.notice), r.notice);
  r = await send("key rejected", { ext: { token: "ak_not_a_real_key" } });
  check("a rejected capture key: sent unchecked, with a visible notice", r.arrived && /capture key rejected/.test(r.notice), r.notice);

  // an unreadable body is reported to the console as a parse-miss on this device's sensor
  const streamer = await newKey("streamer@demo.local");
  await sw.evaluate((c) => chrome.storage.sync.set(c), { backendUrl: PALI, token: streamer, user: "streamer@demo.local", enforce: true });
  await sw.evaluate(() => chrome.storage.local.set({ lastVerdict: null, lastSkip: null, blockCount: 0 }));
  const sp = await ctx.newPage();
  await sp.goto("https://claude.ai/?mode=stream");
  await sp.fill("#prompt", SSN);
  await sp.click("#send");
  await sp.waitForTimeout(2500);
  const fleet = await api("GET", "/api/fleet", null, admin);
  const mine = (fleet.sensors || []).filter((s) => s.actor === "streamer@demo.local" && s.plane === "ai-usage");
  check("a body the extension cannot read (a stream) is counted as a parse-miss in the console", mine.length > 0 && mine[0].parse_miss_count >= 1, JSON.stringify(mine.map((s) => s.parse_miss_count)));
  check("...and the toolbar badge shows '!'", (await sw.evaluate(() => chrome.action.getBadgeText({}))) === "!");
  const pop = await ctx.newPage();
  await pop.goto(`chrome-extension://${extId}/popup.html`);
  await pop.waitForTimeout(400);
  check("...and the popup says the last message went out unchecked", /sent unchecked: could not read a message on claude\.ai/.test(await pop.locator("#skip").innerText()), await pop.locator("#skip").innerText());
  await pop.close();
  const ok = await ctx.newPage();
  await ok.goto("https://claude.ai/?mode=string");
  await ok.fill("#prompt", "please summarise this paragraph");
  await ok.click("#send");
  await ok.waitForTimeout(1500);
  check("the next good check clears the '!'", (await sw.evaluate(() => chrome.action.getBadgeText({}))) === "");
  await ok.close(); await sp.close();

  // ---- 5. last: the extension is updated under an open tab ----------------------------------
  await sw.evaluate((c) => chrome.storage.sync.set(c), { backendUrl: PALI, token: key, user: "dev@demo.local", enforce: true });
  const tab = await ctx.newPage();
  await tab.goto("https://claude.ai/?mode=string");
  await tab.fill("#prompt", SSN);
  await tab.click("#send");
  await tab.waitForTimeout(3500);
  const before = await tab.evaluate(() => !!document.getElementById("palivane-modal"));
  await tab.evaluate(() => document.getElementById("palivane-modal")?.remove());
  await sw.evaluate(() => setTimeout(() => chrome.runtime.reload(), 50)).catch(() => {});
  await sleep(2500);
  await fetch(CTL + "/__log", { method: "DELETE" });
  await tab.fill("#prompt", SSN);
  await tab.click("#send");
  await tab.waitForTimeout(1500);
  const after = await tab.evaluate(() => document.getElementById("palivane-notice")?.innerText?.replace(/\s+/g, " ") || "");
  check("(control) the open tab blocked the SSN before the update", before);
  check("an open tab whose extension was updated says to reload it, instead of going quiet", /reload this tab/.test(after), after);
} catch (e) {
  check("the harness ran to the end", false, String(e && e.stack || e));
} finally {
  try { await ctx?.close(); } catch (_) { /* already gone */ }
  for (const c of children) { try { c.kill("SIGTERM"); } catch (_) { /* gone */ } }
}

let bad = 0;
for (const x of results) { console.log(`${x.ok ? "PASS" : "FAIL"}  ${x.name}${!x.ok && x.extra ? "\n        " + x.extra : ""}`); if (!x.ok) bad++; }
console.log(`\n${results.length - bad}/${results.length} passed`);
if (!bad) fs.rmSync(tmp, { recursive: true, force: true }); else console.log(`(left ${tmp} for inspection)`);
process.exit(bad ? 1 : 0);
