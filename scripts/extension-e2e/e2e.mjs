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
// and a Chromium that can load an unpacked extension. The one the pinned playwright-core expects works
// (`npx playwright-core install --no-shell chromium` in frontend/, a Chrome for Testing build);
// branded Chrome 137+ ignores --load-extension. Point PALIVANE_CHROMIUM at a specific binary if
// Playwright's default revision is not the one you have. It runs headless: `headless: true` on a full
// Chromium is the new headless mode, which loads extensions and runs their service worker.
//
// Set PALIVANE_EXTENSION to a different extension folder to run the same checks against another build.
// CI runs it on every PR (the extension-e2e job in .github/workflows/ci.yml).
import { spawn, execFileSync } from "node:child_process";
import crypto from "node:crypto";
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

// PALIVANE_E2E_TMPDIR: where the run's scratch folder goes (CI points it at a directory it uploads
// when the run fails: the children's log, the browser console and a screenshot of each open tab).
const tmpParent = process.env.PALIVANE_E2E_TMPDIR || os.tmpdir();
fs.mkdirSync(tmpParent, { recursive: true });
const tmp = fs.mkdtempSync(path.join(tmpParent, "palivane-ext-e2e-"));
const consoleLog = fs.createWriteStream(path.join(tmp, "console.log"));
const children = [];
const results = [];
const check = (name, ok, extra = "") => { results.push({ name, ok: !!ok, extra }); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function start(cmd, args, opts = {}) {
  const p = spawn(cmd, args, { stdio: ["ignore", "ignore", fs.openSync(path.join(tmp, "children.log"), "a")], ...opts });
  p.what = `${path.basename(cmd)} ${args.slice(0, 2).join(" ")}`;
  children.push(p);
  return p;
}
async function until(fn, what, ms = 30000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try { if (await fn()) return; } catch (_) { /* not yet */ }
    // a child that already exited will not come up: say so now, with its log, not after the timeout
    const dead = children.find((c) => c.exitCode !== null || c.signalCode !== null);
    if (dead) throw new Error(`${dead.what} exited (${dead.exitCode ?? dead.signalCode}) while waiting for ${what}:\n` +
      fs.readFileSync(path.join(tmp, "children.log"), "utf8").split("\n").slice(-15).join("\n"));
    await sleep(250);
  }
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
  const benv = { ...process.env,
    // a throwaway key: the backend refuses to boot on a weak or missing one while signup is on
    PALIVANE_SECRET_KEY: crypto.randomBytes(32).toString("hex"), DATABASE_URL: `sqlite:///${tmp}/e2e.db`, PALIVANE_STATE_DIR: path.join(tmp, "state"), PALIVANE_STATIC_DIR: "" };
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
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--ignore-certificate-errors", "--no-proxy-server",   // a system proxy would resolve the mapped hostnames itself
      // the three AI sites go to the fake one; every other hostname fails to resolve, so nothing in
      // the run (the browser's own background requests included) can reach the real network
      `--host-resolver-rules=MAP claude.ai 127.0.0.1:${PORT.https}, MAP chatgpt.com 127.0.0.1:${PORT.https}, MAP gemini.google.com 127.0.0.1:${PORT.https}, MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1`],
  });
  // Everything the pages and the extension's service worker print, for a failed run's artifact.
  const stamp = () => new Date().toISOString();
  ctx.on("console", (m) => consoleLog.write(`[${stamp()}] ${m.page()?.url() || "worker"} ${m.type()}: ${m.text()}\n`));
  ctx.on("weberror", (e) => consoleLog.write(`[${stamp()}] ${e.page()?.url() || "?"} uncaught: ${e.error()}\n`));
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 20000 });
  const extId = sw.url().split("/")[2];
  const version = await sw.evaluate(() => chrome.runtime.getManifest().version);
  console.log(`extension ${version} loaded from ${path.relative(root, EXT)}`);
  // Count the service worker's calls to the backend still in flight. A scan can outlive the send
  // it was for (the page gives up at 4s and sends; the answer is still recorded when it comes),
  // so a check that reads the popup after a slow scan has to wait for those, not for a fixed time.
  await sw.evaluate((pali) => {
    const f = self.fetch; self.__pvInflight = 0;
    self.fetch = (...a) => {
      if (!String(a[0]?.url || a[0]).startsWith(pali)) return f(...a);
      self.__pvInflight++;
      return f(...a).finally(() => { self.__pvInflight--; });
    };
  }, PALI);
  // Every scan answered and its verdict/skip written: nothing in flight, and the popup's state
  // unchanged across two reads.
  async function scansSettled() {
    let last = "";
    await until(async () => {
      const now = JSON.stringify(await sw.evaluate(async () => [self.__pvInflight || 0,
        await chrome.storage.local.get({ lastVerdict: null, lastSkip: null })]));
      const done = now.startsWith("[0,") && now === last;
      last = now;
      return done;
    }, "the extension's scans to finish", 60000);
  }

  // Config goes where the extension reads it: the capture key in local storage (since 0.7.6 it
  // is moved out of sync storage and any copy left there is ignored), the rest in sync storage.
  const setConfig = async (c) => {
    const { token, ...rest } = c;
    await sw.evaluate((x) => chrome.storage.sync.set(x), rest);
    if ("token" in c) await sw.evaluate((t) => chrome.storage.local.set({ token: t }), token);
  };
  // One message through the extension. Returns what the person saw and whether it got out.
  async function send(label, { host = "claude.ai", text = SSN, mode = "string", ext = {}, patch = null, extraWait = 0, keepState = false } = {}) {
    if (patch) await tenant(patch);
    await fetch(CTL + "/__log", { method: "DELETE" });
    await setConfig({ backendUrl: PALI, token: key, user: "dev@demo.local", enforce: true, ...ext });
    if (!keepState) await sw.evaluate(() => chrome.storage.local.set({ lastVerdict: null, lastSkip: null, blockCount: 0 }));
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
  // What the toolbar popup says about the last message: its "sent unchecked" line, if shown.
  async function popupSkip() {
    const pop = await ctx.newPage();
    await pop.goto(`chrome-extension://${extId}/popup.html`);
    await pop.waitForTimeout(400);
    const s = await pop.evaluate(() => { const e = document.getElementById("skip"); return e.hidden ? "" : e.innerText; });
    await pop.close();
    return s;
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
  // An SSN is a confirmed leak (force_block): monitor mode would let a merely risky coached
  // message out with the amber warning, but not this one.
  check("COACHING with the extension in monitor mode still holds a confirmed leak, with the cleaned copy", held(r), JSON.stringify(r));
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

  // ---- 3b. long messages: the backend scores at most 200,000 characters a call ----------------
  const pad = (n) => "lorem ipsum dolor sit amet ".repeat(Math.ceil(n / 27)).slice(0, n);
  r = await send("long message", { text: pad(250000) + " " + SSN });
  check("an SSN at the END of a 250,000-character message is still found and blocked", blocked(r), JSON.stringify({ ...r, title: r.title }));
  r = await send("gemini, form-encoded, long", { host: "gemini.google.com", text: pad(20000) + " " + SSN });
  check("an SSN past character 8,000 of a form-encoded (Gemini-style) send is still found and blocked", blocked(r), JSON.stringify(r));
  r = await send("gemini, form-encoded, short", { host: "gemini.google.com" });
  check("a short form-encoded send is blocked", blocked(r), JSON.stringify(r));
  // A real Gemini send carries opaque ids around the typed text: an upload id, a session uuid,
  // page state and an `at` token. Only the text is a prompt; scanning the rest read every
  // random-looking id as a possible secret and filled the console with findings nobody caused.
  const noisy = async () => {
    const f = await api("GET", "/api/findings?actor=dev%40demo.local&limit=200", null, admin);
    return (Array.isArray(f) ? f : f.findings || []).filter((x) => x.severity !== "benign").length;
  };
  const findingsBefore = await noisy();
  r = await send("gemini, real shape, benign", { host: "gemini.google.com", mode: "real", text: "what_is_the_capital_of_France_today" });
  check("a real-shaped Gemini send with a benign prompt goes out untouched", wentOut(r) && !r.banner, JSON.stringify(r));
  const findingsAfter = await noisy();
  check("...and its upload id, session uuid and page tokens raise no finding", findingsAfter === findingsBefore, `${findingsBefore} -> ${findingsAfter}`);
  r = await send("gemini, real shape, ssn", { host: "gemini.google.com", mode: "real", text: SSN });
  check("an SSN typed into a real-shaped Gemini send is still blocked", blocked(r), JSON.stringify(r));

  // claude.ai's send is a Connect RPC with a protobuf body (PerformAction), not a JSON POST to
  // /completion. The extension did not recognize the path, so it never looked at a message sent
  // from the web app: no scan, no finding, no notice.
  r = await send("claude rpc, ssn", { mode: "rpc", text: SSN });
  check("an SSN sent as claude.ai's protobuf PerformAction is blocked and does not arrive", blocked(r), JSON.stringify(r));
  r = await send("claude rpc, aws key", { mode: "rpc", text: AWS });
  check("an AWS key sent the same way is blocked", blocked(r), JSON.stringify(r));
  // claude.ai retries a send it was told failed, on a backoff. One blocked message used to put up a
  // popup per retry, and re-scanned each one, so the popup would not stop.
  {
    await setConfig({ backendUrl: PALI, token: key, user: "dev@demo.local", enforce: true });
    const page = await ctx.newPage();
    const piiScans = async () => {
      const f = await api("GET", "/api/findings?actor=dev%40demo.local&limit=100", null, admin);
      return (Array.isArray(f) ? f : f.findings || [])
        .filter((x) => /personal|pii/i.test(JSON.stringify(x.categories || []) + JSON.stringify(x.top_signals || [])))
        .reduce((n, x) => n + (x.seen_count || 1), 0);
    };
    const scansBefore = await piiScans();
    await page.goto("https://claude.ai/?mode=rpc-retry");
    await page.fill("#prompt", "retry storm 123-12-1234");
    await page.click("#send");
    await page.waitForFunction(() => /attempts/.test(document.getElementById("out").textContent), null, { timeout: 30000 });
    await page.waitForTimeout(600);
    const out = await page.locator("#out").innerText();
    const popups = await page.evaluate(() => window.__modals);
    const scans = (await piiScans()) - scansBefore;
    await page.close();
    check("a blocked send the page retries 8 times puts up one popup, not one per retry", popups === 1, `popups=${popups} ${out}`);
    check("...every retry is answered as a final Connect error (403, permission_denied)", /status 403 .*code permission_denied/.test(out), out);
    check("...and the retries are not each scanned again (8 sends, at most 2 scans)", scans >= 1 && scans <= 2, `scans for the storm: ${scans}`);
  }
  const rpcBefore = await noisy();
  r = await send("claude rpc, benign", { mode: "rpc", text: "what_is_the_capital_of_France_today" });
  check("a benign message sent the same way goes out untouched", wentOut(r) && !r.banner, JSON.stringify(r));
  const rpcAfter = await noisy();
  check("...and its conversation uuids, session id, locale and timezone raise no finding", rpcAfter === rpcBefore, `${rpcBefore} -> ${rpcAfter}`);
  r = await send("long benign message", { text: pad(250000) });
  check("a long benign message goes through with no UI", wentOut(r) && !r.banner && !r.notice, JSON.stringify(r));
  // Past 1.2M characters only the first 1.2M are scored. An allow on that prefix used to be recorded
  // as a clean check, which hid the "sent unchecked" line although the tail was never looked at.
  // (the SSN sits in the unscored tail; the trailing padding is what the arrival check looks for)
  r = await send("over the scan cap, clean prefix", { text: pad(1250000) + " " + SSN + " " + pad(40), extraWait: 1500 });
  // eight 150,000-character scans: on a slow machine some answer after the message went out, and
  // one landing after the next send would put the "unchecked" line back over its clean verdict
  await scansSettled();
  check("a message over 1.2M characters still goes out (fail open)", r.arrived && !r.modal, JSON.stringify({ ...r, title: r.title }));
  let skipLine = await popupSkip();
  check("...and the popup keeps saying it went out unchecked, though its prefix was clean", /sent unchecked: message too long, only the first part was checked/.test(skipLine), skipLine);
  check("...and the toolbar badge shows '!'", (await sw.evaluate(() => chrome.action.getBadgeText({}))) === "!");
  r = await send("whole message after a skip", { text: "please summarise this paragraph for me", keepState: true });
  skipLine = await popupSkip();
  check("a normal whole-message allow after it clears the unchecked line", wentOut(r) && skipLine === "", skipLine);

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
  await setConfig({ backendUrl: PALI, token: streamer, user: "streamer@demo.local", enforce: true });
  await sw.evaluate(() => chrome.storage.local.set({ lastVerdict: null, lastSkip: null, blockCount: 0 }));
  // the over-the-cap send above already told the console about claude.ai, which it hears once per ten minutes
  await sw.evaluate(() => chrome.storage.session.remove("blindAt:https://claude.ai"));
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
  // A compressed claude.ai RPC body cannot be read at all. Right after a good check (and within the
  // ten minutes in which the console hears of one blind send per site) it must still say so.
  const gz = await ctx.newPage();
  await gz.goto("https://claude.ai/?mode=rpc-gzip");
  await gz.fill("#prompt", SSN);
  await gz.click("#send");
  await gz.waitForFunction(() => document.getElementById("out").textContent !== "", null, { timeout: 20000 }).catch(() => {});
  await gz.waitForTimeout(1000);
  await gz.close();
  const gzSkip = await popupSkip();
  check("a compressed claude.ai RPC send right after a good check shows as unchecked in the popup", /sent unchecked: could not read a message on claude\.ai/.test(gzSkip), gzSkip);
  check("...and the toolbar badge shows '!' again", (await sw.evaluate(() => chrome.action.getBadgeText({}))) === "!");

  // ---- 5. last: the extension is updated under an open tab ----------------------------------
  await setConfig({ backendUrl: PALI, token: key, user: "dev@demo.local", enforce: true });
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
  await tab.fill("#prompt", SSN + " again, in new words");   // not the same send as the one just stopped
  await tab.click("#send");
  await tab.waitForTimeout(1500);
  const after = await tab.evaluate(() => document.getElementById("palivane-notice")?.innerText?.replace(/\s+/g, " ") || "");
  check("(control) the open tab blocked the SSN before the update", before);
  check("an open tab whose extension was updated says to reload it, instead of going quiet", /reload this tab/.test(after), after);
} catch (e) {
  check("the harness ran to the end", false, String(e && e.stack || e));
} finally {
  if (results.some((x) => !x.ok)) {   // whatever is still open when something failed
    let i = 0;
    for (const p of ctx?.pages() || []) { try { await p.screenshot({ path: path.join(tmp, `open-tab-${i++}.png`) }); } catch (_) { /* closed */ } }
  }
  try { await ctx?.close(); } catch (_) { /* already gone */ }
  for (const c of children) { try { c.kill("SIGTERM"); } catch (_) { /* gone */ } }
}

let bad = 0;
for (const x of results) { console.log(`${x.ok ? "PASS" : "FAIL"}  ${x.name}${!x.ok && x.extra ? "\n        " + x.extra : ""}`); if (!x.ok) bad++; }
console.log(`\n${results.length - bad}/${results.length} passed`);
if (!bad) fs.rmSync(tmp, { recursive: true, force: true }); else console.log(`(left ${tmp} for inspection)`);
process.exit(bad ? 1 : 0);
