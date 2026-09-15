// Load every page in a real browser and fail if it throws.
//
// `vite build` succeeding says nothing about whether a page renders, and this project has
// no other frontend tests. That gap shipped an OAuth consent screen that was blank for
// every remote-MCP user (the API client was called as a function; the build was green), and
// on the same day hid a missing space in JSX, a wrong badge, and a comparison grid whose
// rows did not line up. All four were found by a human opening a browser.
//
// So: open the browser in CI. The bar is deliberately low and absolute — a page that throws
// is broken, a page that renders nothing is broken. It is not a visual-regression suite and
// should not grow into one; the point is to catch "white screen", which is the failure that
// reaches a customer before it reaches us.
//
//   BASE=http://localhost:8080 node scripts/render-smoke.mjs
//
// Console views need a session. The seeded demo admin is used when present; if sign-in
// fails the console pages are REPORTED AS SKIPPED and the run still fails, because a
// silently-skipped check is the thing that let native-install pass having done nothing.
import { chromium } from "playwright-core";

const BASE = (process.env.BASE || "http://localhost:8080").replace(/\/$/, "");
const EMAIL = process.env.SMOKE_EMAIL || "admin@demo.local";
const PASSWORD = process.env.SMOKE_PASSWORD || "changeme123";
const ORG = process.env.SMOKE_ORG || "demo";

// Chrome, wherever this runs. playwright-core ships no browser of its own on purpose —
// downloading one would add ~130MB to a job that otherwise takes seconds.
const CHROME = [
  process.env.CHROME_PATH,
  "/usr/bin/google-chrome-stable",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium-browser",
  "/usr/bin/chromium",
].filter(Boolean);

const PUBLIC_PAGES = [
  ["/", ["Palivane"]],
  ["/pricing", ["AI Exposure Assessment"]],
  ["/security", ["founder-operated"]],          // the page whose whole value is being read
  ["/trust", []],
  ["/coverage", ["Snowflake Cortex"]],
  ["/how-it-works", []],
  ["/why-palivane", []],
  ["/use-cases", []],
  ["/setup", []],
  ["/support", []],
  ["/eu-ai-act", []],
  ["/privacy", []],
  ["/terms", []],
  ["/docs", []],
];

// Every console view in App.jsx's NAV. `connections` is listed explicitly in the comment
// because its Authorized-apps panel is exactly what crashed this tab undetected.
const CONSOLE_VIEWS = [
  "findings", "mine", "sessions", "scanlog", "discovery", "exposure", "coverage",
  "fleet", "agents", "policies", "simulator", "connect", "connections", "users",
  "settings", "report", "audit", "help",
];

const MIN_TEXT = 200;       // a rendered page has text; a white screen does not

async function signIn() {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD, org: ORG }),
  });
  if (!res.ok) throw new Error(`sign-in failed: ${res.status} ${await res.text()}`);
  const token = (await res.json()).access_token;
  if (!token) throw new Error("sign-in returned no access_token");
  return token;
}

async function check(browser, path, must, token) {
  const ctx = await browser.newContext();
  if (token) {
    // The SPA reads its session from localStorage, so seed it before any script runs.
    await ctx.addInitScript((t) => window.localStorage.setItem("palivane_token", t), token);
  }
  const page = await ctx.newPage();
  const problems = [];
  page.on("pageerror", (e) => problems.push(`uncaught: ${e.message}`));
  page.on("console", (m) => { if (m.type() === "error") problems.push(`console: ${m.text()}`); });

  try {
    await page.goto(BASE + path, { waitUntil: "networkidle", timeout: 30000 });
  } catch (e) {
    problems.push(`navigation: ${e.message}`);
  }
  const text = await page.locator("body").innerText().catch(() => "");
  if (text.trim().length < MIN_TEXT) {
    problems.push(`rendered ${text.trim().length} chars of text (a white screen renders ~0)`);
  }
  for (const m of must) {
    if (!text.includes(m)) problems.push(`missing expected text: ${JSON.stringify(m)}`);
  }
  await ctx.close();
  return problems;
}

const executablePath = CHROME.find((p) => p);
const browser = await chromium.launch({ executablePath }).catch((e) => {
  console.error(`could not launch a browser (tried: ${CHROME.join(", ")})\n${e.message}`);
  process.exit(2);
});

let failed = 0, checked = 0;
for (const [path, must] of PUBLIC_PAGES) {
  const problems = await check(browser, path, must, null);
  checked++;
  console.log(`${problems.length ? "FAIL" : "ok  "}  ${path}`);
  problems.forEach((p) => console.log(`        ${p}`));
  failed += problems.length ? 1 : 0;
}

let token = null;
try {
  token = await signIn();
} catch (e) {
  console.error(`\nconsole views NOT CHECKED: ${e.message}`);
  console.error("Treating that as a failure — a skipped check that reads as green is the");
  console.error("exact failure mode this job exists to end.");
  await browser.close();
  process.exit(1);
}

for (const view of CONSOLE_VIEWS) {
  const path = `/app/${view}`;
  const problems = await check(browser, path, [], token);
  checked++;
  console.log(`${problems.length ? "FAIL" : "ok  "}  ${path}`);
  problems.forEach((p) => console.log(`        ${p}`));
  failed += problems.length ? 1 : 0;
}

await browser.close();
console.log(`\nrender-smoke: ${checked - failed}/${checked} pages rendered clean`);
process.exit(failed ? 1 : 0);
