// One-off: capture assets/help.png for the README. Logs in via the API, injects the
// session token into localStorage, opens the Help page, and full-page screenshots it at
// the same 1440@2x geometry as the other README shots.
import { chromium } from "playwright";

const BASE = process.env.PALIVANE_BASE || "http://localhost:8090";
const EMAIL = process.env.PALIVANE_E2E_EMAIL || "admin@demo.local";
const PASSWORD = process.env.PALIVANE_E2E_PASSWORD || "changeme123";
const OUT = process.env.OUT || "assets/help.png";

const login = await fetch(`${BASE}/api/auth/login`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
});
if (!login.ok) throw new Error(`login failed: ${login.status}`);
const tok = (await login.json()).access_token;
if (!tok) throw new Error("no token in login response");

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
// Seed the token before the app boots so it lands signed-in.
await page.addInitScript((t) => localStorage.setItem("warden_token", t), tok);
await page.goto(BASE, { waitUntil: "networkidle" });
// Click the Help nav item.
await page.getByRole("button", { name: "Help" }).click();
await page.getByText("Help & documentation").waitFor();
await page.waitForTimeout(400);
await page.screenshot({ path: OUT, fullPage: true });
await browser.close();
console.log("wrote", OUT);
