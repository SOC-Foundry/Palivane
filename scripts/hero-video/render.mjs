// Render hero.html to an mp4: drive system Chrome frame-by-frame via CDP (deterministic
// window.__render(t) per frame), screenshot each, then ffmpeg the PNG sequence + the lo-fi
// soundtrack into an H.264/AAC mp4. One persistent browser — fast.
//
//   node render.mjs                 # -> hero.mp4 (+ frames in $FRAMES)
//   FRAMES=/tmp/hv/frames node render.mjs
import puppeteer from "puppeteer-core";
import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const DIR = dirname(fileURLToPath(import.meta.url));
const CHROME = process.env.CHROME || "/usr/bin/google-chrome-stable";
const FRAMES = process.env.FRAMES || join(DIR, "frames");
const OUT = process.env.OUT || join(DIR, "hero.mp4");
const WAV = join(DIR, "soundtrack.wav");

rmSync(FRAMES, { recursive: true, force: true });
mkdirSync(FRAMES, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: CHROME, headless: "new",
  args: ["--no-sandbox", "--hide-scrollbars", "--force-device-scale-factor=1",
         "--disable-gpu", "--force-color-profile=srgb"],
});
const page = await browser.newPage();
await page.setViewport({ width: 1280, height: 800, deviceScaleFactor: 1 });
await page.goto(`file://${join(DIR, "hero.html")}?capture=1`, { waitUntil: "networkidle0" });

const { FPS, DURATION } = await page.evaluate(() => ({ FPS: window.__FPS, DURATION: window.__DURATION }));
const total = Math.round(FPS * DURATION);
process.stdout.write(`capturing ${total} frames @ ${FPS}fps (${DURATION}s)\n`);

for (let f = 0; f < total; f++) {
  await page.evaluate((t) => window.__render(t), f / FPS);
  await page.screenshot({ path: join(FRAMES, `f_${String(f).padStart(5, "0")}.png`),
                          clip: { x: 0, y: 0, width: 1280, height: 800 } });
  if (f % 60 === 0) process.stdout.write(`  ${f}/${total}\n`);
}
await browser.close();

if (!existsSync(WAV)) { console.error(`missing ${WAV} — run: .venv/bin/python soundtrack.py`); process.exit(1); }

const args = [
  "-y", "-framerate", String(FPS), "-i", join(FRAMES, "f_%05d.png"),
  "-i", WAV,
  "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "19", "-preset", "medium",
  "-profile:v", "high", "-movflags", "+faststart",
  "-c:a", "aac", "-b:a", "192k", "-shortest", OUT,
];
process.stdout.write(`encoding -> ${OUT}\n`);
const r = spawnSync("ffmpeg", args, { stdio: ["ignore", "ignore", "inherit"] });
if (r.status !== 0) process.exit(r.status || 1);
process.stdout.write("done\n");
