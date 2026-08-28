// Derive the landing page's stats-band numbers from the detector SOURCE, so the site
// can never claim a different count than the engine ships (the "28 detection checks"
// stat sat stale while the engine grew past 40 — hand-maintained numbers drift).
//
//   node scripts/gen-stats.mjs           # regenerate src/stats.gen.json
//   node scripts/gen-stats.mjs --check   # CI: fail if the committed file is stale
//
// The Docker web-build stage has no backend/ in its context, so the generated file is
// COMMITTED and this script exits quietly when the backend source is absent; the
// --check run in CI (where the full repo is present) is what prevents drift.
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const detectors = join(here, "..", "..", "backend", "app", "detectors");
const outPath = join(here, "..", "src", "stats.gen.json");

if (!existsSync(detectors)) {
  console.log("gen-stats: backend source not present (image build) — keeping committed stats");
  process.exit(0);
}

// Distinct human-facing signal titles across every detector (template titles with {}
// placeholders excluded — they parameterize an already-counted check).
const titles = new Set();
for (const f of readdirSync(detectors).filter((f) => f.endsWith(".py"))) {
  const src = readFileSync(join(detectors, f), "utf8");
  for (const m of src.matchAll(/title="([^"{}]+)"/g)) titles.add(m[1]);
}

// Distinct credential formats in the tier-1 secret library (labels, deduped — some
// formats need two regexes).
const patterns = readFileSync(join(detectors, "patterns.py"), "utf8");
const block = patterns.split("SECRET_PATTERNS")[1].split("\n]")[0];
const formats = new Set([...block.matchAll(/^\s*\("([^"]+)",/gm)].map((m) => m[1]));

const stats = { detection_checks: titles.size, secret_formats: formats.size };
const next = JSON.stringify(stats, null, 2) + "\n";

if (process.argv.includes("--check")) {
  const current = existsSync(outPath) ? readFileSync(outPath, "utf8") : "";
  if (current !== next) {
    console.error(`gen-stats: src/stats.gen.json is stale — expected ${next.trim()}`);
    console.error("run `node scripts/gen-stats.mjs` in frontend/ and commit the result");
    process.exit(1);
  }
  console.log("gen-stats: committed stats match the engine", stats);
} else {
  writeFileSync(outPath, next);
  console.log("gen-stats: wrote", stats);
}
