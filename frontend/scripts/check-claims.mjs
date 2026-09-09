// Fail the build when the marketing pages make a claim the coverage matrix contradicts.
//
// /coverage is the honest document: every surface with what it actually needs, and the
// gaps listed on purpose, because "a coverage page that only lists wins is a brochure".
// The pages people actually read summarise it, and summaries drift toward the flattering
// version one small edit at a time. Twice in one day: four claims that Palivane installs
// nothing (it installs a browser extension and a CLI, and a proxy plus a CA for desktop),
// and two that Discovery shows "every AI tool in use" (unmanaged devices are invisible,
// which is the first gap the coverage page lists).
//
// This is the cheap half of not doing that again. The counts are already drift-proof via
// gen-stats.mjs; this covers the prose. It is a small, evidence-based blocklist, not a
// style checker: every entry is a phrase that actually shipped and had to be corrected.
// Keep it that way. A gate that fires on things that are fine gets switched off: the first
// draft of this banned "100%" on principle, and its only two hits were a CSS width and a
// benchmark result of 97 of 97 that the coverage page already backs with a reproducible
// harness. Both were fine. The rule was not, so it is gone.
//
//   node scripts/check-claims.mjs
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const components = join(here, "..", "src", "components");

// The public pages. The console is excluded: it talks to people who already bought.
const PAGES = ["Landing", "WhyPalivane", "UseCases", "HowItWorks", "Pricing", "Trust", "Support",
               "Setup", "CoverageMatrix", "SiteChrome", "Legal", "Docs"];

const BANNED = [
  { phrase: "nothing to install",
    why: "a browser extension and a CLI do install; desktop coverage also needs a proxy and a CA",
    instead: 'name what installs, or say "nobody has to touch a laptop"' },
  { phrase: "nothing installed",
    why: "only the gateway, SaaS and cloud-storage planes install nothing",
    instead: "attach it to the specific plane, as /coverage does" },
  { phrase: "install by hand",
    why: '"by hand" was carrying an otherwise false claim',
    instead: "say who pushes it (MDM) rather than qualifying the install away" },
  { phrase: "every ai tool",
    why: "unmanaged, unenrolled devices are invisible, the first gap /coverage lists",
    instead: 'say "the AI tools in use" and name what is not covered' },
  { phrase: "all ai tools",
    why: "same as 'every AI tool'",
    instead: 'say "the AI tools in use" and name what is not covered' },
  { phrase: "browser extension, cli capture hooks, and egress proxy",
    why: "shipped on Trust as the complete list of what's public, months after the MCP server joined it — an enumeration that omits a component reads as a closed set",
    instead: "name every component, or say 'the endpoint components' and let the repo be the list" },
];

// Legitimate uses, each tied to one file and justified. Adding to this list should mean
// arguing that the claim is scoped, not that the checker is annoying.
const ALLOW = [
  { file: "CoverageMatrix", phrase: "nothing installed",
    why: "attached per row to the gateway, SaaS and cloud-storage planes, where it is true" },
  { file: "CoverageMatrix", phrase: "install by hand",
    why: "'nobody installs anything by hand' sits under the MDM group, which is what it means" },
  { file: "Landing", phrase: "nothing installed",
    why: "on the SaaS card, naming Slack/Drive/SharePoint/Salesforce, which is the plane /coverage says installs nothing" },
];

const allowed = (file, phrase) =>
  ALLOW.some((a) => a.file === file && a.phrase === phrase);

// Drop comments so a note explaining a past mistake cannot fail the build. Only strip //
// at the start of a line, or an https:// inside copy would be truncated.
const decomment = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, "")
     .split("\n").map((l) => (l.trimStart().startsWith("//") ? "" : l)).join("\n");

let failures = 0;
for (const page of PAGES) {
  const path = join(components, `${page}.jsx`);
  if (!existsSync(path)) continue;
  const lines = decomment(readFileSync(path, "utf8")).split("\n");
  for (const { phrase, why, instead } of BANNED) {
    if (allowed(page, phrase)) continue;
    lines.forEach((line, i) => {
      if (!line.toLowerCase().includes(phrase)) return;
      failures++;
      console.error(`\n${page}.jsx:${i + 1}  "${phrase}"`);
      console.error(`  ${line.trim().slice(0, 150)}`);
      console.error(`  why:     ${why}`);
      console.error(`  instead: ${instead}`);
    });
  }
}

if (failures) {
  console.error(`\ncheck-claims: ${failures} claim(s) the coverage matrix does not support.`);
  console.error("Fix the copy, or add a justified entry to ALLOW in this script.");
  process.exit(1);
}
console.log(`check-claims: ${PAGES.length} public pages, no unsupported claims`);
