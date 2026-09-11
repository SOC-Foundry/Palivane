// Fail the build when a component calls the API client in a way that does not exist.
//
// src/api.js exports `api` as an OBJECT of named methods, each of which prefixes /api for
// you. Both OAuth components shipped calling it as a FUNCTION with a full path —
// `api("/api/oauth/grants")` — which is a synchronous TypeError on mount ("G is not a
// function" in the minified bundle). The consent screen rendered a blank page, which is
// the one screen in the product a person reaches from outside it, mid-authorization.
//
// Nothing caught it: there are no frontend tests, and `vite build` bundles a bad call
// happily because it is only wrong at runtime. This is the cheap guard for that specific
// class — an unknown method name or a call-as-function — not a type checker. It exists
// because the failure was invisible until a human opened the page.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const SRC = new URL("../src/", import.meta.url).pathname;

// The method names on `export const api = { … }`, read off the source rather than imported,
// so this stays a static check with no module loading or DOM.
const apiSrc = readFileSync(join(SRC, "api.js"), "utf8");
const objStart = apiSrc.indexOf("export const api = {");
if (objStart < 0) {
  console.error("check-api-calls: could not find `export const api = {` in src/api.js");
  process.exit(1);
}
const methods = new Set(
  [...apiSrc.slice(objStart).matchAll(/^ {2}(\w+):/gm)].map((m) => m[1]),
);

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return walk(full);
    return /\.jsx?$/.test(name) ? [full] : [];
  });
}

const problems = [];
for (const file of walk(SRC)) {
  if (file.endsWith("/api.js")) continue;
  const text = readFileSync(file, "utf8");
  // Only files that actually import the client — a local `api` variable elsewhere is not
  // ours to police.
  if (!/import\s*\{[^}]*\bapi\b[^}]*\}\s*from\s*["'][^"']*api\.js["']/.test(text)) continue;
  const rel = file.slice(SRC.length);
  text.split("\n").forEach((line, i) => {
    const at = `src/${rel}:${i + 1}`;
    // The import specifier itself is `…/api.js`, which looks exactly like a method access.
    if (/^\s*import\b/.test(line)) return;
    if (/(?<![\w.])api\s*\(/.test(line)) {
      problems.push(`${at}: \`api\` is an object of methods, not a function — call api.<method>(…)`);
    }
    for (const m of line.matchAll(/(?<![\w.])api\.(\w+)/g)) {
      if (!methods.has(m[1])) {
        problems.push(`${at}: api.${m[1]} is not defined in src/api.js`);
      }
    }
  });
}

if (problems.length) {
  console.error("API client is called in ways it does not support:\n");
  for (const p of problems) console.error(`  ${p}`);
  console.error(`\n${problems.length} problem(s). Add the method to src/api.js, or fix the call.`);
  process.exit(1);
}
console.log(`check-api-calls: ok (${methods.size} methods)`);
