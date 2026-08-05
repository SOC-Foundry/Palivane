// Warden for VS Code — the continuous in-IDE posture sensor (the "real extension" that
// the palivane-posture CLI was the 80/20 for). Same scan APIs, but event-driven instead of
// session-triggered:
//
//   - installed extension inventory  -> POST /api/scan/ide-extensions
//     (re-reported the moment extensions change — vscode.extensions.onDidChange)
//   - MCP server configs             -> POST /api/scan/mcp-config
//     (workspace .mcp.json watched live; user-level configs on activation/report)
//   - AI-assistant autonomy settings -> POST /api/scan/agent-config
//
// Sign-in mirrors palivane-connect: a loopback server + the console's /extension-connect
// page mint a per-user capture key, stored in VS Code SecretStorage. Config falls back
// to PALIVANE_URL/PALIVANE_TOKEN in the environment or ~/.claude/settings.json, so a machine
// already onboarded by palivane-connect reports with zero extra setup.
//
// Everything is fail-open and deduplicated (sha256 per report key in globalState) — the
// sensor never interferes with the editor and never spams unchanged state.

const vscode = require("vscode");
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const UA = "palivane-vscode/0.1.0";   // Cloudflare's front door 403s default/bare UAs
const DEFAULT_URL = "https://palivane.tachtech.net";

let status;          // status bar item
let ctx;             // extension context

// --- config -----------------------------------------------------------------------------

function settingsEnv() {
  try {
    const env = JSON.parse(fs.readFileSync(path.join(os.homedir(), ".claude", "settings.json"), "utf8")).env;
    return env && typeof env === "object" ? env : {};
  } catch { return {}; }
}

async function resolveConfig() {
  const senv = settingsEnv();
  let url = vscode.workspace.getConfiguration("warden").get("url") ||
            process.env.PALIVANE_URL || senv.PALIVANE_URL || "";
  if (!url && typeof senv.ANTHROPIC_BASE_URL === "string") {
    url = senv.ANTHROPIC_BASE_URL.replace(/\/v1\/?$/, "");
  }
  let token = (await ctx.secrets.get("warden.token")) ||
              process.env.PALIVANE_TOKEN || senv.PALIVANE_TOKEN || "";
  if (!token && typeof senv.ANTHROPIC_AUTH_TOKEN === "string" &&
      senv.ANTHROPIC_AUTH_TOKEN.startsWith("ak_")) {
    token = senv.ANTHROPIC_AUTH_TOKEN;
  }
  return { url: (url || DEFAULT_URL).replace(/\/+$/, ""), token };
}

// --- sign-in (loopback + /extension-connect, same flow as palivane-connect) ---------------

function connectFlow(consoleUrl) {
  return new Promise((resolve, reject) => {
    const state = crypto.randomBytes(9).toString("base64url");
    const server = http.createServer((req, res) => {
      const u = new URL(req.url, "http://127.0.0.1");
      if (u.pathname !== "/cb") { res.statusCode = 404; return res.end(); }
      res.setHeader("content-type", "text/html");
      res.end("<h2>Warden connected. You can close this tab and return to VS Code.</h2>");
      const got = Object.fromEntries(u.searchParams);
      server.close();
      if (got.state !== state) return reject(new Error("state mismatch"));
      if (!got.token) return reject(new Error("no token returned"));
      resolve(got);
    });
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      const redirect = encodeURIComponent(`http://127.0.0.1:${port}/cb`);
      vscode.env.openExternal(vscode.Uri.parse(
        `${consoleUrl}/extension-connect?redirect_uri=${redirect}&state=${state}`));
    });
    setTimeout(() => { try { server.close(); } catch {} reject(new Error("sign-in timed out")); },
               5 * 60 * 1000);
  });
}

// --- collectors (mirrors cli/palivane-posture) ---------------------------------------------

function collectExtensions() {
  const ids = vscode.extensions.all
    .filter((e) => !(e.packageJSON && e.packageJSON.isBuiltin) && !e.id.startsWith("vscode."))
    .map((e) => e.id.toLowerCase())
    .sort();
  return [...new Set(ids)];
}

function synthesizeClaudeConfig(raw) {
  // Minimal {"mcpServers": …} from ~/.claude.json — never post the raw file (it holds
  // unrelated user state).
  let data;
  try { data = JSON.parse(raw); } catch { return null; }
  if (!data || typeof data !== "object") return null;
  const servers = {};
  if (data.mcpServers && typeof data.mcpServers === "object") Object.assign(servers, data.mcpServers);
  if (data.projects && typeof data.projects === "object") {
    for (const proj of Object.values(data.projects)) {
      if (proj && typeof proj === "object" && proj.mcpServers && typeof proj.mcpServers === "object") {
        for (const [name, cfg] of Object.entries(proj.mcpServers)) {
          if (!(name in servers)) servers[name] = cfg;
        }
      }
    }
  }
  if (!Object.keys(servers).length) return null;
  return JSON.stringify({ mcpServers: servers });
}

function readIfExists(p) {
  try { return fs.readFileSync(p, "utf8").slice(0, 200000); } catch { return null; }
}

function collectMcpConfigs() {
  const found = [];
  const claude = readIfExists(path.join(os.homedir(), ".claude.json"));
  if (claude) {
    const synth = synthesizeClaudeConfig(claude);
    if (synth) found.push(["~/.claude.json", synth]);
  }
  for (const folder of vscode.workspace.workspaceFolders || []) {
    const c = readIfExists(path.join(folder.uri.fsPath, ".mcp.json"));
    if (c) found.push([`${folder.name}/.mcp.json`, c]);
  }
  for (const rel of [".config/Code/User/mcp.json", ".cursor/mcp.json"]) {
    const c = readIfExists(path.join(os.homedir(), rel));
    if (c) found.push([`~/${rel}`, c]);
  }
  return found;
}

function collectAgentConfigs() {
  const out = [];
  const candidates = [
    ["claude-code:settings", path.join(os.homedir(), ".claude", "settings.json"), "claude-code"],
    ["cursor:settings", path.join(os.homedir(), ".config", "Cursor", "User", "settings.json"), "cursor"],
    ["cursor:settings", path.join(os.homedir(), ".cursor", "settings.json"), "cursor"],
  ];
  const seen = new Set();
  for (const [label, p, tool] of candidates) {
    if (seen.has(p)) continue;
    const c = readIfExists(p);
    if (c && c.trim()) { seen.add(p); out.push([label, c, tool]); }
  }
  return out;
}

// --- reporting --------------------------------------------------------------------------

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

async function post(cfg, apiPath, body) {
  try {
    const r = await fetch(cfg.url + apiPath, {
      method: "POST",
      headers: { "content-type": "application/json", "User-Agent": UA, "X-Warden-Token": cfg.token },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    return r.ok;
  } catch { return false; }
}

async function report(force = false) {
  const cfg = await resolveConfig();
  if (!cfg.token) { updateStatus(false); return; }

  const items = [];   // [key, apiPath, body, canonical]
  const exts = collectExtensions();
  items.push(["ide-extensions", "/api/scan/ide-extensions",
              { extensions: exts, record: true }, exts.join("\n")]);
  for (const [label, content] of collectMcpConfigs()) {
    items.push([`mcp:${label}`, "/api/scan/mcp-config",
                { content, path: label, record: true }, content]);
  }
  const user = process.env.PALIVANE_USER || os.userInfo().username || "";
  for (const [label, content, tool] of collectAgentConfigs()) {
    items.push([`agent:${label}`, "/api/scan/agent-config",
                { content, tool, user, record: true }, content]);
  }

  const cacheKey = `warden.reported.${cfg.url}`;
  const cache = force ? {} : (ctx.globalState.get(cacheKey) || {});
  let posted = 0;
  for (const [key, apiPath, body, canonical] of items) {
    const dig = sha256(canonical);
    if (cache[key] === dig) continue;
    if (await post(cfg, apiPath, body)) {
      cache[key] = dig;
      posted += 1;
    }
  }
  await ctx.globalState.update(cacheKey, cache);
  updateStatus(true, posted);
}

function updateStatus(connected, posted) {
  if (!status) return;
  if (!connected) {
    status.text = "$(shield) Warden: not connected";
    status.tooltip = "Click to sign in to your Warden console";
    status.command = "warden.connect";
  } else {
    status.text = "$(shield) Warden";
    status.tooltip = posted
      ? `Warden posture sensor active — ${posted} report(s) just sent`
      : "Warden posture sensor active — everything up to date";
    status.command = "warden.reportNow";
  }
  status.show();
}

// --- activation ---------------------------------------------------------------------------

async function activate(context) {
  ctx = context;
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 90);
  context.subscriptions.push(status);

  context.subscriptions.push(
    vscode.commands.registerCommand("warden.connect", async () => {
      const cfg = await resolveConfig();
      try {
        const got = await connectFlow(cfg.url);
        await ctx.secrets.store("warden.token", got.token);
        vscode.window.showInformationMessage(
          `Warden connected as ${got.user || "you"} — posture reporting is on.`);
        await report(true);
      } catch (e) {
        vscode.window.showErrorMessage(`Warden sign-in failed: ${e.message || e}`);
      }
    }),
    vscode.commands.registerCommand("warden.reportNow", () => report(true)),
    vscode.commands.registerCommand("warden.disconnect", async () => {
      await ctx.secrets.delete("warden.token");
      updateStatus(false);
    }),
    // Live drift: a newly installed/removed extension is reported within seconds.
    vscode.extensions.onDidChange(() => report()),
  );

  // Watch workspace MCP configs — a new/edited .mcp.json is a posture change.
  const watcher = vscode.workspace.createFileSystemWatcher("**/.mcp.json");
  watcher.onDidChange(() => report());
  watcher.onDidCreate(() => report());
  watcher.onDidDelete(() => report());
  context.subscriptions.push(watcher);

  await report();
}

function deactivate() {}

module.exports = { activate, deactivate };
