// Runs extension/injected.js in a bare Node vm (no browser) and checks which POSTs it hands to
// Palivane for a scan: a chat send is scanned, the page's own analytics are not.
//
//   node scripts/extension-e2e/telemetry-skip.js
const fs = require("fs"), path = require("path"), vm = require("vm"), assert = require("assert");

const scans = [];
const win = {
  location: { origin: "https://claude.ai", href: "https://claude.ai/chat/x" },
  addEventListener: (_t, f) => { (win.__l = win.__l || []).push(f); },
  postMessage: (m) => {
    if (m.kind !== "scan") return;
    scans.push(m.content);
    setTimeout(() => win.__l.forEach((f) => f({ source: win,
      data: { __palivane: true, kind: "verdict", id: m.id, verdict: { action: "allow" } } })), 0);
  },
  fetch: async () => ({ ok: true }),
};
win.window = win;
const ctx = { window: win, URL, URLSearchParams, location: win.location, Response: class {},
  XMLHttpRequest: function () {}, setTimeout, TextDecoder, Blob };
ctx.XMLHttpRequest.prototype = { open() {}, send() {} };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, "../../extension/injected.js"), "utf8"), ctx);

const post = (url, body) => ctx.window.fetch(url, { method: "POST", body });
const chat = JSON.stringify({ prompt: "hello" });
const beacon = JSON.stringify({ type: "action", _dd: { format_version: 2, drift: 123456789 } });

(async () => {
  await post("https://browser-intake-datadoghq.com/api/v2/rum/completion", chat);  // vendor host
  await post("https://claude.ai/api/chat/rum", beacon);                          // first-party proxy of RUM
  await post("https://claude.ai/other?x=/completion", chat);                     // route only in the query
  assert.deepStrictEqual(scans, [], "analytics must not be scanned");
  await post("https://claude.ai/api/organizations/1/chat_conversations/2/completion", chat);
  await post("/backend-api/conversation", JSON.stringify({ messages: [{ role: "user", content: "hi" }] }));
  assert.deepStrictEqual(scans, ["hello", "hi"], "chat sends must still be scanned");
  console.log("ok");
})();
