// Service worker: calls the Warden AI-usage ingest endpoint and returns a verdict.
// Config (backend URL, token, user, enforce) comes from chrome.storage — in a managed
// rollout these are pushed via enterprise policy (managed storage).

const DEFAULTS = {
  backendUrl: "http://localhost:8090",
  token: "",
  user: "",
  enforce: true, // when false, "block" verdicts are downgraded to "warn"
};

async function config() {
  const sync = await chrome.storage.sync.get(DEFAULTS);
  // Enterprise policy (chrome.storage.managed) wins over user settings, so a
  // force-installed deployment is configured centrally and users can't repoint it.
  let managed = {};
  try {
    managed = (await chrome.storage.managed.get(null)) || {};
  } catch (_) { /* no managed policy present */ }
  return Object.assign({}, DEFAULTS, sync, managed);
}

async function recordVerdict(verdict) {
  // Keep a session block counter + the last verdict for the popup, and reflect blocks
  // on the toolbar badge.
  const { blockCount = 0 } = await chrome.storage.local.get({ blockCount: 0 });
  const next = verdict.action === "block" ? blockCount + 1 : blockCount;
  await chrome.storage.local.set({
    blockCount: next,
    lastVerdict: { ...verdict, at: Date.now() },
  });
  try {
    if (next > 0) {
      await chrome.action.setBadgeText({ text: String(next) });
      await chrome.action.setBadgeBackgroundColor({ color: "#c0283a" });
    }
  } catch (_) { /* action API may be unavailable in some contexts */ }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "scan") return;
  (async () => {
    try {
      const c = await config();
      if (!c.token) { sendResponse({ action: "allow", reason: "unconfigured" }); return; }
      const res = await fetch(c.backendUrl.replace(/\/$/, "") + "/api/ingest/ai-usage", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Warden-Token": c.token },
        body: JSON.stringify({ content: msg.content, destination: msg.destination, user: c.user }),
      });
      if (!res.ok) { sendResponse({ action: "allow", reason: "backend " + res.status }); return; }
      const verdict = await res.json();
      if (!c.enforce && verdict.action === "block") verdict.action = "warn";
      await recordVerdict(verdict);
      sendResponse(verdict);
    } catch (e) {
      sendResponse({ action: "allow", reason: String(e) }); // fail open
    }
  })();
  return true; // keep the message channel open for the async sendResponse
});
