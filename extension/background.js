// Service worker: calls the Warden AI-usage ingest endpoint and returns a verdict.
// Config (backend URL, token, user, enforce) comes from chrome.storage — in a managed
// rollout these are pushed via enterprise policy (managed storage).

const DEFAULTS = {
  backendUrl: "http://localhost:8090",
  // Warden console URL for self-serve sign-in (set to your SaaS app URL before publishing;
  // in a managed rollout it's pushed via policy). Falls back to backendUrl.
  consoleUrl: "",
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

async function isManaged() {
  try { return Object.keys((await chrome.storage.managed.get(null)) || {}).length > 0; }
  catch (_) { return false; }
}

// Self-serve / BYOD sign-in: open the Warden console, let the user authenticate (login or
// SSO), and receive a per-user tenant-scoped token via the OAuth redirect. Not used on
// managed devices (policy config wins).
async function signIn() {
  const c = await config();
  const consoleUrl = (c.consoleUrl || c.backendUrl || "").replace(/\/$/, "");
  if (!consoleUrl) throw new Error("Set your Warden URL first (Options).");
  const redirectUri = chrome.identity.getRedirectURL();          // https://<id>.chromiumapp.org/
  const state = Math.random().toString(36).slice(2);
  const authUrl = `${consoleUrl}/extension-connect?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
  const resultUrl = await chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true });
  const frag = new URLSearchParams(new URL(resultUrl).hash.slice(1));
  if (frag.get("state") !== state) throw new Error("state mismatch");
  const token = frag.get("token");
  if (!token) throw new Error("no token returned");
  await chrome.storage.sync.set({
    token,
    backendUrl: frag.get("backend") || consoleUrl,
    user: frag.get("user") || "",
  });
  return { user: frag.get("user") || "" };
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
  if (msg && msg.type === "status") {
    (async () => {
      const c = await config();
      sendResponse({ configured: !!c.token, user: c.user || "",
                     backendUrl: c.backendUrl, managed: await isManaged() });
    })();
    return true;
  }
  if (msg && msg.type === "signIn") {
    (async () => {
      try { sendResponse({ ok: true, ...(await signIn()) }); }
      catch (e) { sendResponse({ ok: false, error: String(e.message || e) }); }
    })();
    return true;
  }
  if (msg && msg.type === "exception") {
    (async () => {
      try {
        const c = await config();
        if (!c.token) { sendResponse({ ok: false }); return; }
        const res = await fetch(c.backendUrl.replace(/\/$/, "") + "/api/exception-request", {
          method: "POST",
          headers: { "content-type": "application/json", "X-Warden-Token": c.token },
          body: JSON.stringify({ ...msg.payload, user: c.user }),
        });
        sendResponse({ ok: res.ok });
      } catch (e) { sendResponse({ ok: false, error: String(e) }); }
    })();
    return true;
  }
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
