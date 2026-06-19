// Isolated-world content script. Injects the page-context interceptor, relays scan
// requests to the background worker (which calls Warden), and renders warn/block UI.

const s = document.createElement("script");
s.src = chrome.runtime.getURL("injected.js");
(document.head || document.documentElement).appendChild(s);
s.remove();

window.addEventListener("message", async (e) => {
  const d = e.data;
  if (!d || !d.__warden) return;

  if (d.kind === "scan") {
    let verdict = { action: "allow" };
    try {
      verdict = await chrome.runtime.sendMessage({
        type: "scan", content: d.content, destination: d.destination,
      });
    } catch (_) { verdict = { action: "allow" }; }
    window.postMessage({ __warden: true, kind: "verdict", id: d.id, verdict: verdict || { action: "allow" } }, "*");
  } else if (d.kind === "blocked") {
    showBanner(true, d.verdict);
  } else if (d.kind === "warn") {
    showBanner(false, d.verdict);
  }
});

const CATEGORY_LABELS = {
  secret_leak: "credentials/secrets",
  pii_exposure: "personal data (PII)",
  source_code_leak: "proprietary code / confidential material",
  unsanctioned_ai: "unsanctioned AI tool",
};

function reasonText(verdict) {
  const cats = [...new Set((verdict.signals || []).map((s) => s.category))]
    .filter((c) => c !== "unsanctioned_ai");        // the data categories are what matter
  const labels = cats.map((c) => CATEGORY_LABELS[c] || c);
  if (!labels.length) return "sensitive content";
  if (labels.length === 1) return labels[0];
  return labels.slice(0, -1).join(", ") + " and " + labels[labels.length - 1];
}

function showBanner(blocked, verdict) {
  const id = "warden-banner";
  document.getElementById(id)?.remove();
  const reason = reasonText(verdict);
  const el = document.createElement("div");
  el.id = id;
  el.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    "padding:12px 18px", "font:14px/1.45 system-ui,sans-serif", "color:#fff",
    "box-shadow:0 2px 14px rgba(0,0,0,.45)",
    `background:${blocked ? "#c0283a" : "#b8791f"}`,
  ].join(";");
  const headline = blocked
    ? `🛡 Warden blocked this prompt — it was not sent.`
    : `⚠ Warden warning — review before sending.`;
  el.innerHTML =
    `<strong>${headline}</strong> ` +
    `<span style="opacity:.95">Detected ${reason} (risk ${verdict.risk_score}/${verdict.severity}). ` +
    `Remove the sensitive content${blocked ? " and try again" : ""}.</span>`;
  const close = document.createElement("span");
  close.textContent = "✕";
  close.style.cssText = "cursor:pointer;float:right;opacity:.85;font-weight:700;margin-left:12px";
  close.onclick = () => el.remove();
  el.prepend(close);
  document.documentElement.appendChild(el);
  if (!blocked) setTimeout(() => el.remove(), 8000);
}
