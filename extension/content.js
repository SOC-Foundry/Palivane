// Isolated-world content script. Relays scan requests from the MAIN-world interceptor
// (injected.js, registered as a world:MAIN content script) to the background worker,
// and renders the warn/block UI. injected.js no longer needs to be injected via a
// <script> tag — that was blocked by strict-CSP sites like Microsoft Copilot.

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
    showBlockModal(d.verdict);
  } else if (d.kind === "warn") {
    showWarnBanner(d.verdict);
  }
});

const CATEGORY_LABELS = {
  secret_leak: "Credentials / secrets",
  pii_exposure: "Personal data (PII)",
  source_code_leak: "Proprietary code / confidential material",
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak attempt",
  data_exfiltration: "Data-exfiltration attempt",
  unsanctioned_ai: "Unsanctioned AI tool",
};

function dataSignals(verdict) {
  // The categories that explain the block, most-specific first (destination last).
  const order = (c) => (c === "unsanctioned_ai" ? 1 : 0);
  const seen = new Set();
  return (verdict.signals || [])
    .filter((s) => !seen.has(s.category) && seen.add(s.category))
    .sort((a, b) => order(a.category) - order(b.category));
}

function reasonText(verdict) {
  const labels = dataSignals(verdict)
    .filter((s) => s.category !== "unsanctioned_ai")
    .map((s) => (CATEGORY_LABELS[s.category] || s.category).toLowerCase());
  if (!labels.length) return "sensitive content";
  if (labels.length === 1) return labels[0];
  return labels.slice(0, -1).join(", ") + " and " + labels[labels.length - 1];
}

// --- Block: a prominent, explanatory modal (so claude.ai's own fetch error reads as expected) ---
function showBlockModal(verdict) {
  document.getElementById("warden-modal")?.remove();
  const rows = dataSignals(verdict).map((s) => {
    const label = CATEGORY_LABELS[s.category] || s.category;
    const ev = s.evidence ? ` — <span style="opacity:.7">${escapeHtml(s.evidence)}</span>` : "";
    return `<li style="margin:4px 0">${escapeHtml(label)}${ev}</li>`;
  }).join("");

  const wrap = document.createElement("div");
  wrap.id = "warden-modal";
  wrap.style.cssText = [
    "position:fixed", "inset:0", "z-index:2147483647",
    "background:rgba(10,12,18,.55)", "backdrop-filter:blur(2px)",
    "display:flex", "align-items:center", "justify-content:center",
    "font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif",
  ].join(";");
  wrap.innerHTML = `
    <div role="alertdialog" aria-modal="true" style="
        width:440px;max-width:92vw;background:#151926;color:#e6e9f0;
        border:1px solid #2a3346;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);
        padding:22px 24px">
      <div style="display:flex;align-items:center;gap:10px;font-size:17px;font-weight:800">
        <span style="color:#ff5d6c">🛡</span> Warden blocked this message
      </div>
      <p style="color:#c4ccdb;margin:12px 0 6px">
        It was <strong>not sent</strong> to the AI tool because it contained ${reasonText(verdict)}.
      </p>
      <ul style="margin:8px 0 4px;padding-left:18px;color:#e6e9f0">${rows}</ul>
      <div style="color:#8a93a6;font-size:12px;margin-top:10px">
        risk ${verdict.risk_score}/${(verdict.severity || "").toUpperCase()} ·
        the AI tool may show a "failed to send" error — that's the block working.
      </div>
      <button id="warden-modal-x" style="
        margin-top:18px;width:100%;padding:11px;border:none;border-radius:8px;
        background:#4da3ff;color:#04101f;font-weight:700;font-size:14px;cursor:pointer">
        Edit my message
      </button>
    </div>`;
  const close = () => wrap.remove();
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  document.documentElement.appendChild(wrap);
  const btn = document.getElementById("warden-modal-x");
  btn.addEventListener("click", close);
  btn.focus();
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
  });
}

// --- Warn: a lightweight top banner (content was sent, just flagged) ---
function showWarnBanner(verdict) {
  const id = "warden-banner";
  document.getElementById(id)?.remove();
  const el = document.createElement("div");
  el.id = id;
  el.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    "padding:12px 18px", "font:14px/1.45 system-ui,sans-serif", "color:#fff",
    "box-shadow:0 2px 14px rgba(0,0,0,.45)", "background:#b8791f",
  ].join(";");
  el.innerHTML =
    `<strong>⚠ Warden warning</strong> ` +
    `<span style="opacity:.95">Detected ${reasonText(verdict)} ` +
    `(risk ${verdict.risk_score}/${verdict.severity}). Review before sending sensitive data.</span>`;
  const close = document.createElement("span");
  close.textContent = "✕";
  close.style.cssText = "cursor:pointer;float:right;opacity:.85;font-weight:700;margin-left:12px";
  close.onclick = () => el.remove();
  el.prepend(close);
  document.documentElement.appendChild(el);
  setTimeout(() => el.remove(), 8000);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}
