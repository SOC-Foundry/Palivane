const $ = (id) => document.getElementById(id);

function render(state) {
  $("blockCount").textContent = state.blockCount || 0;
  const v = state.lastVerdict;
  const el = $("verdict");
  if (!v) {
    el.className = "verdict muted";
    el.textContent = "No prompts inspected yet.";
    return;
  }
  const sigs = (v.signals || []).map((s) => s.category).join(", ") || "—";
  const when = v.at ? new Date(v.at).toLocaleTimeString() : "";
  el.className = "verdict";
  el.innerHTML =
    `<div>last verdict — <span class="sev sev-${v.severity}">${v.action} · ${v.severity}</span> ` +
    `(risk ${v.risk_score ?? "?"})</div>` +
    `<div class="sigs">${sigs}</div>` +
    `<div class="muted" style="margin-top:4px;font-size:11px;">${when}</div>`;
}

async function load() {
  render(await chrome.storage.local.get({ blockCount: 0, lastVerdict: null }));
}

document.addEventListener("DOMContentLoaded", load);
$("reset").addEventListener("click", async () => {
  await chrome.storage.local.set({ blockCount: 0 });
  try { await chrome.action.setBadgeText({ text: "" }); } catch (_) {}
  load();
});
$("options").addEventListener("click", () => chrome.runtime.openOptionsPage());
