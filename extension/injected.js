// Runs in the PAGE context. Wraps window.fetch so we can inspect a prompt *before*
// it's sent to the AI tool, ask Warden for a verdict, and block/warn inline.
// Communicates with the content script (isolated world) via window.postMessage.
(() => {
  const PENDING = new Map();
  let SEQ = 0;

  // URL patterns that look like "the user is submitting a prompt".
  const SEND_PATTERNS = [
    /\/backend-api\/(f\/)?conversation\b/, // chatgpt.com
    /\/completion\b/,                      // claude.ai
    /\/append_message\b/,                  // claude.ai (older)
    /\/retry_completion\b/,
    /\/chat_conversations\/.+\/(completion|messages)\b/, // claude.ai (current)
    /GenerateContent|StreamGenerate/i,     // gemini
    /\/v1\/(chat\/completions|messages|responses)\b/,    // OpenAI/Anthropic-style APIs
  ];
  const looksLikeSend = (url) => SEND_PATTERNS.some((re) => re.test(url));

  function extractPrompt(bodyText) {
    if (!bodyText) return "";
    try {
      const j = JSON.parse(bodyText);
      if (Array.isArray(j.messages)) {            // OpenAI/ChatGPT shape
        const parts = [];
        for (const m of j.messages) {
          const role = (m.author && m.author.role) || m.role;
          if (role && role !== "user") continue;
          const c = m.content;
          if (typeof c === "string") parts.push(c);
          else if (c && Array.isArray(c.parts)) parts.push(c.parts.filter((p) => typeof p === "string").join("\n"));
        }
        if (parts.length) return parts.join("\n");
      }
      if (typeof j.prompt === "string") return j.prompt;   // claude.ai
      if (typeof j.text === "string") return j.text;
    } catch (_) { /* not JSON — fall through */ }
    return String(bodyText).slice(0, 8000);
  }

  function scan(content, destination) {
    return new Promise((resolve) => {
      const id = ++SEQ;
      PENDING.set(id, resolve);
      window.postMessage({ __warden: true, kind: "scan", id, content, destination }, "*");
      // Fail OPEN: never break the user's tool if Warden is slow/unreachable.
      setTimeout(() => {
        if (PENDING.has(id)) { PENDING.delete(id); resolve({ action: "allow" }); }
      }, 4000);
    });
  }

  window.addEventListener("message", (e) => {
    const d = e.data;
    if (!d || !d.__warden || d.kind !== "verdict") return;
    const resolve = PENDING.get(d.id);
    if (resolve) { PENDING.delete(d.id); resolve(d.verdict || { action: "allow" }); }
  });

  const DEBUG = false; // flip to true to log captured requests/verdicts to the page console (per-site tuning)

  const origFetch = window.fetch;
  window.fetch = async function (input, init) {
    try {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      const method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
      const body = init && init.body;
      if (DEBUG && method === "POST") {
        console.debug("[Warden] POST", url, "match=", looksLikeSend(url),
          "bodyType=", body && body.constructor && body.constructor.name);
      }
      if (method === "POST" && looksLikeSend(url) && typeof body === "string") {
        const prompt = extractPrompt(body);
        if (DEBUG) console.log("[Warden] captured", url, "promptChars=", (prompt || "").length,
          "snippet=", (prompt || "").slice(0, 80));
        if (prompt && prompt.trim()) {
          const verdict = await scan(prompt, location.origin);
          if (DEBUG) console.log("[Warden] verdict", verdict.action, verdict.severity, verdict.risk_score);
          if (verdict.action === "block") {
            window.postMessage({ __warden: true, kind: "blocked", verdict }, "*");
            return new Response(JSON.stringify({ error: "Blocked by Warden: sensitive data detected." }),
              { status: 451, headers: { "content-type": "application/json" } });
          }
          if (verdict.action === "warn") {
            window.postMessage({ __warden: true, kind: "warn", verdict }, "*");
          }
        }
      }
    } catch (_) { /* fail open */ }
    return origFetch.apply(this, arguments);
  };
})();
