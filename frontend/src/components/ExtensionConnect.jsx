// Browser-extension sign-in landing (OAuth-style). The extension opens this page via
// chrome.identity.launchWebAuthFlow; after the user authenticates (login or SSO) we mint a
// per-user, tenant-scoped capture key and hand it back to the extension by redirecting to
// its chromiumapp.org callback with the token in the URL fragment.

import { useEffect, useState } from "react";
import { api, getToken } from "../api.js";
import Login from "./Login.jsx";

// Only ever redirect the token to a Chrome extension's callback (chromiumapp.org) or a
// loopback address (the `warden connect` CLI's local server, for Claude Code onboarding).
function redirectKind(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:" && u.hostname.endsWith(".chromiumapp.org")) return "fragment";
    if ((u.hostname === "127.0.0.1" || u.hostname === "localhost")) return "query";
    return null;
  } catch {
    return null;
  }
}

export default function ExtensionConnect() {
  const params = new URLSearchParams(window.location.search);
  const redirectUri = params.get("redirect_uri") || "";
  const state = params.get("state") || "";
  // Which device is connecting (browser deviceId / warden-connect hostname) — relayed to the
  // token endpoint so re-connecting the same device rotates its key instead of piling up rows.
  const device = params.get("device") || "";
  const [authed, setAuthed] = useState(!!getToken());
  const [status, setStatus] = useState("init");   // init | connecting | done | error
  const [detail, setDetail] = useState("");

  useEffect(() => {
    if (!authed) return;
    const kind = redirectKind(redirectUri);
    if (!kind) {
      setStatus("error"); setDetail("Invalid or missing redirect URL.");
      return;
    }
    setStatus("connecting");
    api.extensionToken(device)
      .then((r) => {
        const u = new URL(redirectUri);
        const params = `token=${encodeURIComponent(r.token)}` +
                       `&backend=${encodeURIComponent(window.location.origin)}` +
                       `&user=${encodeURIComponent(r.actor)}` +
                       `&state=${encodeURIComponent(state)}` +
                       // Can the gateway forward Claude Code to a real model, or does the
                       // org still need a provider key? The CLI warns on upstream=0.
                       `&upstream=${r.upstream_forwards === false ? "0" : "1"}` +
                       // Org enforce stance (Settings → Enforcement) — warden-connect
                       // provisions it into the hooks it installs.
                       `&enforce=${r.enforce ? "1" : "0"}`;
        if (kind === "fragment") u.hash = params;   // extension (launchWebAuthFlow)
        else u.search = params;                     // CLI loopback server reads query
        setStatus("done"); setDetail(r.actor);
        window.location.href = u.toString();
      })
      .catch((e) => { setStatus("error"); setDetail(String(e.message || e)); });
  }, [authed]);

  if (!authed) {
    return <Login onAuthed={() => setAuthed(true)} />;
  }

  return (
    <div className="login-screen">
      <div className="login-card" style={{ textAlign: "center" }}>
        <img className="login-logo" src="/warden-logo.png" alt="Warden" width="120" height="120" />
        {status === "connecting" && <p className="login-sub">Connecting your browser extension…</p>}
        {status === "done" && (
          <p className="login-sub">Connected as <strong>{detail}</strong>. You can close this tab.</p>
        )}
        {status === "error" && <div className="error">Couldn’t connect the extension: {detail}</div>}
      </div>
    </div>
  );
}
