// Browser-extension sign-in landing (OAuth-style). The extension opens this page via
// chrome.identity.launchWebAuthFlow; after the user authenticates (login or SSO) we mint a
// per-user, tenant-scoped capture key and hand it back to the extension by redirecting to
// its chromiumapp.org callback with the token in the URL fragment.

import { useEffect, useState } from "react";
import { api, getToken, setToken } from "../api.js";
import Login from "./Login.jsx";

// A present-but-EXPIRED session token must not count as signed in. `!!getToken()` did, so the
// page skipped the login screen, called the token endpoint with a dead token, and dead-ended
// on "token expired" (the extension) or simply never handed a token back (the CLI). Decode the
// JWT's exp and treat an expired one as signed out.
function sessionFresh() {
  const t = getToken();
  if (!t) return false;
  try {
    const b = t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const exp = JSON.parse(atob(b + "=".repeat((4 - (b.length % 4)) % 4))).exp;
    return typeof exp === "number" && exp * 1000 > Date.now();
  } catch {
    return false;   // unparseable -> make them sign in rather than trust it
  }
}

// Only ever redirect the token to a Chrome extension's callback (chromiumapp.org) or a
// loopback address (the `palivane connect` CLI's local server, for Claude Code onboarding).
function redirectKind(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:" && u.hostname.endsWith(".chromiumapp.org")) return "fragment";
    // Loopback CLI server is plain http — pin the scheme so a non-http(s) redirect_uri
    // (e.g. a custom scheme that still parses with a 127.0.0.1 host) can't carry the token.
    if ((u.protocol === "http:" || u.protocol === "https:") &&
        (u.hostname === "127.0.0.1" || u.hostname === "localhost")) return "query";
    return null;
  } catch {
    return null;
  }
}

export default function ExtensionConnect() {
  const params = new URLSearchParams(window.location.search);
  const redirectUri = params.get("redirect_uri") || "";
  const state = params.get("state") || "";
  // Which device is connecting (browser deviceId / palivane-connect hostname), relayed to the
  // token endpoint so re-connecting the same device rotates its key instead of piling up rows.
  const device = params.get("device") || "";
  const [authed, setAuthed] = useState(sessionFresh());
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
                       // Org enforce stance (Settings → Enforcement), palivane-connect
                       // provisions it into the hooks it installs.
                       `&enforce=${r.enforce ? "1" : "0"}`;
        if (kind === "fragment") u.hash = params;   // extension (launchWebAuthFlow)
        else u.search = params;                     // CLI loopback server reads query
        setStatus("done"); setDetail(r.actor);
        window.location.href = u.toString();
      })
      .catch((e) => {
        // A dead/revoked session: the api layer already cleared the token on the 401, so send
        // the user back to sign in and retry rather than dead-ending on "token expired".
        if (!getToken()) { setToken(null); setAuthed(false); setStatus("init"); return; }
        setStatus("error"); setDetail(String(e.message || e));
      });
  }, [authed]);

  if (!authed) {
    return <Login onAuthed={() => setAuthed(true)} />;
  }

  return (
    <div className="login-screen">
      <div className="login-card" style={{ textAlign: "center" }}>
        <img className="login-logo" src="/palivane-emblem.svg" alt="Palivane" width="120" height="120" />
        {status === "connecting" && <p className="login-sub">Connecting your browser extension...</p>}
        {status === "done" && (
          <p className="login-sub">Connected as <strong>{detail}</strong>. You can close this tab.</p>
        )}
        {status === "error" && <div className="error">Couldn't connect the extension: {detail}</div>}
      </div>
    </div>
  );
}
