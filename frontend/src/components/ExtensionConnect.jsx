// Browser-extension sign-in landing (OAuth-style). The extension opens this page via
// chrome.identity.launchWebAuthFlow; after the user authenticates (login or SSO) we mint a
// per-user, tenant-scoped capture key and hand it back to the extension by redirecting to
// its chromiumapp.org callback with the token in the URL fragment.

import { useEffect, useState } from "react";
import { api, getToken } from "../api.js";
import Login from "./Login.jsx";

// Only ever redirect the token to a Chrome extension's own callback origin.
function isExtensionRedirect(uri) {
  try {
    const u = new URL(uri);
    return u.protocol === "https:" && u.hostname.endsWith(".chromiumapp.org");
  } catch {
    return false;
  }
}

export default function ExtensionConnect() {
  const params = new URLSearchParams(window.location.search);
  const redirectUri = params.get("redirect_uri") || "";
  const state = params.get("state") || "";
  const [authed, setAuthed] = useState(!!getToken());
  const [status, setStatus] = useState("init");   // init | connecting | done | error
  const [detail, setDetail] = useState("");

  useEffect(() => {
    if (!authed) return;
    if (!isExtensionRedirect(redirectUri)) {
      setStatus("error"); setDetail("Invalid or missing extension redirect URL.");
      return;
    }
    setStatus("connecting");
    api.extensionToken()
      .then((r) => {
        const u = new URL(redirectUri);
        u.hash = `token=${encodeURIComponent(r.token)}` +
                 `&backend=${encodeURIComponent(window.location.origin)}` +
                 `&user=${encodeURIComponent(r.actor)}` +
                 `&state=${encodeURIComponent(state)}`;
        setStatus("done"); setDetail(r.actor);
        window.location.href = u.toString();   // captured by launchWebAuthFlow
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
