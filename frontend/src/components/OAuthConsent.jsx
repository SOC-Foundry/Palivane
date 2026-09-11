import { useEffect, useState } from "react";
import { api } from "../api.js";

// The OAuth consent screen. Reached only as a redirect from /authorize, which cannot
// authenticate the browser itself: the console's session lives in localStorage, not a
// cookie, so the authorize endpoint sees an anonymous request however thoroughly the user
// is signed in. This page is the one place that holds the token, so it owns the approval.
//
// What it deliberately does NOT do is render anything out of its own query string. The
// client name comes from /api/oauth/pending, resolved server-side by client_id against what
// was recorded at registration — because "Palivane Official" is a trivial thing to put in a
// URL, and a consent screen that repeats the caller's own claim about itself is a phishing
// page with extra steps.
export default function OAuthConsent() {
  const q = new URLSearchParams(window.location.search);
  const clientId = q.get("client_id") || "";
  const redirectUri = q.get("redirect_uri") || "";
  const state = q.get("state") || "";
  const challenge = q.get("code_challenge") || "";

  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.oauthPending(clientId, redirectUri)
      .then(setInfo)
      .catch((e) => setError(e.message || "This authorization request is not valid."));
  }, [clientId, redirectUri]);

  const approve = async () => {
    setBusy(true);
    try {
      const r = await api.oauthConsent({
        client_id: clientId, redirect_uri: redirectUri,
        code_challenge: challenge, state,
      });
      window.location.replace(r.redirect_to);
    } catch (e) {
      setError(e.message || "Could not complete authorization.");
      setBusy(false);
    }
  };

  // Deny sends the user nowhere: no redirect back to the client, because a denial should
  // not hand the caller a navigation it can distinguish from an approval by timing.
  const deny = () => { window.location.replace("/app/findings"); };

  if (error) {
    return (
      <div className="consent-wrap">
        <div className="consent-card">
          <h1 className="dsp">This request isn't valid</h1>
          <p className="consent-lead">{error}</p>
          <p className="consent-note">
            Nothing was authorized. If you started this from an AI assistant, try connecting
            again — and if it keeps failing, the app may be registered with a different
            redirect address than the one it is using.
          </p>
          <button type="button" className="primary-btn slim" onClick={deny}>Back to the console</button>
        </div>
      </div>
    );
  }

  if (!info) return <div className="consent-wrap"><div className="consent-card">Checking…</div></div>;

  return (
    <div className="consent-wrap">
      <div className="consent-card">
        <h1 className="dsp">Allow <strong>{info.client_name}</strong> to read your Palivane data?</h1>
        <p className="consent-lead">{info.scope_description}</p>

        <dl className="consent-facts">
          <div><dt>Granting as</dt><dd>{info.granting_as.email} ({info.granting_as.role})</dd></div>
          <div><dt>Sends you back to</dt><dd><code>{info.redirect_uri}</code></dd></div>
          <div><dt>Access</dt><dd>Read only — it cannot change or delete anything</dd></div>
        </dl>

        {/* True again as of the Authorized apps panel in Connections. It briefly said this
            when it was not true, which is the failure mode a consent screen can least
            afford — so if that panel is ever removed, this sentence goes with it. */}
        <p className="consent-note">
          This grants exactly what your own account can see, and nothing beyond it. You can
          cut it off at any time from <strong>Connections → Authorized apps</strong>, and it
          lapses on its own within 30 days.
        </p>

        <div className="consent-actions">
          <button type="button" className="primary-btn slim" onClick={approve} disabled={busy}>
            {busy ? "Authorizing…" : "Allow read access"}
          </button>
          <button type="button" className="lp-nav-ghost" onClick={deny} disabled={busy}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
