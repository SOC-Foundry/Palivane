import { useEffect, useState } from "react";
import { api } from "../api.js";

// The OAuth consent screen. Reached only as a redirect from /authorize, which cannot
// authenticate the browser itself: the console's session lives in localStorage, not a
// cookie, so the authorize endpoint sees an anonymous request however thoroughly the user
// is signed in. This page is the one place that holds the token, so it owns the approval.
//
// What it deliberately does NOT do is render anything out of its own query string: what it
// shows comes from /api/oauth/pending, resolved server-side against the registration. That
// stops a crafted URL renaming a real client, but not a client registered under a lying
// name — registration is open — which is why the page leads with the redirect host, the
// one thing an app can't misstate, and labels the name as the app's own claim.
export default function OAuthConsent() {
  const q = new URLSearchParams(window.location.search);
  const clientId = q.get("client_id") || "";
  const redirectUri = q.get("redirect_uri") || "";
  const state = q.get("state") || "";
  const challenge = q.get("code_challenge") || "";
  const requested = q.get("scope") || "";

  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  // Write scopes the app asked for, each a box the person can untick. What is offered comes
  // from the server (within the app's registration), never from the URL alone.
  const [declined, setDeclined] = useState({});

  useEffect(() => {
    api.oauthPending(clientId, redirectUri, requested)
      .then(setInfo)
      .catch((e) => setError(e.message || "This authorization request is not valid."));
  }, [clientId, redirectUri, requested]);

  const writes = (info?.scopes || []).filter((s) => s.writes);
  const granted = (info?.scopes || []).filter((s) => !s.writes || !declined[s.scope]);
  const grantsWrite = granted.some((s) => s.writes);

  const approve = async () => {
    setBusy(true);
    try {
      const r = await api.oauthConsent({
        client_id: clientId, redirect_uri: redirectUri,
        code_challenge: challenge, state,
        scope: granted.map((s) => s.scope).join(" "),
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
            again. If it keeps failing, the app may be registered with a different
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
        {/* Lead with where the grant goes, not what the app calls itself: registration is
            open, so the name is whatever its registrant typed, "Palivane" included. The
            redirect host is the one thing the app cannot fake, because the code goes there. */}
        <h1 className="dsp">
          {info.redirect_local
            ? <>Allow an app <strong>on this computer</strong> to {grantsWrite ? "use" : "read"} your Palivane data?</>
            : <>Allow an app at <strong>{info.redirect_host}</strong> to {grantsWrite ? "use" : "read"} your Palivane data?</>}
        </h1>
        <p className="consent-lead">{info.scope_description}</p>

        <dl className="consent-facts">
          <div>
            <dt>Calls itself</dt>
            <dd>“{info.client_name}” <span className="consent-unverified">(not verified: any app can use any name)</span></dd>
          </div>
          <div><dt>Granting as</dt><dd>{info.granting_as.email} ({info.granting_as.role})</dd></div>
          <div><dt>Sends you back to</dt><dd><code>{info.redirect_uri}</code></dd></div>
          <div><dt>Access</dt><dd>{grantsWrite
            ? "Read, and change a finding's status. It cannot delete anything or change settings, users or keys"
            : "Read only, so it cannot change or delete anything"}</dd></div>
        </dl>

        {writes.length > 0 && (
          <div className="consent-writes">
            <p className="consent-writes-head">It also asks to change things:</p>
            {writes.map((s) => (
              <label key={s.scope} className="check">
                <input type="checkbox" checked={!declined[s.scope]}
                       onChange={(e) => setDeclined((d) => ({ ...d, [s.scope]: !e.target.checked }))} />
                {s.description}
              </label>
            ))}
          </div>
        )}

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
            {busy ? "Authorizing…" : grantsWrite ? "Allow" : "Allow read access"}
          </button>
          <button type="button" className="lp-nav-ghost" onClick={deny} disabled={busy}>Cancel</button>
        </div>
      </div>
    </div>
  );
}
