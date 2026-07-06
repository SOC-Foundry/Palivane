import { useEffect, useState } from "react";
import { api, setToken } from "../api.js";

export default function Login({ onAuthed, onBack }) {
  const [mode, setMode] = useState("signin");   // "signin" | "signup"
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [allowSignup, setAllowSignup] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState(null);   // set when login needs a 2nd factor
  const [mfaCode, setMfaCode] = useState("");

  // Only offer self-serve org creation when the server permits it.
  useEffect(() => {
    api.health().then((h) => setAllowSignup(!!h.allow_signup)).catch(() => setAllowSignup(false));
  }, []);

  const signup = mode === "signup";

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const res = signup
        ? await api.signup(org.trim(), email.trim(), password)
        : await api.login(email.trim(), password, org.trim());
      if (res.mfa_required) { setMfaChallenge(res.challenge); return; }   // second-factor step
      setToken(res.access_token);
      onAuthed(res.user);
    } catch (e) {
      const msg = String(e.message || e);
      setErr(
        msg.includes("401") ? "Invalid email or password." :
        msg.includes("403") ? "Self-serve signup is disabled here." :
        msg.includes("409") ? "This email belongs to more than one organization — enter your organization." :
        msg.includes("429") ? "Too many attempts. Please wait a few minutes and try again." :
        msg
      );
    } finally {
      setBusy(false);
    }
  }

  function ssoLogin() {
    if (!org.trim()) { setErr("Enter your organization to sign in with SSO."); return; }
    window.location.href = `/api/auth/sso/${encodeURIComponent(org.trim())}/login`;
  }

  async function submitMfa(e) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      const res = await api.mfaVerify(mfaChallenge, mfaCode.trim());
      setToken(res.access_token);
      onAuthed(res.user);
    } catch (e) {
      const msg = String(e.message || e);
      setErr(msg.includes("429") ? "Too many attempts. Please wait and try again." :
             "Invalid code. Try again, or use a recovery code.");
    } finally { setBusy(false); }
  }

  if (mfaChallenge) {
    return (
      <div className="login-screen">
        <form className="login-card" onSubmit={submitMfa}>
          <img className="login-logo" src="/warden-logo.png" alt="Warden" width="76" height="76" />
          <div className="brand"><span className="logo">◆</span> Warden</div>
          <p className="login-sub">Enter the 6-digit code from your authenticator app (or a recovery code).</p>
          <input autoFocus inputMode="numeric" placeholder="123456" value={mfaCode}
                 onChange={(e) => setMfaCode(e.target.value)} required />
          {err && <div className="error">{err}</div>}
          <button className="primary-btn" disabled={busy || !mfaCode}>{busy ? "…" : "Verify"}</button>
          <button type="button" className="link-btn link-muted"
                  onClick={() => { setMfaChallenge(null); setMfaCode(""); setErr(null); }}>
            ← Back
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <img className="login-logo" src="/warden-emblem.png" alt="Warden" />
        <div className="login-wordmark">WARDEN</div>
        <p className="login-sub">
          {signup ? "Create your organization" : "Sign in to your security workspace"}
        </p>
        <input placeholder={signup ? "organization name" : "organization (only if required)"}
               value={org} onChange={(e) => setOrg(e.target.value)}
               autoFocus={signup} required={signup} />

        <input type="email" placeholder="email" value={email}
               onChange={(e) => setEmail(e.target.value)} autoFocus={!signup} required />
        <input type="password" placeholder={signup ? "password (min 8 chars)" : "password"}
               value={password} onChange={(e) => setPassword(e.target.value)} required />
        {err && <div className="error">{err}</div>}
        <button className="primary-btn" disabled={busy || !email || !password || (signup && !org)}>
          {busy ? "…" : signup ? "Create organization" : "Sign in"}
        </button>
        {!signup && (
          <button type="button" className="sso-btn" onClick={ssoLogin}>
            Sign in with SSO
          </button>
        )}
        {(allowSignup || signup) && (
          <button type="button" className="link-btn" style={{ marginTop: 10 }}
                  onClick={() => { setErr(null); setMode(signup ? "signin" : "signup"); }}>
            {signup ? "← Back to sign in" : "Create a new organization →"}
          </button>
        )}
        {onBack && !signup && (
          <button type="button" className="link-btn link-muted" onClick={onBack}>
            ← Back to home
          </button>
        )}
      </form>
    </div>
  );
}
