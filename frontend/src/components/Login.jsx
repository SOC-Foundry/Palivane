import { useEffect, useState } from "react";
import { api, setToken } from "../api.js";

export default function Login({ onAuthed, onBack }) {
  const [mode, setMode] = useState("signin");   // "signin" | "signup" | "forgot" | "reset"
  const [resetToken, setResetToken] = useState(null);
  const [notice, setNotice] = useState(null);   // green info banner (sent / reset ok)
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [allowSignup, setAllowSignup] = useState(false);
  const [mfaChallenge, setMfaChallenge] = useState(null);   // set when login needs a 2nd factor
  const [mfaCode, setMfaCode] = useState("");
  const [pendingOrg, setPendingOrg] = useState(null);       // signup became a join request
  const [pendingKind, setPendingKind] = useState("approval"); // "approval" | "email"

  // Only offer self-serve org creation when the server permits it.
  useEffect(() => {
    api.health().then((h) => {
      setAllowSignup(!!h.allow_signup);
      setEmailEnabled(!!h.email_enabled);
    }).catch(() => setAllowSignup(false));
    // Password-reset links land as /#reset=TOKEN (fragment: never sent to the server).
    const m = window.location.hash.match(/^#reset=(.+)$/);
    if (m) {
      setResetToken(m[1]);
      setMode("reset");
      window.history.replaceState(null, "", window.location.pathname);
    }
    // Join-confirm links bounce back as /#join=approved|verified|invalid.
    const j = window.location.hash.match(/^#join=(\w+)$/);
    if (j) {
      window.history.replaceState(null, "", window.location.pathname);
      if (j[1] === "approved") setNotice("Email confirmed — your account is ready. Sign in with the password you chose.");
      else if (j[1] === "verified") setNotice("Email confirmed — an admin has been notified and will approve your request.");
      else setErr("That confirmation link is invalid or has expired — sign up again to get a new one.");
    }
    // New-org signup verify links bounce back as /#verified=ok|bad.
    const v = window.location.hash.match(/^#verified=(\w+)$/);
    if (v) {
      window.history.replaceState(null, "", window.location.pathname);
      if (v[1] === "ok") setNotice("Email verified — your organization is active. Sign in with your password.");
      else setErr("That verification link is invalid or has expired — sign up again to get a new one.");
    }
  }, []);

  const signup = mode === "signup";

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setNotice(null);
    try {
      if (mode === "forgot") {
        await api.forgot(email.trim(), org.trim());
        setNotice("If that address has an account, a reset link is on its way. It's valid for 30 minutes.");
        setMode("signin");
        return;
      }
      if (mode === "reset") {
        await api.resetPassword(resetToken, password);
        setNotice("Password updated — sign in with your new password.");
        setMode("signin"); setPassword(""); setResetToken(null);
        return;
      }
      const res = signup
        ? await api.signup(org.trim(), email.trim(), password)
        : await api.login(email.trim(), password, org.trim());
      if (res.mfa_required) { setMfaChallenge(res.challenge); return; }   // second-factor step
      // Domain capture: the email belongs to an org already on Palivane — request queued.
      if (res.status === "pending_approval") { setPendingKind("approval"); setPendingOrg(res.org); return; }
      if (res.status === "confirm_email") { setPendingKind("email"); setPendingOrg(res.org); return; }
      // New-org signup with the email plane on — must verify the mailbox first.
      if (res.status === "verify_email") { setPendingKind("verify"); setPendingOrg(res.org); return; }
      setToken(res.access_token);
      onAuthed(res.user);
    } catch (e) {
      const msg = String(e.message || e);
      setErr(
        mode === "reset" ? "That reset link is invalid or has expired — request a new one." :
        msg.includes("401") ? "Invalid email or password." :
        msg.includes("403") && msg.includes("suspended") ? "This organization is suspended." :
        msg.includes("403") ? "Self-serve signup is disabled here." :
        msg.includes("409") && signup && msg.includes("awaiting approval")
          ? "Your join request is still awaiting an admin's approval." :
        msg.includes("409") && signup && msg.includes("sign in instead")
          ? "You already have an account in your organization — sign in instead." :
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

  if (pendingOrg) {
    return (
      <div className="login-screen">
        <div className="login-card">
          <img className="login-logo" src="/palivane-emblem.png" alt="Palivane" />
          <div className="login-wordmark">PALIVANE</div>
          <p className="login-sub">
            {pendingKind === "verify" ? (
              <>Almost there — we emailed a link to verify your address and activate
              <strong> {pendingOrg}</strong>. Click it, then sign in.</>
            ) : pendingKind === "email" ? (
              <><strong>{pendingOrg}</strong> is already on Palivane. We emailed you a
              confirmation link — click it to verify your address and complete your
              request to join.</>
            ) : (
              <><strong>{pendingOrg}</strong> is already on Palivane, so we sent your request to
              its administrators instead of creating a new organization. You can sign in with
              the password you chose once an admin approves you.</>
            )}
          </p>
          <button type="button" className="primary-btn"
                  onClick={() => { setPendingOrg(null); setMode("signin"); setErr(null); }}>
            Back to sign in
          </button>
        </div>
      </div>
    );
  }

  if (mfaChallenge) {
    return (
      <div className="login-screen">
        <form className="login-card" onSubmit={submitMfa}>
          <img className="login-logo" src="/palivane-logo.png" alt="Palivane" width="76" height="76" />
          <div className="brand"><span className="logo">◆</span> Palivane</div>
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
        <img className="login-logo" src="/palivane-emblem.png" alt="Palivane" />
        <div className="login-wordmark">PALIVANE</div>
        <p className="login-sub">
          {mode === "signup" ? "Create your organization" :
           mode === "forgot" ? "We'll email you a password-reset link" :
           mode === "reset" ? "Choose a new password" :
           "Sign in to your security workspace"}
        </p>
        {mode !== "reset" && (
          <input placeholder={signup ? "organization name" : "organization (only if required)"}
                 value={org} onChange={(e) => setOrg(e.target.value)}
                 autoFocus={signup} required={signup} />
        )}
        {mode !== "reset" && (
          <input type="email" placeholder="email" value={email}
                 onChange={(e) => setEmail(e.target.value)} autoFocus={!signup} required />
        )}
        {mode !== "forgot" && (
          <input type="password"
                 placeholder={mode === "signin" ? "password" : "new password (min 8 chars)"}
                 value={password} onChange={(e) => setPassword(e.target.value)}
                 autoFocus={mode === "reset"} required />
        )}
        {notice && <div className="login-sub" style={{ color: "var(--ok, #4caf50)" }}>{notice}</div>}
        {err && <div className="error">{err}</div>}
        <button className="primary-btn"
                disabled={busy || (mode === "forgot" ? !email : !password || (mode !== "reset" && !email)) || (signup && !org)}>
          {busy ? "…" :
           mode === "signup" ? "Create organization" :
           mode === "forgot" ? "Send reset link" :
           mode === "reset" ? "Set new password" : "Sign in"}
        </button>
        {mode === "signin" && (
          <button type="button" className="sso-btn" onClick={ssoLogin}>
            Sign in with SSO
          </button>
        )}
        {mode === "signin" && emailEnabled && (
          <button type="button" className="link-btn link-muted"
                  onClick={() => { setErr(null); setNotice(null); setMode("forgot"); }}>
            Forgot password?
          </button>
        )}
        {(mode === "forgot" || mode === "reset") && (
          <button type="button" className="link-btn link-muted"
                  onClick={() => { setErr(null); setNotice(null); setMode("signin"); }}>
            ← Back to sign in
          </button>
        )}
        {(mode === "signin" || mode === "signup") && (allowSignup || signup) && (
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
