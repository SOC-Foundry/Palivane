import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const PROVIDERS = { openai: "OpenAI", anthropic: "Anthropic", gemini: "Gemini" };

function judgeValue(t) {
  return t?.judge_enabled === true ? "on" : t?.judge_enabled === false ? "off" : "inherit";
}

export default function Settings({ tenant, currentUser, onTenant, onLogout }) {
  const [msg, setMsg] = useState(null);       // { ok, text }
  const flash = (text, ok = true) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 3000); };
  const err = (e) => flash(String(e.message || e).replace(/^\d+:\s*/, ""), false);

  // --- Organization ---
  const [org, setOrgState] = useState({
    name: tenant?.name || "", judge: judgeValue(tenant),
    retention_days: tenant?.retention_days ?? 0, rate_limit: tenant?.rate_limit ?? 0,
  });
  const setField = (k) => (e) => setOrgState((o) => ({ ...o, [k]: e.target.value }));

  async function saveOrg(e) {
    e.preventDefault();
    try {
      const t = await api.updateTenant({
        name: org.name, judge: org.judge,
        retention_days: Number(org.retention_days), rate_limit: Number(org.rate_limit),
      });
      onTenant?.(t);
      flash("Organization settings saved.");
    } catch (e) { err(e); }
  }

  // --- Usage ---
  const [usage, setUsage] = useState(null);
  const loadUsage = useCallback(() => api.usage().then(setUsage).catch(() => {}), []);

  // --- Upstreams ---
  const [ups, setUps] = useState([]);
  const [upDraft, setUpDraft] = useState({});   // provider -> {base_url, key}
  const loadUps = useCallback(() => api.upstreams().then((r) => setUps(r.upstreams)).catch(() => {}), []);

  async function saveUpstream(p) {
    const d = upDraft[p] || {};
    try {
      await api.setUpstream(p, { base_url: d.base_url || "", key: d.key || "" });
      setUpDraft((s) => ({ ...s, [p]: { ...d, key: "" } }));   // clear the key field
      await loadUps();
      flash(`${PROVIDERS[p]} upstream saved.`);
    } catch (e) { err(e); }
  }
  async function clearUpstream(p) {
    try { await api.deleteUpstream(p); await loadUps(); flash(`${PROVIDERS[p]} reset to global default.`); }
    catch (e) { err(e); }
  }

  // --- OIDC ---
  const [oidc, setOidcState] = useState(null);
  const [oidcDraft, setOidcDraft] = useState({ issuer: "", client_id: "", client_secret: "", allowed_domain: "" });
  const loadOidc = useCallback(() => api.oidc().then((o) => {
    setOidcState(o);
    setOidcDraft((d) => ({ ...d, issuer: o.issuer || "", client_id: o.client_id || "", allowed_domain: o.allowed_domain || "" }));
  }).catch(() => {}), []);

  async function saveOidc(patch) {
    try {
      const o = await api.setOidc({ ...oidcDraft, ...patch });
      setOidcState(o);
      setOidcDraft((d) => ({ ...d, client_secret: "" }));
      flash("SSO settings saved.");
    } catch (e) { err(e); }
  }
  async function disableOidc() {
    try { await api.deleteOidc(); await loadOidc(); flash("SSO removed."); } catch (e) { err(e); }
  }

  // --- MFA (TOTP) ---
  const [mfaOn, setMfaOn] = useState(!!currentUser?.mfa_enabled);
  const [enroll, setEnroll] = useState(null);        // { secret, otpauth_uri }
  const [mfaCode, setMfaCode] = useState("");
  const [recovery, setRecovery] = useState(null);    // shown once after confirm
  const [disableCode, setDisableCode] = useState("");

  async function startMfa() {
    try { setEnroll(await api.mfaSetup()); setRecovery(null); } catch (e) { err(e); }
  }
  async function confirmMfa() {
    try {
      const r = await api.mfaConfirm(mfaCode.trim());
      setRecovery(r.recovery_codes); setMfaOn(true); setEnroll(null); setMfaCode("");
      flash("Two-factor enabled.");
    } catch (e) { err(e); }
  }
  async function disableMfa() {
    try {
      await api.mfaDisable(disableCode.trim());
      setMfaOn(false); setRecovery(null); setDisableCode("");
      flash("Two-factor disabled.");
    } catch (e) { err(e); }
  }

  useEffect(() => { loadUsage(); loadUps(); loadOidc(); }, [loadUsage, loadUps, loadOidc]);

  async function logoutEverywhere() {
    try { await api.logoutAll(); } catch { /* ignore */ }
    onLogout?.();
  }

  return (
    <div className="settings">
      <div className="content-head">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-sub">Organization, gateway upstreams, SSO, and usage — admin only.</p>
        </div>
      </div>
      {msg && <div className={msg.ok ? "flash-ok" : "flash-err"}>{msg.text}</div>}

      {/* Organization */}
      <form className="panel settings-card" onSubmit={saveOrg}>
        <h2>Organization</h2>
        <div className="field-grid">
          <label>Name<input value={org.name} onChange={setField("name")} /></label>
          <label>Claude judge
            <select value={org.judge} onChange={setField("judge")}>
              <option value="inherit">Inherit (global)</option>
              <option value="on">On</option>
              <option value="off">Off (no content to Anthropic)</option>
            </select>
          </label>
          <label>Findings retention (days, 0 = forever)
            <input type="number" min="0" value={org.retention_days} onChange={setField("retention_days")} /></label>
          <label>Gateway rate limit (req/min, 0 = unlimited)
            <input type="number" min="0" value={org.rate_limit} onChange={setField("rate_limit")} /></label>
        </div>
        <button className="primary-btn slim">Save organization</button>
      </form>

      {/* Usage */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>Gateway usage</h2>
          <button type="button" className="mini-btn" onClick={loadUsage}>refresh</button></div>
        {usage ? (
          <>
            <div className="usage-stats">
              <div><span className="usage-n">{usage.current_window}</span><span className="usage-l">this minute</span></div>
              <div><span className="usage-n">{usage.last_24h}</span><span className="usage-l">last 24h</span></div>
              <div><span className="usage-n">{usage.limit_per_min || "∞"}</span><span className="usage-l">limit / min</span></div>
            </div>
            {Object.keys(usage.by_day || {}).length > 0 && (
              <ul className="usage-days">
                {Object.entries(usage.by_day).map(([d, n]) => (
                  <li key={d}><span>{d}</span><span className="usage-daycount">{n}</span></li>
                ))}
              </ul>
            )}
          </>
        ) : <p className="muted">No usage yet.</p>}
      </div>

      {/* Upstreams */}
      <div className="panel settings-card">
        <h2>Gateway upstreams</h2>
        <p className="muted">Each org forwards allowed gateway calls with its own provider key
          (stored encrypted). Leave blank to use the global default.</p>
        {ups.map((u) => {
          const d = upDraft[u.provider] || {};
          return (
            <div key={u.provider} className="upstream-row">
              <div className="upstream-name">{PROVIDERS[u.provider]}
                <span className={`chip ${u.effective === "tenant" ? "chip-on" : "chip-off"}`}>
                  {u.effective === "tenant" ? "org key" : "global"}</span>
              </div>
              <input placeholder="base URL (optional)" value={d.base_url ?? u.base_url ?? ""}
                     onChange={(e) => setUpDraft((s) => ({ ...s, [u.provider]: { ...d, base_url: e.target.value } }))} />
              <input type="password" placeholder={u.key_set ? "key set — enter to replace" : "API key"}
                     value={d.key || ""}
                     onChange={(e) => setUpDraft((s) => ({ ...s, [u.provider]: { ...d, key: e.target.value } }))} />
              <button type="button" className="mini-btn" onClick={() => saveUpstream(u.provider)}>Save</button>
              <button type="button" className="mini-btn" onClick={() => clearUpstream(u.provider)}>Reset</button>
            </div>
          );
        })}
      </div>

      {/* SSO / OIDC */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>Single sign-on (OIDC)</h2>
          {oidc?.enabled && <span className="chip chip-on">enabled</span>}</div>
        <div className="field-grid">
          <label>Issuer URL
            <input placeholder="https://accounts.google.com" value={oidcDraft.issuer}
                   onChange={(e) => setOidcDraft((d) => ({ ...d, issuer: e.target.value }))} /></label>
          <label>Client ID
            <input value={oidcDraft.client_id}
                   onChange={(e) => setOidcDraft((d) => ({ ...d, client_id: e.target.value }))} /></label>
          <label>Client secret
            <input type="password" placeholder={oidc?.secret_set ? "secret set — enter to replace" : "client secret"}
                   value={oidcDraft.client_secret}
                   onChange={(e) => setOidcDraft((d) => ({ ...d, client_secret: e.target.value }))} /></label>
          <label>Allowed email domain (optional)
            <input placeholder="acme.com" value={oidcDraft.allowed_domain}
                   onChange={(e) => setOidcDraft((d) => ({ ...d, allowed_domain: e.target.value }))} /></label>
        </div>
        <div className="detail-actions">
          <button type="button" className="mini-btn" onClick={() => saveOidc({ enabled: true })}>Save &amp; enable</button>
          <button type="button" className="mini-btn" onClick={() => saveOidc({ enabled: false })}>Save (disabled)</button>
          <button type="button" className="mini-btn danger" onClick={disableOidc}>Remove SSO</button>
        </div>
      </div>

      {/* Two-factor */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>Two-factor authentication</h2>
          {mfaOn && !recovery && <span className="chip chip-on">on</span>}</div>

        {recovery && (
          <div className="mfa-recovery">
            <p className="muted">Two-factor is on. Save these one-time recovery codes now — they
              won't be shown again.</p>
            <ul className="recovery-codes">{recovery.map((c) => <li key={c}>{c}</li>)}</ul>
          </div>
        )}

        {!mfaOn && !enroll && (
          <>
            <p className="muted">Require a time-based code (TOTP) at sign-in, in addition to your password.</p>
            <button type="button" className="mini-btn" onClick={startMfa}>Enable 2FA</button>
          </>
        )}

        {enroll && (
          <div className="mfa-enroll">
            <p className="muted">Add this secret to your authenticator app, then enter a code to confirm.</p>
            <div className="mfa-secret">{enroll.secret}</div>
            <div className="mfa-uri">{enroll.otpauth_uri}</div>
            <div className="mfa-confirm-row">
              <input inputMode="numeric" placeholder="123456" value={mfaCode}
                     onChange={(e) => setMfaCode(e.target.value)} />
              <button type="button" className="mini-btn" onClick={confirmMfa}>Confirm</button>
              <button type="button" className="mini-btn" onClick={() => { setEnroll(null); setMfaCode(""); }}>Cancel</button>
            </div>
          </div>
        )}

        {mfaOn && !recovery && (
          <div className="mfa-confirm-row">
            <input inputMode="numeric" placeholder="code to disable" value={disableCode}
                   onChange={(e) => setDisableCode(e.target.value)} />
            <button type="button" className="mini-btn danger" onClick={disableMfa}>Disable 2FA</button>
          </div>
        )}
      </div>

      {/* Session */}
      <div className="panel settings-card">
        <h2>Session</h2>
        <p className="muted">Revoke every active session for your account (including this one).</p>
        <button type="button" className="mini-btn danger" onClick={logoutEverywhere}>Log out everywhere</button>
      </div>
    </div>
  );
}
