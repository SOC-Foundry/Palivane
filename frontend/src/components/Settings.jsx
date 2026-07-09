import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const PROVIDERS = { openai: "OpenAI", anthropic: "Anthropic", gemini: "Gemini" };

function judgeValue(t) {
  return t?.judge_enabled === true ? "on" : t?.judge_enabled === false ? "off" : "inherit";
}

function enforceValue(t) {
  return t?.gateway_enforce === true ? "on" : t?.gateway_enforce === false ? "off" : "inherit";
}

const SEVERITIES = ["low", "suspicious", "high", "critical"];

export default function Settings({ tenant, currentUser, onTenant, onLogout }) {
  const [msg, setMsg] = useState(null);       // { ok, text }
  const flash = (text, ok = true) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 3000); };
  const err = (e) => flash(String(e.message || e).replace(/^\d+:\s*/, ""), false);

  // --- Organization ---
  const [org, setOrgState] = useState({
    name: tenant?.name || "", judge: judgeValue(tenant),
    retention_days: tenant?.retention_days ?? 0, rate_limit: tenant?.rate_limit ?? 0,
    ingest_rate_limit: tenant?.ingest_rate_limit ?? 0,
    mcp_allowed_servers: tenant?.mcp_allowed_servers || "",
    ide_ext_allowed: tenant?.ide_ext_allowed || "",
    ide_ext_denylist: tenant?.ide_ext_denylist || "",
    dep_denylist: tenant?.dep_denylist || "",
    gateway_enforce: enforceValue(tenant),
    gateway_block_severity: tenant?.gateway_block_severity || "",
    mcp_block_severity: tenant?.mcp_block_severity || "",
    sanctioned_ai_tools: tenant?.sanctioned_ai_tools || "",
    tool_suppress: tenant?.tool_suppress || "",
    custom_pii_patterns: tenant?.custom_pii_patterns || "",
    oversharing_rules: tenant?.oversharing_rules || "",
  });
  const setField = (k) => (e) => setOrgState((o) => ({ ...o, [k]: e.target.value }));

  async function saveOrg(e) {
    e.preventDefault();
    try {
      const t = await api.updateTenant({
        name: org.name, judge: org.judge,
        retention_days: Number(org.retention_days), rate_limit: Number(org.rate_limit),
        ingest_rate_limit: Number(org.ingest_rate_limit),
        mcp_allowed_servers: org.mcp_allowed_servers,
        ide_ext_allowed: org.ide_ext_allowed,
        ide_ext_denylist: org.ide_ext_denylist,
        dep_denylist: org.dep_denylist,
        gateway_enforce: org.gateway_enforce,
        gateway_block_severity: org.gateway_block_severity,
        mcp_block_severity: org.mcp_block_severity,
        sanctioned_ai_tools: org.sanctioned_ai_tools,
        tool_suppress: org.tool_suppress,
        custom_pii_patterns: org.custom_pii_patterns,
        oversharing_rules: org.oversharing_rules,
      });
      onTenant?.(t);
      flash("Organization settings saved.");
    } catch (e) { err(e); }
  }

  // --- Alerts & integrations ---
  const [alertCfg, setAlertCfg] = useState({
    webhook: "", min: tenant?.alert_min_severity || "high",
    digest: tenant?.alert_digest || "off", webhookSet: !!tenant?.alert_webhook_set,
  });
  async function saveAlerts() {
    try {
      const payload = { alert_min_severity: alertCfg.min, alert_digest: alertCfg.digest };
      if (alertCfg.webhook) payload.alert_webhook = alertCfg.webhook;   // write-only; only if changed
      const t = await api.updateTenant(payload);
      onTenant?.(t); setAlertCfg((a) => ({ ...a, webhook: "", webhookSet: !!t.alert_webhook_set }));
      flash("Alerts saved.");
    } catch (e) { err(e); }
  }
  async function testAlert() {
    try { const r = await api.testAlert(); flash(r.ok ? "Test alert sent." : "Webhook unreachable.", !!r.ok); }
    catch (e) { err(e); }
  }

  // --- SIEM forwarding ---
  const [siemCfg, setSiemCfg] = useState({
    url: tenant?.siem_url || "", token: "", min: tenant?.siem_min_severity || "high",
    format: tenant?.siem_format || "json", tokenSet: !!tenant?.siem_token_set,
  });
  async function saveSiem() {
    try {
      const payload = { siem_url: siemCfg.url, siem_min_severity: siemCfg.min, siem_format: siemCfg.format };
      if (siemCfg.token) payload.siem_token = siemCfg.token;   // write-only; only send if changed
      const t = await api.updateTenant(payload);
      onTenant?.(t); setSiemCfg((s) => ({ ...s, token: "", tokenSet: !!t.siem_token_set })); flash("SIEM saved.");
    } catch (e) { err(e); }
  }
  async function testSiem() {
    try { const r = await api.testSiem(); flash(r.ok ? "Test event sent to SIEM." : "SIEM endpoint unreachable.", !!r.ok); }
    catch (e) { err(e); }
  }
  function _download(text, name, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }
  async function exportFindings() {
    try { _download(await api.exportFindings(), "warden-findings.jsonl", "application/x-ndjson"); }
    catch (e) { err(e); }
  }

  // --- Data & compliance ---
  const [dpa, setDpa] = useState(null);
  const [inclContent, setInclContent] = useState(false);
  const [delText, setDelText] = useState("");
  const loadDpa = useCallback(() => api.dpa().then(setDpa).catch(() => {}), []);
  async function acceptDpa() {
    try { setDpa(await api.acceptDpa()); flash("DPA accepted and recorded."); } catch (e) { err(e); }
  }
  async function exportTenant() {
    try {
      _download(await api.exportTenant(inclContent), `warden-export-${tenant?.slug || "org"}.json`,
                "application/json");
    } catch (e) { err(e); }
  }
  async function deleteOrg() {
    try {
      await api.deleteTenant(delText.trim());
      flash("Organization deleted.");
      onLogout?.();
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

  // --- SAML SSO ---
  const [saml, setSamlState] = useState(null);
  const [samlDraft, setSamlDraft] = useState({ idp_entity_id: "", idp_sso_url: "", idp_x509_cert: "", allowed_domain: "" });
  const loadSaml = useCallback(() => api.saml().then((s) => {
    setSamlState(s);
    setSamlDraft((d) => ({ ...d, idp_entity_id: s.idp_entity_id || "",
      idp_sso_url: s.idp_sso_url || "", allowed_domain: s.allowed_domain || "" }));
  }).catch(() => {}), []);

  async function saveSaml(patch) {
    try {
      const s = await api.setSaml({ ...samlDraft, ...patch });
      setSamlState(s); setSamlDraft((d) => ({ ...d, idp_x509_cert: "" }));
      flash("SAML settings saved.");
    } catch (e) { err(e); }
  }
  async function disableSaml() {
    try { await api.deleteSaml(); await loadSaml(); flash("SAML removed."); } catch (e) { err(e); }
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

  useEffect(() => { loadUsage(); loadUps(); loadOidc(); loadSaml(); loadDpa(); },
    [loadUsage, loadUps, loadOidc, loadSaml, loadDpa]);

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
          <label>LLM judge
            <select value={org.judge} onChange={setField("judge")}>
              <option value="inherit">Inherit (global)</option>
              <option value="on">On</option>
              <option value="off">Off (no content sent to the LLM provider)</option>
            </select>
          </label>
          <label>Findings retention (days, 0 = forever)
            <input type="number" min="0" value={org.retention_days} onChange={setField("retention_days")} /></label>
          <label>Gateway rate limit (req/min, 0 = unlimited)
            <input type="number" min="0" value={org.rate_limit} onChange={setField("rate_limit")} /></label>
          <label>Ingest rate limit (sensors, req/min, 0 = unlimited)
            <input type="number" min="0" value={org.ingest_rate_limit} onChange={setField("ingest_rate_limit")} /></label>
          <label className="field-wide">Approved MCP servers (comma-separated hosts; empty = don't flag)
            <input placeholder="mcp.githubcopilot.com, mcp.acme.com"
                   value={org.mcp_allowed_servers} onChange={setField("mcp_allowed_servers")} /></label>
          <label className="field-wide">Approved IDE extensions (allowlist; empty = allow all)
            <input placeholder="ms-python.python, esbenp.prettier-vscode"
                   value={org.ide_ext_allowed} onChange={setField("ide_ext_allowed")} /></label>
          <label className="field-wide">Blocked IDE extensions (denylist)
            <input placeholder="publisher.badext"
                   value={org.ide_ext_denylist} onChange={setField("ide_ext_denylist")} /></label>
          <label className="field-wide">Blocked dependencies (denylist)
            <input placeholder="crossenv, colourama"
                   value={org.dep_denylist} onChange={setField("dep_denylist")} /></label>
        </div>
        <p className="muted" style={{ margin: "0 0 12px", fontSize: 12 }}>Supply-chain lists apply to
           the CI scans (<code>/api/scan/ide-extensions</code>, <code>/api/scan/deps</code>) and the
           MDM policy pack. Empty = inherit the global default.</p>

        <h3 style={{ margin: "4px 0 8px" }}>Policy</h3>
        <div className="field-grid">
          <label>Gateway mode
            <select value={org.gateway_enforce} onChange={setField("gateway_enforce")}>
              <option value="inherit">Inherit (global)</option>
              <option value="on">Enforce (block risky calls)</option>
              <option value="off">Monitor (record only)</option>
            </select>
          </label>
          <label>Gateway block severity
            <select value={org.gateway_block_severity} onChange={setField("gateway_block_severity")}>
              <option value="">Inherit (global)</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label>MCP block severity
            <select value={org.mcp_block_severity} onChange={setField("mcp_block_severity")}>
              <option value="">Inherit (global)</option>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="field-wide">Sanctioned AI tools (comma-separated hosts; empty = inherit)
            <input placeholder="chatgpt.com, claude.ai"
                   value={org.sanctioned_ai_tools} onChange={setField("sanctioned_ai_tools")} /></label>
          <label className="field-wide">Per-tool suppressions (tool:category;tool:category)
            <input placeholder="claude-code:source_code_leak;cursor:pii_exposure"
                   value={org.tool_suppress} onChange={setField("tool_suppress")} /></label>
          <label className="field-wide">Custom PII / confidential patterns (one <code>label=regex</code> per line)
            <textarea rows={3} placeholder={"Customer ID=CUST-\\d{8}\nMRN=MRN\\d{7}\nProject codename=(Bluebird|Falcon)"}
                      value={org.custom_pii_patterns} onChange={setField("custom_pii_patterns")} /></label>
          <label className="field-wide">Need-to-know rules (oversharing) — one <code>restricted = allowed-group</code> per line
            <textarea rows={3} placeholder={"confidential_data = *@acme.com\npii_exposure = *@hr.acme.com\nkw:salary = *@hr.acme.com,*@exec.acme.com"}
                      value={org.oversharing_rules} onChange={setField("oversharing_rules")} /></label>
        </div>
        <p className="muted" style={{ margin: "0 0 12px", fontSize: 12 }}>Block severity is the lowest
           verdict that blocks (lower = stricter). Suppressions drop a category for a named capture
           tool. Empty = inherit the global env default.</p>
        <button className="primary-btn slim">Save organization</button>
      </form>

      {/* Alerts & integrations */}
      <div className="panel settings-card">
        <h2>Alerts &amp; integrations</h2>
        <div className="field-grid">
          <label className="field-wide">Webhook URL (Slack-compatible — posts findings) {alertCfg.webhookSet && <span className="muted">(set — leave blank to keep)</span>}
            <input type="password" placeholder={alertCfg.webhookSet ? "••••••••" : "https://hooks.slack.com/services/…"}
                   value={alertCfg.webhook} onChange={(e) => setAlertCfg((a) => ({ ...a, webhook: e.target.value }))} /></label>
          <label>Alert on severity ≥
            <select value={alertCfg.min} onChange={(e) => setAlertCfg((a) => ({ ...a, min: e.target.value }))}>
              <option value="low">low</option>
              <option value="suspicious">suspicious</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select></label>
          <label>Delivery
            <select value={alertCfg.digest} onChange={(e) => setAlertCfg((a) => ({ ...a, digest: e.target.value }))}>
              <option value="off">real-time (every finding)</option>
              <option value="hourly">hourly digest</option>
              <option value="daily">daily digest</option>
            </select></label>
        </div>
        <div className="form-row" style={{ gap: 10 }}>
          <button type="button" className="primary-btn slim" onClick={saveAlerts}>Save alerts</button>
          <button type="button" className="mini-btn" onClick={testAlert}>Send test</button>
          <button type="button" className="mini-btn" onClick={exportFindings}>Export findings (JSONL)</button>
        </div>
        <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>In digest mode, alertable
           findings are batched into a rollup on the chosen cadence — <strong>critical findings
           still fire in real time</strong>. Findings export is for SIEM ingest. Alerts fail open
           — a down webhook never blocks capture.</p>
      </div>

      {/* SIEM forwarding */}
      <div className="panel settings-card">
        <h2>SIEM forwarding</h2>
        <p className="muted" style={{ fontSize: 12 }}>Stream findings to your SIEM in real time
           (complements the pull-based JSONL export above). Vendor-neutral — point it at any
           HTTP collector.</p>
        <div className="field-grid">
          <label className="field-wide">Collector URL
            <input placeholder="https://http-inputs.splunkcloud.com/services/collector"
                   value={siemCfg.url} onChange={(e) => setSiemCfg((s) => ({ ...s, url: e.target.value }))} /></label>
          <label className="field-wide">Token {siemCfg.tokenSet && <span className="muted">(set — leave blank to keep)</span>}
            <input type="password" placeholder={siemCfg.tokenSet ? "••••••••" : "HEC / bearer token"}
                   value={siemCfg.token} onChange={(e) => setSiemCfg((s) => ({ ...s, token: e.target.value }))} /></label>
          <label>Format
            <select value={siemCfg.format} onChange={(e) => setSiemCfg((s) => ({ ...s, format: e.target.value }))}>
              <option value="json">JSON (generic / Sentinel / Elastic)</option>
              <option value="splunk_hec">Splunk HEC</option>
              <option value="cef">CEF (syslog)</option>
            </select></label>
          <label>Forward severity ≥
            <select value={siemCfg.min} onChange={(e) => setSiemCfg((s) => ({ ...s, min: e.target.value }))}>
              <option value="low">low</option>
              <option value="suspicious">suspicious</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select></label>
        </div>
        <div className="form-row" style={{ gap: 10 }}>
          <button type="button" className="primary-btn slim" onClick={saveSiem}>Save SIEM</button>
          <button type="button" className="mini-btn" onClick={testSiem}>Send test event</button>
        </div>
        <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>Pushes each finding at/above
           the threshold as it's captured; SSRF-guarded and fail-open (a down collector never
           blocks capture). Internal/private endpoints are blocked — use a reachable collector.</p>
      </div>

      {/* Usage */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>Gateway usage</h2>
          <button type="button" className="mini-btn" onClick={loadUsage}>refresh</button></div>
        {usage ? (
          <>
            <div className="usage-stats">
              <div><span className="usage-n">{usage.current_window}</span><span className="usage-l">gateway / min</span></div>
              <div><span className="usage-n">{usage.last_24h}</span><span className="usage-l">gateway 24h</span></div>
              <div><span className="usage-n">{usage.ingest_last_24h ?? 0}</span><span className="usage-l">sensors 24h</span></div>
              <div><span className="usage-n">{usage.limit_per_min || "∞"}</span><span className="usage-l">gateway limit</span></div>
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

      {/* Data & compliance */}
      <div className="panel settings-card">
        <h2>Data &amp; compliance</h2>

        <div className="settings-sub">
          <h3 style={{ margin: "0 0 6px" }}>Data-processing agreement</h3>
          {dpa ? (
            dpa.accepted ? (
              <p className="muted">Accepted <strong>v{dpa.version}</strong>
                {dpa.accepted_at ? ` on ${dpa.accepted_at.slice(0, 10)}` : ""}
                {dpa.accepted_by ? ` by ${dpa.accepted_by}` : ""}.</p>
            ) : (
              <p className="muted">Current version <strong>v{dpa.current_version}</strong> — not yet accepted
                {dpa.version ? ` (last accepted v${dpa.version})` : ""}.</p>
            )
          ) : <p className="muted">…</p>}
          <button type="button" className="primary-btn slim" onClick={acceptDpa}
                  disabled={dpa?.accepted}>
            {dpa?.accepted ? "DPA accepted" : "Accept DPA"}
          </button>
        </div>

        <div className="settings-sub" style={{ marginTop: 16 }}>
          <h3 style={{ margin: "0 0 6px" }}>Data export</h3>
          <p className="muted" style={{ fontSize: 12 }}>A complete JSON export of this org — config, users,
             keys, findings, audit log, SSO/upstream settings, DPA record. Secrets are never included.</p>
          <label style={{ fontSize: 13 }}>
            <input type="checkbox" checked={inclContent}
                   onChange={(e) => setInclContent(e.target.checked)} /> include finding content (decrypted)
          </label>
          <div className="form-row" style={{ gap: 10, marginTop: 8 }}>
            <button type="button" className="primary-btn slim" onClick={exportTenant}>Download full export (JSON)</button>
            <button type="button" className="mini-btn" onClick={exportFindings}>Findings only (JSONL)</button>
          </div>
        </div>

        <div className="settings-sub danger-zone" style={{ marginTop: 16 }}>
          <h3 style={{ margin: "0 0 6px" }}>Delete organization</h3>
          <p className="muted" style={{ fontSize: 12 }}>Permanently deletes this org and <strong>all</strong> its
             data (findings, users, keys, audit log, everything). Irreversible. Type the org slug
             <code> {tenant?.slug}</code> to confirm.</p>
          <div className="form-row" style={{ gap: 10 }}>
            <input placeholder={tenant?.slug} value={delText} onChange={(e) => setDelText(e.target.value)} />
            <button type="button" className="mini-btn danger" onClick={deleteOrg}
                    disabled={delText.trim() !== tenant?.slug}>Delete organization</button>
          </div>
        </div>
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

      {/* SSO / SAML */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>Single sign-on (SAML)</h2>
          {saml?.enabled && <span className="chip chip-on">enabled</span>}</div>
        <p className="muted">We're the SP. Give your IdP the ACS URL
          <code> /api/auth/saml/{tenant?.slug}/acs</code> (SP metadata:
          <a href={`/api/auth/saml/${tenant?.slug}/metadata`} target="_blank" rel="noreferrer"> /metadata</a>).</p>
        <div className="field-grid">
          <label>IdP Entity ID
            <input value={samlDraft.idp_entity_id}
                   onChange={(e) => setSamlDraft((d) => ({ ...d, idp_entity_id: e.target.value }))} /></label>
          <label>IdP SSO URL
            <input placeholder="https://idp/sso" value={samlDraft.idp_sso_url}
                   onChange={(e) => setSamlDraft((d) => ({ ...d, idp_sso_url: e.target.value }))} /></label>
          <label>Allowed email domain (optional)
            <input placeholder="acme.com" value={samlDraft.allowed_domain}
                   onChange={(e) => setSamlDraft((d) => ({ ...d, allowed_domain: e.target.value }))} /></label>
          <label>IdP signing certificate (X.509)
            <input placeholder={saml?.cert_set ? "cert set — paste to replace" : "MIIC…"}
                   value={samlDraft.idp_x509_cert}
                   onChange={(e) => setSamlDraft((d) => ({ ...d, idp_x509_cert: e.target.value }))} /></label>
        </div>
        <div className="detail-actions">
          <button type="button" className="mini-btn" onClick={() => saveSaml({ enabled: true })}>Save &amp; enable</button>
          <button type="button" className="mini-btn" onClick={() => saveSaml({ enabled: false })}>Save (disabled)</button>
          <button type="button" className="mini-btn danger" onClick={disableSaml}>Remove SAML</button>
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
