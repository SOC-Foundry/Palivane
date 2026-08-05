import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";

const PROVIDERS = { openai: "OpenAI", anthropic: "Anthropic", gemini: "Gemini" };

function judgeValue(t) {
  return t?.judge_enabled === true ? "on" : t?.judge_enabled === false ? "off" : "inherit";
}

function enforceValue(t) {
  return t?.gateway_enforce === true ? "on" : t?.gateway_enforce === false ? "off" : "inherit";
}

function clientEnforceValue(t) {
  return t?.client_enforce === true ? "on" : t?.client_enforce === false ? "off" : "inherit";
}

const SEVERITIES = ["low", "suspicious", "high", "critical"];

export default function Settings({ tenant, currentUser, onTenant, onLogout }) {
  const [msg, setMsg] = useState(null);       // { ok, text }
  const flash = (text, ok = true) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 3000); };
  const err = (e) => flash(String(e.message || e).replace(/^\d+:\s*/, ""), false);

  // Licensing plan (display hints only — the API enforces the gates).
  const plan = tenant?.plan || "free";
  // plan_label comes from the server so "Trial expired" / "Free (self-hosted)" read
  // correctly instead of being title-cased from the raw key.
  const planLabel = tenant?.plan_label || (plan.charAt(0).toUpperCase() + plan.slice(1));
  const trialLeft = tenant?.trial_days_left;   // null unless on a hosted trial
  const can = (f) => (tenant?.plan_features || []).includes(f);
  const NEEDS = { alerts: "Team", mdm: "Team", sso: "Enterprise", siem: "Enterprise", s3_delivery: "Enterprise" };
  const PlanLock = ({ need }) => can(need) ? null : (
    <p className="muted" style={{ marginTop: 2 }}>🔒 {NEEDS[need]} plan feature — request an
      upgrade under “Your plan” above to enable.</p>
  );

  // --- Organization ---
  const [org, setOrgState] = useState({
    name: tenant?.name || "", judge: judgeValue(tenant),
    store_content: tenant?.store_content === true ? "on" : tenant?.store_content === false ? "off" : "inherit",
    retention_days: tenant?.retention_days ?? 0, rate_limit: tenant?.rate_limit ?? 0,
    ingest_rate_limit: tenant?.ingest_rate_limit ?? 0,
    mcp_allowed_servers: tenant?.mcp_allowed_servers || "",
    ide_ext_allowed: tenant?.ide_ext_allowed || "",
    ide_ext_denylist: tenant?.ide_ext_denylist || "",
    dep_denylist: tenant?.dep_denylist || "",
    gateway_enforce: enforceValue(tenant),
    client_enforce: clientEnforceValue(tenant),
    gateway_block_severity: tenant?.gateway_block_severity || "",
    mcp_block_severity: tenant?.mcp_block_severity || "",
    ci_block_severity: tenant?.ci_block_severity || "",
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
        name: org.name, judge: org.judge, store_content: org.store_content,
        retention_days: Number(org.retention_days), rate_limit: Number(org.rate_limit),
        ingest_rate_limit: Number(org.ingest_rate_limit),
        mcp_allowed_servers: org.mcp_allowed_servers,
        ide_ext_allowed: org.ide_ext_allowed,
        ide_ext_denylist: org.ide_ext_denylist,
        dep_denylist: org.dep_denylist,
        gateway_enforce: org.gateway_enforce,
        client_enforce: org.client_enforce,
        gateway_block_severity: org.gateway_block_severity,
        mcp_block_severity: org.mcp_block_severity,
        ci_block_severity: org.ci_block_severity,
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
    format: tenant?.siem_format || "json", naming: tenant?.siem_naming || "warden",
    tokenSet: !!tenant?.siem_token_set,
  });
  async function saveSiem() {
    try {
      const payload = { siem_url: siemCfg.url, siem_min_severity: siemCfg.min,
                        siem_format: siemCfg.format, siem_naming: siemCfg.naming };
      if (siemCfg.token) payload.siem_token = siemCfg.token;   // write-only; only send if changed
      const t = await api.updateTenant(payload);
      onTenant?.(t); setSiemCfg((s) => ({ ...s, token: "", tokenSet: !!t.siem_token_set,
                                          naming: t.siem_naming || "warden" })); flash("SIEM saved.");
    } catch (e) { err(e); }
  }
  async function testSiem() {
    try { const r = await api.testSiem(); flash(r.ok ? "Test event sent to SIEM." : "SIEM endpoint unreachable.", !!r.ok); }
    catch (e) { err(e); }
  }

  // --- SIEM S3 / data-lake delivery ---
  const [s3Cfg, setS3Cfg] = useState({
    bucket: tenant?.siem_s3_bucket || "", prefix: tenant?.siem_s3_prefix || "",
    region: tenant?.siem_s3_region || "", keyId: "", secret: "",
    configured: !!tenant?.siem_s3_configured,
  });
  async function saveS3() {
    try {
      const payload = { siem_s3_bucket: s3Cfg.bucket, siem_s3_prefix: s3Cfg.prefix, siem_s3_region: s3Cfg.region };
      if (s3Cfg.keyId) payload.siem_s3_key_id = s3Cfg.keyId;    // write-only; only send if changed
      if (s3Cfg.secret) payload.siem_s3_secret = s3Cfg.secret;
      const t = await api.updateTenant(payload);
      onTenant?.(t);
      setS3Cfg((s) => ({ ...s, keyId: "", secret: "", configured: !!t.siem_s3_configured }));
      flash("S3 delivery saved.");
    } catch (e) { err(e); }
  }
  async function testS3() {
    try { const r = await api.testSiemS3(); flash(r.ok ? "Test object written to S3." : `S3 write failed: ${r.detail || "check config"}`, !!r.ok); }
    catch (e) { err(e); }
  }
  function _download(text, name, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }
  async function exportFindings() {
    try { _download(await api.exportFindings(), "palivane-findings.jsonl", "application/x-ndjson"); }
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
      _download(await api.exportTenant(inclContent), `palivane-export-${tenant?.slug || "org"}.json`,
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

  // --- Plan catalog (entitlements panel; rendered from the backend so it can't drift) ---
  const [catalog, setCatalog] = useState(null);
  const loadCatalog = useCallback(() => api.planCatalog().then(setCatalog).catch(() => {}), []);

  // --- Upgrade request (the in-app upgrade path; sales-led, one pending per org) ---
  const [upgrade, setUpgrade] = useState(null);          // latest request row or null
  const [upDraftPlan, setUpDraftPlan] = useState({ plan: "team", seats: "", note: "" });
  const loadUpgrade = useCallback(
    () => api.upgradeRequest().then((r) => setUpgrade(r.request)).catch(() => {}), []);

  async function submitUpgrade(e) {
    e.preventDefault();
    try {
      const r = await api.requestUpgrade(upDraftPlan.plan, Number(upDraftPlan.seats) || 0,
                                         upDraftPlan.note);
      setUpgrade(r.request);
      flash("Upgrade requested — we'll be in touch shortly.");
    } catch (e2) { err(e2); }
  }

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

  // --- BYOK judge key ---
  const [judgeKey, setJudgeKeyState] = useState(null);   // {provider, model, key_set}
  const [jkDraft, setJkDraft] = useState({ provider: "anthropic", key: "", model: "" });
  const loadJudgeKey = useCallback(() => api.judgeKey().then((j) => {
    setJudgeKeyState(j);
    setJkDraft((d) => ({ ...d, provider: j.provider || "anthropic", model: j.model || "" }));
  }).catch(() => {}), []);

  async function saveJudgeKey(e) {
    e.preventDefault();
    try {
      await api.setJudgeKey({ provider: jkDraft.provider, key: jkDraft.key, model: jkDraft.model });
      setJkDraft((d) => ({ ...d, key: "" }));             // key is write-only
      await loadJudgeKey();
      flash("Judge key saved — the LLM judge now runs on your org's own key.");
    } catch (e2) { err(e2); }
  }
  async function clearJudgeKey() {
    try { await api.deleteJudgeKey(); await loadJudgeKey(); flash("Judge key removed."); }
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

  useEffect(() => { loadUsage(); loadUps(); loadJudgeKey(); loadOidc(); loadSaml(); loadDpa(); loadCatalog(); loadUpgrade(); },
    [loadUsage, loadUps, loadJudgeKey, loadOidc, loadSaml, loadDpa, loadCatalog, loadUpgrade]);

  async function logoutEverywhere() {
    try { await api.logoutAll(); } catch { /* ignore */ }
    onLogout?.();
  }

  return (
    <div className="settings">
      <div className="content-head">
        <div>
          <h1 className="page-title">Settings
            <span className={`chip ${plan === "enterprise" ? "chip-on" : "chip-off"}`}
                  style={{ marginLeft: 10, verticalAlign: "middle" }}>{planLabel} plan</span>
          </h1>
          <p className="page-sub">Organization, gateway upstreams, SSO, and usage — admin only.
            {plan !== "enterprise" && (
              <> &nbsp;Need SSO, SIEM, or higher limits? Request an upgrade under “Your plan” below.</>
            )}
          </p>
        </div>
      </div>
      {msg && <div className={msg.ok ? "flash-ok" : "flash-err"}>{msg.text}</div>}

      {/* Your plan — entitlements comparison across tiers, current one highlighted */}
      {catalog && (
        <div className="panel settings-card">
          <h2>Your plan</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            You're on the <strong>{planLabel}</strong> plan.
            {plan === "trial" && trialLeft != null && (
              <> Every feature is unlocked for <strong>{trialLeft} more {trialLeft === 1 ? "day" : "days"}</strong>.</>
            )}
          </p>
          {plan === "expired" && (
            <p style={{ color: "var(--crit)", marginTop: 0 }}>
              Your trial has ended. Capture and detection keep running, but paid features
              can no longer be configured and limits are reduced — request an upgrade below
              to pick a plan.
            </p>
          )}
          {plan !== "enterprise" && (
            upgrade && upgrade.status === "pending" ? (
              <p className="flash-ok" style={{ marginTop: 0 }}>
                Upgrade to <strong>{upgrade.plan === "team" ? "Team" : "Enterprise"}</strong> requested
                {upgrade.created_at && <> on {upgrade.created_at.slice(0, 10)}</>} — we'll be in
                touch at <strong>{upgrade.contact}</strong>. Prefer email?{" "}
                <a href="mailto:sales@tachtech.net">sales@tachtech.net</a>.
              </p>
            ) : (
              <form onSubmit={submitUpgrade}
                    style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end", marginBottom: 14 }}>
                <label>Plan
                  <select value={upDraftPlan.plan}
                          onChange={(e) => setUpDraftPlan((s) => ({ ...s, plan: e.target.value }))}>
                    <option value="team">Team — $12/user/mo</option>
                    <option value="enterprise">Enterprise — custom</option>
                  </select>
                </label>
                <label>Seats
                  <input type="number" min="0" placeholder="optional" value={upDraftPlan.seats}
                         style={{ width: 90 }}
                         onChange={(e) => setUpDraftPlan((s) => ({ ...s, seats: e.target.value }))} />
                </label>
                <label style={{ flex: "1 1 220px" }}>Anything we should know?
                  <input value={upDraftPlan.note} placeholder="optional"
                         onChange={(e) => setUpDraftPlan((s) => ({ ...s, note: e.target.value }))} />
                </label>
                <button className="primary-btn slim" type="submit">Request upgrade</button>
              </form>
            )
          )}
          <div style={{ overflowX: "auto" }}>
            <table className="data-table plan-table">
              <thead>
                <tr>
                  <th>Feature</th>
                  {catalog.tiers.map((t) => (
                    <th key={t.name} className={t.name === catalog.current ? "plan-col-current" : ""}>
                      {t.label}{t.name === catalog.current && <span className="chip chip-on" style={{ marginLeft: 6 }}>current</span>}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="muted">Users included</td>
                  {catalog.tiers.map((t) => (
                    <td key={t.name} className={t.name === catalog.current ? "plan-col-current" : ""}>
                      {t.user_quota ? t.user_quota : "Custom"}
                    </td>
                  ))}
                </tr>
                {catalog.features.map((f) => (
                  <tr key={f.key}>
                    <td className="muted">{f.label}</td>
                    {catalog.tiers.map((t) => (
                      <td key={t.name} className={t.name === catalog.current ? "plan-col-current" : ""}>
                        {t.includes[f.key] ? "✓" : "—"}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

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
          <label>Store prompt content
            <select value={org.store_content} onChange={setField("store_content")}>
              <option value="inherit">Inherit (global — metadata-only)</option>
              <option value="off">Metadata only (recommended — no prompt text stored)</option>
              <option value="on">Store full content (redacted + encrypted per-tenant)</option>
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
          <label>Device enforcement (CLI hooks + desktop proxy)
            <select value={org.client_enforce} onChange={setField("client_enforce")}>
              <option value="inherit">Inherit (global)</option>
              <option value="on">Enforce (block risky prompts & tool calls)</option>
              <option value="off">Monitor (confirmed secret/PII leaks still block)</option>
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
          <label>CI scan block severity
            <select value={org.ci_block_severity} onChange={setField("ci_block_severity")}>
              <option value="">Inherit (critical)</option>
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
        <PlanLock need="alerts" />
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
        <PlanLock need="siem" />
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
          <label>Event naming
            <select value={siemCfg.naming} onChange={(e) => setSiemCfg((s) => ({ ...s, naming: e.target.value }))}>
              <option value="palivane">palivane (current brand)</option>
              <option value="warden">warden (legacy, pre-rebrand)</option>
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
           blocks capture). Internal/private endpoints are blocked — use a reachable collector.
           Event naming sets the Splunk sourcetype (<code>{siemCfg.naming}:finding</code>) and the
           S3 object path below — keep <em>warden</em> if your dashboards/pipelines already
           key on it.</p>
      </div>

      {/* SIEM S3 / data-lake delivery */}
      <div className="panel settings-card">
        <h2>S3 / data-lake delivery</h2>
        <PlanLock need="s3_delivery" />
        <p className="muted" style={{ fontSize: 12 }}>Independent of the HTTP push above — write
           each finding as a JSON object to an S3 bucket for a <strong>Panther S3 log source</strong>,
           Athena, or Snowflake. Uses the <strong>same severity threshold</strong> as SIEM forwarding.</p>
        <div className="field-grid">
          <label className="field-wide">Bucket
            <input placeholder="my-palivane-logs"
                   value={s3Cfg.bucket} onChange={(e) => setS3Cfg((s) => ({ ...s, bucket: e.target.value }))} /></label>
          <label>Prefix (optional)
            <input placeholder="acme/"
                   value={s3Cfg.prefix} onChange={(e) => setS3Cfg((s) => ({ ...s, prefix: e.target.value }))} /></label>
          <label>Region
            <input placeholder="us-east-1"
                   value={s3Cfg.region} onChange={(e) => setS3Cfg((s) => ({ ...s, region: e.target.value }))} /></label>
          <label>AWS access key ID {s3Cfg.configured && <span className="muted">(set — leave blank to keep)</span>}
            <input placeholder={s3Cfg.configured ? "••••••••" : "AKIA…"}
                   value={s3Cfg.keyId} onChange={(e) => setS3Cfg((s) => ({ ...s, keyId: e.target.value }))} /></label>
          <label>AWS secret access key {s3Cfg.configured && <span className="muted">(set — leave blank to keep)</span>}
            <input type="password" placeholder={s3Cfg.configured ? "••••••••" : "secret"}
                   value={s3Cfg.secret} onChange={(e) => setS3Cfg((s) => ({ ...s, secret: e.target.value }))} /></label>
        </div>
        <div className="form-row" style={{ gap: 10 }}>
          <button type="button" className="primary-btn slim" onClick={saveS3}>Save S3 delivery</button>
          <button type="button" className="mini-btn" onClick={testS3}>Write test object</button>
        </div>
        <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>Objects are written under
           <code> &lt;prefix&gt;/{siemCfg.naming}/findings/YYYY/MM/DD/…json</code> (path follows the
           SIEM event-naming setting above). Credentials are stored write-only. Grant the key
           <code> s3:PutObject</code> on the bucket only.</p>
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

      {/* BYOK judge key */}
      <form className="panel settings-card" onSubmit={saveJudgeKey}>
        <h2>LLM judge — bring your own key
          {judgeKey?.key_set && <span className="chip chip-on">active</span>}
        </h2>
        <p className="muted">Run the LLM judge on your org's own provider key: verdicts bill
          your account, work regardless of the platform's judge capacity, and aren't plan-gated.
          The key is stored encrypted and never shown again. Your "LLM judge" consent setting
          above still applies — Off disables the judge entirely.</p>
        <div className="field-grid">
          <label>Provider
            <select value={jkDraft.provider}
                    onChange={(e) => setJkDraft((d) => ({ ...d, provider: e.target.value }))}>
              <option value="anthropic">Anthropic (Claude)</option>
              <option value="openai">OpenAI (GPT)</option>
              <option value="gemini">Google (Gemini)</option>
            </select>
          </label>
          <label>API key
            <input type="password" value={jkDraft.key}
                   placeholder={judgeKey?.key_set ? "key set — enter to replace" : "provider API key"}
                   onChange={(e) => setJkDraft((d) => ({ ...d, key: e.target.value }))} />
          </label>
          <label>Model (optional)
            <input value={jkDraft.model} placeholder="provider default"
                   onChange={(e) => setJkDraft((d) => ({ ...d, model: e.target.value }))} />
          </label>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="primary-btn slim" type="submit">Save judge key</button>
          {judgeKey?.key_set &&
            <button type="button" className="mini-btn" onClick={clearJudgeKey}>Remove key</button>}
        </div>
      </form>

      {/* SSO / OIDC */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>Single sign-on (OIDC)</h2>
          {oidc?.enabled && <span className="chip chip-on">enabled</span>}</div>
        <PlanLock need="sso" />
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
        <PlanLock need="sso" />
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
