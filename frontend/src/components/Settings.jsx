import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import StripeCheckout from "./StripeCheckout.jsx";

const PROVIDERS = { openai: "OpenAI", anthropic: "Anthropic", gemini: "Gemini", xai: "xAI (Grok)",
                    vertex: "Claude on Vertex AI", bedrock: "Claude on Bedrock" };

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

// Writing a regex is the reason most orgs never define their own identifiers, so this
// writes it from examples instead. Inference is deterministic and server-side (see
// app/pattern_infer.py); this is only the form and the review step. Nothing saves until
// the admin has seen the pattern, read what it means in words, and pressed Add.
function PatternBuilder({ onAdd }) {
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [examples, setExamples] = useState("");
  const [counters, setCounters] = useState("");
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const lines = (s) => s.split("\n").map((x) => x.trim()).filter(Boolean);

  async function build() {
    setBusy(true);
    try { setRes(await api.patternFromExamples(lines(examples), lines(counters))); }
    catch (e) { setRes({ ok: false, error: String(e.message || e) }); }
    finally { setBusy(false); }
  }
  if (!open) {
    return <button type="button" className="ghost-btn slim" onClick={() => setOpen(true)}>
      Build one from examples →</button>;
  }
  return (
    <div className="field-wide" style={{ border: "1px solid var(--line)", borderRadius: 8, padding: 12 }}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <label style={{ flex: "1 1 180px" }}>Name it
          <input placeholder="Customer ID" value={label} onChange={(e) => setLabel(e.target.value)} /></label>
        <label style={{ flex: "1 1 220px" }}>Examples (one per line, at least two)
          <textarea rows={3} placeholder={"CUST-4821-A\nCUST-9930-B"}
                    value={examples} onChange={(e) => setExamples(e.target.value)} /></label>
        <label style={{ flex: "1 1 220px" }}>Should NOT match (optional)
          <textarea rows={3} placeholder={"ORD-4821-A"}
                    value={counters} onChange={(e) => setCounters(e.target.value)} /></label>
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button type="button" className="ghost-btn slim" onClick={build} disabled={busy}>
          {busy ? "Working…" : "Build pattern"}</button>
        <button type="button" className="ghost-btn slim" onClick={() => { setOpen(false); setRes(null); }}>
          Close</button>
      </div>
      {res && !res.ok && <p className="muted" style={{ marginTop: 10 }}>{res.error}
        {res.false_hits?.length ? ` (also matched: ${res.false_hits.join(", ")})` : ""}</p>}
      {res?.ok && (
        <div style={{ marginTop: 10 }}>
          <code>{res.regex}</code>
          <p className="muted" style={{ margin: "6px 0" }}>Matches {res.explain}.</p>
          <button type="button" className="primary-btn slim"
                  onClick={() => { onAdd(`${label.trim() || "Custom PII"}=${res.regex}`);
                                   setRes(null); setExamples(""); setCounters(""); setLabel(""); }}>
            Add to patterns</button>
        </div>
      )}
    </div>
  );
}

export default function Settings({ tenant, currentUser, onTenant, onLogout }) {
  const [msg, setMsg] = useState(null);       // { ok, text }
  const flash = (text, ok = true) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 3000); };
  const err = (e) => flash(String(e.message || e).replace(/^\d+:\s*/, ""), false);

  // Licensing plan (display hints only, the API enforces the gates).
  const plan = tenant?.plan || "free";
  // plan_label comes from the server so "Trial expired" / "Free (self-hosted)" read
  // correctly instead of being title-cased from the raw key.
  const planLabel = tenant?.plan_label || (plan.charAt(0).toUpperCase() + plan.slice(1));
  const trialLeft = tenant?.trial_days_left;   // null unless on a hosted trial
  const can = (f) => (tenant?.plan_features || []).includes(f);
  const NEEDS = { alerts: "Team", mdm: "Team", sso: "Enterprise", siem: "Enterprise", s3_delivery: "Enterprise" };
  const PlanLock = ({ need }) => can(need) ? null : (
    <p className="muted" style={{ marginTop: 2 }}>🔒 {NEEDS[need]} plan feature, request an
      upgrade under 'Your plan' above to enable.</p>
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
    redact_mode: tenant?.redact_mode === true ? "on" : tenant?.redact_mode === false ? "off" : "inherit",
    self_justify: tenant?.self_justify === true ? "on" : tenant?.self_justify === false ? "off" : "inherit",
    gateway_tokenize: tenant?.gateway_tokenize === true ? "on"
      : tenant?.gateway_tokenize === false ? "off" : "inherit",
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
        redact_mode: org.redact_mode,
        self_justify: org.self_justify,
        gateway_tokenize: org.gateway_tokenize,
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
    format: tenant?.siem_format || "json",
    tokenSet: !!tenant?.siem_token_set,
  });
  async function saveSiem() {
    try {
      const payload = { siem_url: siemCfg.url, siem_min_severity: siemCfg.min,
                        siem_format: siemCfg.format };
      if (siemCfg.token) payload.siem_token = siemCfg.token;   // write-only; only send if changed
      const t = await api.updateTenant(payload);
      onTenant?.(t); setSiemCfg((s) => ({ ...s, token: "", tokenSet: !!t.siem_token_set,
                                           })); flash("SIEM saved.");
    } catch (e) { err(e); }
  }
  async function testSiem() {
    try {
      const r = await api.testSiem();
      flash(r.ok ? "Test event sent to SIEM." : `SIEM send failed: ${r.detail || "endpoint unreachable"}`, !!r.ok);
      loadSinkHealth();
    } catch (e) { err(e); }
  }

  // --- Sink delivery health (per-instance counters + last error, from /api/siem/status) ---
  const [sinkHealth, setSinkHealth] = useState(null);
  const loadSinkHealth = useCallback(async () => {
    try { setSinkHealth(await api.siemStatus()); } catch { /* non-admin or older API */ }
  }, []);
  const SinkHealth = ({ sink, label = "Delivery health" }) => {
    const s = sinkHealth?.sinks?.[sink];
    if (!s) return null;
    if (!s.attempted) return (
      <p className="muted" style={{ marginTop: 6, fontSize: 12 }}>{label}: no deliveries
         attempted yet (since this instance started).</p>
    );
    const ok = !s.last_error_at || (s.last_ok && s.last_ok > s.last_error_at);
    return (
      <p className="muted" style={{ marginTop: 6, fontSize: 12 }}>
        {label}: {s.ok} delivered · {s.failed} failed{" "}
        {ok ? <span style={{ color: "var(--ok, #2e7d32)" }}>✓ last delivery succeeded{s.last_ok ? ` (${s.last_ok})` : ""}</span>
            : <span style={{ color: "var(--danger, #c62828)" }}>✗ last error {s.last_error_at}: {s.last_error}</span>}
      </p>
    );
  };

  // --- SIEM S3 / data-lake delivery ---
  const [s3Cfg, setS3Cfg] = useState({
    bucket: tenant?.siem_s3_bucket || "", prefix: tenant?.siem_s3_prefix || "",
    region: tenant?.siem_s3_region || "", keyId: "", secret: "",
    configured: !!tenant?.siem_s3_configured,
    archive: !!tenant?.archive_s3_enabled, archiveRaw: !!tenant?.archive_s3_raw_content,
  });
  async function saveS3() {
    try {
      const payload = { siem_s3_bucket: s3Cfg.bucket, siem_s3_prefix: s3Cfg.prefix, siem_s3_region: s3Cfg.region,
                        archive_s3_enabled: s3Cfg.archive, archive_s3_raw_content: s3Cfg.archiveRaw };
      if (s3Cfg.keyId) payload.siem_s3_key_id = s3Cfg.keyId;    // write-only; only send if changed
      if (s3Cfg.secret) payload.siem_s3_secret = s3Cfg.secret;
      const t = await api.updateTenant(payload);
      onTenant?.(t);
      setS3Cfg((s) => ({ ...s, keyId: "", secret: "", configured: !!t.siem_s3_configured,
                         archive: !!t.archive_s3_enabled, archiveRaw: !!t.archive_s3_raw_content }));
      flash("S3 delivery saved.");
    } catch (e) { err(e); }
  }
  async function testS3() {
    try {
      const r = await api.testSiemS3();
      flash(r.ok ? "Test object written to S3." : `S3 write failed: ${r.detail || "check config"}`, !!r.ok);
      loadSinkHealth();
    } catch (e) { err(e); }
  }
  async function testArchive() {
    try {
      const r = await api.testArchiveS3();
      flash(r.ok ? "Test object written under events/." : `S3 write failed: ${r.detail || "check config"}`, !!r.ok);
      loadSinkHealth();
    } catch (e) { err(e); }
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

  // --- Slack scanning (collab-surface DLP via the published Slack app) ---
  const [slackConns, setSlackConns] = useState([]);
  // Whether THIS deployment has a published Slack app registered. Without one there is no
  // "Add to Slack" to offer: /api/slack/install can only 404, and the honest answer is the
  // workspace-app route. Null until known, so the button never flashes in and out.
  const [slackApp, setSlackApp] = useState(null);
  useEffect(() => {
    api.health().then((h) => setSlackApp(!!h.slack_app)).catch(() => setSlackApp(false));
  }, []);
  const loadSlack = useCallback(async () => {
    try {
      const r = await api.connectors();
      setSlackConns((r.connectors || []).filter((c) => c.platform === "slack_messages"));
    } catch { /* older API or non-admin */ }
  }, []);
  async function addToSlack() {
    try { const { url } = await api.slackInstallUrl(); window.location.href = url; }
    catch { flash("No published Slack app on this deployment, create a workspace app and register its bot token as a slack_messages connector.", false); }
  }
  async function setSlackAutoJoin(id, on) {
    try {
      const c = await api.updateConnector(id, { auto_join: on });
      setSlackConns((cs) => cs.map((x) => (x.id === id ? c : x)));
      flash(on ? "Palivane will join and scan every public channel on the next scan."
               : "Auto-join off. Only channels the bot was invited to are scanned.");
    } catch (e) { err(e); }
  }
  async function setSlackRemediate(id, on) {
    try {
      const c = await api.updateConnector(id, { remediate: on });
      setSlackConns((cs) => cs.map((x) => (x.id === id ? c : x)));
      flash(on ? "Confirmed leaks will be DELETED from Slack on the next scan. Every "
                 + "deletion is written to the audit log."
               : "Deletion off. Confirmed leaks are recorded, not removed.");
    } catch (e) { err(e); }
  }
  async function syncSlack(id) {
    try {
      const s = await api.syncConnector(id);
      flash(`Scanned ${s.messages} message(s) across ${s.channels} channel(s), ${s.findings} finding(s).`);
      loadSlack();
    } catch (e) { err(e); }
  }
  useEffect(() => {   // OAuth callback lands back here with ?slack=<result>
    const p = new URLSearchParams(window.location.search).get("slack");
    if (p) {
      flash(p === "installed" ? "Slack workspace connected, invite the bot to the channels to scan, then hit Scan now."
        : p === "denied" ? "Slack install was cancelled." : "Slack install failed, try again.",
        p === "installed");
      window.history.replaceState({}, "", window.location.pathname);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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

  // --- Self-serve billing (Stripe; Team only — Enterprise stays sales-led). Dark unless
  // the backend has Stripe configured, in which case the card-swipe path renders above
  // the sales-led request form. ---
  const [billing, setBilling] = useState(null);          // { enabled, subscribed, portal, intervals, publishable_key }
  const [coDraft, setCoDraft] = useState({ seats: "", interval: "month" });
  const [checkoutSecret, setCheckoutSecret] = useState(null);   // embedded Checkout client_secret
  const loadBilling = useCallback(() => api.billing().then(setBilling).catch(() => {}), []);
  useEffect(() => {   // embedded Checkout returns to /#billing=success on completion
    if (window.location.hash === "#billing=success") {
      flash("Payment received — your Team plan activates in a few seconds. Thanks!");
      window.history.replaceState(null, "", window.location.pathname);
      setTimeout(() => { loadBilling(); onTenant?.(); }, 4000);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function startCheckout(e) {
    e.preventDefault();
    try {
      const r = await api.billingCheckout(Number(coDraft.seats) || 1, coDraft.interval);
      setCheckoutSecret(r.client_secret);   // mounts the embedded form in-page (no redirect)
    } catch (e2) { err(e2); }
  }

  async function openPortal() {
    try {
      const r = await api.billingPortal();
      window.location.href = r.url;   // Stripe's portal is hosted-only; redirect is expected
    } catch (e2) { err(e2); }
  }

  async function submitUpgrade(e) {
    e.preventDefault();
    try {
      const r = await api.requestUpgrade(upDraftPlan.plan, Number(upDraftPlan.seats) || 0,
                                         upDraftPlan.note);
      setUpgrade(r.request);
      flash("Upgrade requested, we'll be in touch shortly.");
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
      flash("Judge key saved, the LLM judge now runs on your org's own key.");
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
  // --- SCIM provisioning ---
  const [scimToken, setScimToken] = useState("");   // plaintext, shown once after mint
  async function mintScim() {
    if (tenant?.scim_enabled &&
        !window.confirm("Rotate the SCIM token? The IdP keeps failing until it gets the new one.")) return;
    try {
      const r = await api.scimTokenMint(); setScimToken(r.token);
      onTenant?.({ ...tenant, scim_enabled: true });
    } catch (e) { err(e); }
  }
  async function revokeScim() {
    if (!window.confirm("Revoke the SCIM token? Provisioning stops immediately.")) return;
    try {
      await api.scimTokenRevoke(); setScimToken("");
      onTenant?.({ ...tenant, scim_enabled: false });
      flash("SCIM token revoked.");
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

  useEffect(() => { loadUsage(); loadUps(); loadJudgeKey(); loadOidc(); loadSaml(); loadDpa(); loadCatalog(); loadUpgrade(); loadBilling(); loadSinkHealth(); loadSlack(); },
    [loadUsage, loadUps, loadJudgeKey, loadOidc, loadSaml, loadDpa, loadCatalog, loadUpgrade, loadBilling, loadSinkHealth, loadSlack]);

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
          <p className="page-sub">Organization, gateway upstreams, SSO, and usage, admin only.
            {plan !== "enterprise" && (
              <> &nbsp;Need SSO, SIEM, or higher limits? Request an upgrade under 'Your plan' below.</>
            )}
          </p>
        </div>
      </div>
      {msg && <div className={msg.ok ? "flash-ok" : "flash-err"}>{msg.text}</div>}

      {/* Your plan, entitlements comparison across tiers, current one highlighted */}
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
              can no longer be configured and limits are reduced, request an upgrade below
              to pick a plan.
            </p>
          )}
          {/* Self-serve: buy Team by card via embedded Stripe Checkout — mounted in-page
              (no redirect). Renders only when billing is configured; Enterprise stays
              sales-led below. Once a session starts, the seat form is replaced by the
              embedded card form on our own domain. */}
          {billing?.enabled && !billing.subscribed && !["team", "enterprise"].includes(plan) && (
            checkoutSecret && billing.publishable_key ? (
              <div className="checkout-embed" style={{ marginBottom: 14 }}>
                <StripeCheckout publishableKey={billing.publishable_key}
                                clientSecret={checkoutSecret} />
                <button className="link-btn link-muted" type="button"
                        onClick={() => setCheckoutSecret(null)}>← back</button>
              </div>
            ) : (
              <form onSubmit={startCheckout}
                    style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end", marginBottom: 14 }}>
                <label>Seats
                  <input type="number" min="1" placeholder="5" value={coDraft.seats}
                         style={{ width: 90 }}
                         onChange={(e) => setCoDraft((s) => ({ ...s, seats: e.target.value }))} />
                </label>
                {billing.intervals.length > 1 && (
                  <label>Billing
                    <select value={coDraft.interval}
                            onChange={(e) => setCoDraft((s) => ({ ...s, interval: e.target.value }))}>
                      <option value="month">Monthly, $12/user</option>
                      <option value="year">Annual, $10/user/mo</option>
                    </select>
                  </label>
                )}
                <button className="primary-btn slim" type="submit">Upgrade to Team, pay by card →</button>
                <span className="muted" style={{ flexBasis: "100%" }}>
                  Secure card entry by Stripe, right here on this page. Need Enterprise
                  (SSO, SIEM, S3)? Use the request form below.
                </span>
              </form>
            )
          )}
          {billing?.enabled && billing.portal && (billing.subscribed || plan === "team") && (
            <p style={{ marginTop: 0 }}>
              <button className="secondary-btn slim" type="button" onClick={openPortal}>
                Manage billing (seats, invoices, cancel) →
              </button>
            </p>
          )}
          {plan !== "enterprise" && !(billing?.enabled && billing.subscribed) && (
            upgrade && upgrade.status === "pending" ? (
              <p className="flash-ok" style={{ marginTop: 0 }}>
                Upgrade to <strong>{upgrade.plan === "team" ? "Team" : "Enterprise"}</strong> requested
                {upgrade.created_at && <> on {upgrade.created_at.slice(0, 10)}</>}, we'll be in
                touch at <strong>{upgrade.contact}</strong>. Prefer email?{" "}
                <a href="mailto:sales@palivane.io">sales@palivane.io</a>.
              </p>
            ) : (
              <form onSubmit={submitUpgrade}
                    style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end", marginBottom: 14 }}>
                <label>Plan
                  <select value={upDraftPlan.plan}
                          onChange={(e) => setUpDraftPlan((s) => ({ ...s, plan: e.target.value }))}>
                    <option value="team">Team, $12/user/mo</option>
                    <option value="enterprise">Enterprise, custom</option>
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
                        {t.includes[f.key] ? "✓" : "-"}
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
              <option value="inherit">Inherit (global, metadata-only)</option>
              <option value="off">Metadata only (recommended, no prompt text stored)</option>
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
          <label>Gateway tokenization (personal data)
            <select value={org.gateway_tokenize} onChange={setField("gateway_tokenize")}>
              <option value="inherit">Inherit (global)</option>
              <option value="on">Tokenize, the provider never sees the value</option>
              <option value="off">Off, send as typed</option>
            </select>
            <span className="muted" style={{ fontSize: 11.5, marginTop: 3 }}>
              Gateway traffic only. Personal data is replaced by a placeholder on the way to
              the model and restored in the reply, so the model reasons over a record's shape
              without the provider holding its contents. Scoring still runs on the original
              text. Credentials are never tokenized, they are blocked. Pair with a Monitor
              block severity for PII, or the confirmed-leak stop refuses the prompt before
              tokenization can make it safe to send.
            </span>
          </label>
          <label>Coaching mode (secrets / PII)
            <select value={org.redact_mode} onChange={setField("redact_mode")}>
              <option value="inherit">Inherit (global)</option>
              <option value="on">Coach, warn + show cleaned version</option>
              <option value="off">Block (hard stop)</option>
            </select>
            <span className="muted" style={{ fontSize: 11.5, marginTop: 3 }}>
              When on, a prompt blocked <em>only</em> for a secret or PII becomes a warning that
              shows the redacted version and points to a sanctioned tool, the user chooses.
              Injection, source-code, and unsanctioned-destination blocks are unaffected.
            </span>
          </label>
          <label>Justified proceed (Human Firewall)
            <select value={org.self_justify} onChange={setField("self_justify")}>
              <option value="inherit">Inherit (global)</option>
              <option value="on">On, a justification unlocks the send</option>
              <option value="off">Off, blocks are final</option>
            </select>
            <span className="muted" style={{ fontSize: 11.5, marginTop: 3 }}>
              When on, a blocked user can record a business justification and send anyway.
              The justification lands on the finding and in the audit log, so enforcement
              teaches instead of queueing tickets. Confirmed secrets / PII stay blocked
              regardless, those go to an admin via Request exception.
            </span>
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
          <PatternBuilder onAdd={(line) => setOrgState((o) => ({
            ...o, custom_pii_patterns: (o.custom_pii_patterns || "").trim()
              ? `${o.custom_pii_patterns.trim()}\n${line}` : line }))} />
          <label className="field-wide">Need-to-know rules (oversharing), one <code>restricted = allowed-group</code> per line
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
          <label className="field-wide">Webhook URL (Slack-compatible (posts findings) {alertCfg.webhookSet && <span className="muted">(set) leave blank to keep)</span>}
            <input type="password" placeholder={alertCfg.webhookSet ? "••••••••" : "https://hooks.slack.com/services/..."}
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
           findings are batched into a rollup on the chosen cadence, <strong>critical findings
           still fire in real time</strong>. Findings export is for SIEM ingest. Alerts fail open
          , a down webhook never blocks capture.</p>
      </div>

      {/* SIEM forwarding */}
      <div className="panel settings-card">
        <h2>SIEM forwarding</h2>
        <PlanLock need="siem" />
        <p className="muted" style={{ fontSize: 12 }}>Stream findings to your SIEM in real time
           (complements the pull-based JSONL export above). Vendor-neutral, point it at any
           HTTP collector.</p>
        <div className="field-grid">
          <label className="field-wide">Collector URL
            <input placeholder="https://http-inputs.splunkcloud.com/services/collector"
                   value={siemCfg.url} onChange={(e) => setSiemCfg((s) => ({ ...s, url: e.target.value }))} /></label>
          <label className="field-wide">Token {siemCfg.tokenSet && <span className="muted">(set, leave blank to keep)</span>}
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
        <SinkHealth sink="siem_http" />
        <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>Pushes each finding at/above
           the threshold as it's captured; SSRF-guarded and fail-open (a down collector never
           blocks capture). Internal/private endpoints are blocked, use a reachable collector.
           Events arrive with the Splunk sourcetype <code>palivane:finding</code>, which also
           sets the S3 object path below.</p>
      </div>

      {/* SIEM S3 / data-lake delivery */}
      <div className="panel settings-card">
        <h2>S3 / data-lake delivery</h2>
        <PlanLock need="s3_delivery" />
        <p className="muted" style={{ fontSize: 12 }}>Independent of the HTTP push above, write
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
          <label>AWS access key ID {s3Cfg.configured && <span className="muted">(set, leave blank to keep)</span>}
            <input placeholder={s3Cfg.configured ? "••••••••" : "AKIA..."}
                   value={s3Cfg.keyId} onChange={(e) => setS3Cfg((s) => ({ ...s, keyId: e.target.value }))} /></label>
          <label>AWS secret access key {s3Cfg.configured && <span className="muted">(set, leave blank to keep)</span>}
            <input type="password" placeholder={s3Cfg.configured ? "••••••••" : "secret"}
                   value={s3Cfg.secret} onChange={(e) => setS3Cfg((s) => ({ ...s, secret: e.target.value }))} /></label>
        </div>
        <div className="settings-sub" style={{ marginTop: 12 }}>
          <h3 style={{ margin: "0 0 6px" }}>Raw event archive</h3>
          <p className="muted" style={{ fontSize: 12 }}>Beyond findings: archive <strong>every
             captured event</strong> (benign included) to the same bucket as NDJSON micro-batches
             under <code>&lt;prefix&gt;/palivane/events/YYYY/MM/DD/HH/...ndjson</code>
             a complete, hour-partitioned capture record for Athena / Panther / Snowflake.</p>
          <label style={{ fontSize: 13, display: "block" }}>
            <input type="checkbox" checked={s3Cfg.archive}
                   onChange={(e) => setS3Cfg((s) => ({ ...s, archive: e.target.checked }))} /> archive all events
          </label>
          {s3Cfg.archive && (
            <label style={{ fontSize: 13, display: "block" }}>
              <input type="checkbox" checked={s3Cfg.archiveRaw}
                     onChange={(e) => setS3Cfg((s) => ({ ...s, archiveRaw: e.target.checked }))} /> include
              unredacted content (default: secrets/PII are masked, as in stored findings)
            </label>
          )}
        </div>
        <div className="form-row" style={{ gap: 10 }}>
          <button type="button" className="primary-btn slim" onClick={saveS3}>Save S3 delivery</button>
          <button type="button" className="mini-btn" onClick={testS3}>Write test object</button>
          {s3Cfg.archive && <button type="button" className="mini-btn" onClick={testArchive}>Write test event</button>}
        </div>
        <SinkHealth sink="siem_s3" label="Findings delivery" />
        {s3Cfg.archive && <SinkHealth sink="archive_s3" label="Event archive" />}
        <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>Findings are written under
           <code> &lt;prefix&gt;/palivane/findings/YYYY/MM/DD/...json</code> (path follows the
           same brand key). Your credentials are stored write-only and encrypted. Grant
           the key <code>s3:PutObject</code> on the bucket only.</p>
      </div>

      {/* Slack scanning */}
      <div className="panel settings-card">
        <h2>Slack scanning</h2>
        <p className="muted" style={{ fontSize: 12 }}>Scan Slack message content for PII, PHI, and
           secrets, the same detection engine as every other plane, on the <code>collab</code>
           surface. Slack AI, bots, and MCP servers can read whatever sits in your channels;
           this finds the regulated data before an AI rollout indexes it.</p>
        {slackConns.map((c) => (
          <div key={c.id} className="form-row" style={{ gap: 10, alignItems: "center" }}>
            <span><strong>{c.label || "workspace"}</strong>{" "}
              <span className="muted" style={{ fontSize: 12 }}>
                {c.last_sync_at ? `last scan ${c.last_sync_at.slice(0, 16).replace("T", " ")}` : "never scanned"}
                {c.last_sync_status === "error" && ", last scan failed"}
              </span></span>
            <button type="button" className="mini-btn" onClick={() => syncSlack(c.id)}>Scan now</button>
          </div>
        ))}
        {can("remediation") && slackConns.map((c) => (
          <label key={`rm-${c.id}`} className="form-row" style={{ gap: 8, marginTop: 6,
                                                                  alignItems: "flex-start" }}>
            <input type="checkbox" checked={!!c.options?.remediate}
                   onChange={(e) => setSlackRemediate(c.id, e.target.checked)} />
            <span style={{ fontSize: 12 }}>Delete confirmed leaks from{" "}
              <strong>{c.label || "this workspace"}</strong>{" "}
              <span className="muted">— a message this scan flags at high or critical is
              removed from Slack, and the deletion is written to the audit log. Needs the
              workspace-admin user token (<code>xoxp-…</code>) on this connector; the bot
              token cannot delete anyone else's message. Deletion is all Slack allows below
              Enterprise Grid: editing someone else's message to mask just the sensitive
              part is Grid-only.</span></span>
          </label>
        ))}
        {slackConns.map((c) => (
          <label key={`aj-${c.id}`} className="form-row" style={{ gap: 8, marginTop: 6,
                                                                  alignItems: "flex-start" }}>
            <input type="checkbox" checked={!!c.options?.auto_join}
                   onChange={(e) => setSlackAutoJoin(c.id, e.target.checked)} />
            <span style={{ fontSize: 12 }}>Scan every public channel in{" "}
              <strong>{c.label || "this workspace"}</strong>{" "}
              <span className="muted">— joins the ones it is not in, which posts a visible
              "joined the channel" line in each. Private channels and DMs still need an
              invite.</span></span>
          </label>
        ))}
        {slackApp && (
          <div className="form-row" style={{ gap: 10, marginTop: slackConns.length ? 8 : 0 }}>
            <button type="button" className={slackConns.length ? "mini-btn" : "primary-btn slim"}
                    onClick={addToSlack}>
              {slackConns.length ? "Add another workspace" : "Add to Slack"}</button>
          </div>
        )}
        {slackApp === false && !slackConns.length && (
          <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>One-click install is not
             available on this deployment. Create a Slack app in your own workspace with the
             read scopes below, then add its bot token here as a <code>slack_messages</code>
             connector. <a href="/docs/slack-scanning" target="_blank"
             rel="noreferrer">Step by step →</a></p>
        )}
        <p className="muted" style={{ marginTop: 8, fontSize: 12 }}>Read-only scopes
           (<code>channels:read</code>, <code>groups:read</code>, <code>channels:history</code>,
           <code>groups:history</code>, <code>users:read</code>, <code>users:read.email</code>,
           <code>files:read</code>, plus <code>channels:join</code> for the option above);
           the bot never posts, edits, or deletes. Every scan pulls messages since the last
           cursor (first scan looks back 7 days) and reads attachments: text, PDFs, and
           Word/Excel/PowerPoint documents, plus screenshots when OCR is enabled on the
           deployment. What nothing can open (pre-2007 Office, encrypted PDFs, images with
           OCR off) is reported as skipped rather than counted clean. Findings land under the <code>collab</code> surface with alerts and
           SIEM export as usual. Deployments that set the Slack app's signing secret also
           receive messages in real time (Events API), the moment they are sent, with the
           scheduled pull as the safety net. Detection only: Slack permits no pre-delivery
           block, and no edit of another person's message, outside Enterprise Grid's
           Discovery API.
           <a href="/docs/slack-scanning" target="_blank" rel="noreferrer"> Full setup →</a></p>
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
              <p className="muted">Current version <strong>v{dpa.current_version}</strong>: not yet accepted
                {dpa.version ? ` (last accepted v${dpa.version})` : ""}.</p>
            )
          ) : <p className="muted">...</p>}
          <button type="button" className="primary-btn slim" onClick={acceptDpa}
                  disabled={dpa?.accepted}>
            {dpa?.accepted ? "DPA accepted" : "Accept DPA"}
          </button>
        </div>

        <div className="settings-sub" style={{ marginTop: 16 }}>
          <h3 style={{ margin: "0 0 6px" }}>Data export</h3>
          <p className="muted" style={{ fontSize: 12 }}>A complete JSON export of this org, config, users,
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
              <input type="password" placeholder={u.key_set ? "key set, enter to replace" : "API key"}
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
        <h2>LLM judge, bring your own key
          {judgeKey?.key_set && (judgeKey?.health?.ok === false
            ? <span className="chip chip-warn">key failing</span>
            : <span className="chip chip-on">active</span>)}
        </h2>
        {judgeKey?.key_set && judgeKey?.health?.ok === false && (
          <div className="judge-health-warn">
            Your judge key is failing, scans are running on offline detectors only, without
            the LLM judge. Last error: <code>{judgeKey.health.last_error || "unknown"}</code>.
            Check the provider account (billing, key revocation) or save a new key below.
          </div>
        )}
        <p className="muted">Run the LLM judge on your org's own provider key: verdicts bill
          your account, work regardless of the platform's judge capacity, and aren't plan-gated.
          The key is stored encrypted and never shown again. Your "LLM judge" consent setting
          above still applies. Off disables the judge entirely.</p>
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
                   placeholder={judgeKey?.key_set ? "key set, enter to replace" : "provider API key"}
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
            <input type="password" placeholder={oidc?.secret_set ? "secret set, enter to replace" : "client secret"}
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
            <input placeholder={saml?.cert_set ? "cert set, paste to replace" : "MIIC..."}
                   value={samlDraft.idp_x509_cert}
                   onChange={(e) => setSamlDraft((d) => ({ ...d, idp_x509_cert: e.target.value }))} /></label>
        </div>
        <div className="detail-actions">
          <button type="button" className="mini-btn" onClick={() => saveSaml({ enabled: true })}>Save &amp; enable</button>
          <button type="button" className="mini-btn" onClick={() => saveSaml({ enabled: false })}>Save (disabled)</button>
          <button type="button" className="mini-btn danger" onClick={disableSaml}>Remove SAML</button>
        </div>
      </div>

      {/* SCIM provisioning */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>User provisioning (SCIM 2.0)</h2>
          {tenant?.scim_enabled && <span className="chip chip-on">enabled</span>}</div>
        <p className="muted">Let your IdP (Okta, Entra ID, OneLogin) create and deactivate
          Palivane users automatically. Point it at <code>{`${location.origin}/scim/v2`}</code> with
          the bearer token below, someone removed from the directory is deactivated here on the
          IdP's next sync, sessions killed immediately. SCIM users arrive as analysts; roles stay
          a console decision. Deleting in the IdP deactivates (findings history survives).</p>
        {scimToken && (
          <p style={{ wordBreak: "break-all" }}><strong>Token (shown once):</strong>{" "}
            <code>{scimToken}</code></p>
        )}
        <div className="detail-actions">
          <button type="button" className="mini-btn" onClick={mintScim}>
            {tenant?.scim_enabled ? "Rotate token" : "Generate token"}</button>
          {tenant?.scim_enabled && (
            <button type="button" className="mini-btn danger" onClick={revokeScim}>Revoke</button>
          )}
        </div>
      </div>

      {/* Two-factor */}
      <div className="panel settings-card">
        <div className="settings-head"><h2>Two-factor authentication</h2>
          {mfaOn && !recovery && <span className="chip chip-on">on</span>}</div>

        {recovery && (
          <div className="mfa-recovery">
            <p className="muted">Two-factor is on. Save these one-time recovery codes now, they
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
