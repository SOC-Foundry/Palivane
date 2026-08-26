const BASE = "/api";
const TOKEN_KEY = "palivane_token";

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t) {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

// Notified when a request is rejected for auth reasons, so the UI can log out.
let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

async function req(path, opts = {}) {
  const headers = { "content-type": "application/json", ...(opts.headers || {}) };
  const token = getToken();
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(BASE + path, { ...opts, headers });
  if (res.ok) return res.json();

  // Prefer the server's own explanation. FastAPI puts it in `detail`, a string for our
  // HTTPExceptions, a list for 422 validation errors (left to the raw fallback below).
  const body = await res.text();
  let detail = "";
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed.detail === "string") detail = parsed.detail;
  } catch { /* not JSON, fall through to the raw body */ }

  if (res.status === 401) {
    // Distinguish a dead session from a refused sign-in. A 401 while holding a token means
    // the token is no longer good; a 401 with no token in hand is a failed login attempt,
    // and calling that "session expired" hides the real reason (wrong password, unknown
    // email) and sends people off debugging their session instead of their credentials.
    if (token) {
      setToken(null);
      onUnauthorized();
      throw new Error(detail || "session expired, please sign in again");
    }
    throw new Error(detail || "invalid credentials");
  }
  throw new Error(detail || `${res.status}: ${body}`);
}

export const api = {
  health: () => req("/health"),
  login: (email, password, org = "") =>
    req("/auth/login", { method: "POST", body: JSON.stringify({ email, password, org }) }),
  mfaVerify: (challenge, code) =>
    req("/auth/mfa/verify", { method: "POST", body: JSON.stringify({ challenge, code }) }),
  mfaSetup: () => req("/auth/mfa/setup", { method: "POST" }),
  mfaConfirm: (code) => req("/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ code }) }),
  mfaDisable: (code) => req("/auth/mfa/disable", { method: "POST", body: JSON.stringify({ code }) }),
  signup: (org_name, email, password) =>
    req("/auth/signup", { method: "POST", body: JSON.stringify({ org_name, email, password }) }),
  forgot: (email, org = "") =>
    req("/auth/forgot", { method: "POST", body: JSON.stringify({ email, org }) }),
  resetPassword: (token, password) =>
    req("/auth/reset", { method: "POST", body: JSON.stringify({ token, password }) }),
  me: () => req("/auth/me"),
  domains: () => req("/domains"),
  claimDomain: (domain) => req("/domains", { method: "POST", body: JSON.stringify({ domain }) }),
  verifyDomain: (id) => req(`/domains/${id}/verify`, { method: "POST" }),
  updateDomain: (id, payload) =>
    req(`/domains/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteDomain: (id) => req(`/domains/${id}`, { method: "DELETE" }),
  joinRequests: () => req("/join-requests"),
  approveJoin: (id) => req(`/join-requests/${id}/approve`, { method: "POST" }),
  denyJoin: (id) => req(`/join-requests/${id}/deny`, { method: "POST" }),
  users: () => req("/users"),
  createUser: (payload) =>
    req("/users", { method: "POST", body: JSON.stringify(payload) }),
  updateUser: (id, payload) =>
    req(`/users/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  createApiKey: (payload) =>
    req("/apikeys", { method: "POST", body: JSON.stringify(payload) }),
  apiKeys: () => req("/apikeys"),
  deleteApiKey: (id) => req(`/apikeys/${id}`, { method: "DELETE" }),
  enrollTokens: () => req("/enroll/tokens"),
  deleteEnrollToken: (id) => req(`/enroll/tokens/${id}`, { method: "DELETE" }),
  provision: (payload) =>
    req("/provision", { method: "POST", body: JSON.stringify(payload) }),
  policyPack: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    return req("/policy-pack" + (q ? `?${q}` : ""));
  },
  coverageReconcile: (events) =>
    req("/coverage/reconcile", { method: "POST", body: JSON.stringify({ events }) }),
  activityUsers: () => req("/activity/users"),
  agents: () => req("/agents"),
  agentCreate: (payload) => req("/agents", { method: "POST", body: JSON.stringify(payload) }),
  agentRotate: (id) => req(`/agents/${id}/rotate`, { method: "POST" }),
  agentDelete: (id) => req(`/agents/${id}`, { method: "DELETE" }),
  agentUpdate: (id, payload) => req(`/agents/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  agentToken: (id, ttl) => req(`/agents/${id}/token`, { method: "POST", body: JSON.stringify({ ttl_minutes: ttl }) }),
  agentRoles: () => req("/agent-roles"),
  agentRoleUpsert: (payload) => req("/agent-roles", { method: "POST", body: JSON.stringify(payload) }),
  agentRoleDelete: (id) => req(`/agent-roles/${id}`, { method: "DELETE" }),
  policies: () => req("/policies"),
  complianceReport: () => req("/compliance/report"),
  redteamSelftest: () => req("/redteam/selftest", { method: "POST" }),
  complianceCsv: async () => {
    const token = getToken();
    const res = await fetch(BASE + "/compliance/report?format=csv",
      { headers: token ? { authorization: `Bearer ${token}` } : {} });
    if (!res.ok) throw new Error(`${res.status}`);
    return res.text();
  },
  policyOverrideUpsert: (payload) =>
    req("/policies/overrides", { method: "POST", body: JSON.stringify(payload) }),
  policyOverrideDelete: (id) =>
    req(`/policies/overrides/${id}`, { method: "DELETE" }),
  fleet: () => req("/fleet"),
  simulate: (payload) =>
    req("/simulate", { method: "POST", body: JSON.stringify(payload) }),
  exceptions: (status = "pending") =>
    req(`/exceptions?${new URLSearchParams({ status })}`),
  exceptionResolve: (id, payload) =>
    req(`/exceptions/${id}/resolve`, { method: "POST", body: JSON.stringify(payload) }),
  policyAnalytics: (days = 30) =>
    req(`/policies/analytics?${new URLSearchParams({ days })}`),
  reportSummary: (days = 30) =>
    req(`/reports/summary?${new URLSearchParams({ days })}`),
  discoveryInventory: () => req("/discovery/inventory"),
  discoveryIngest: (events) =>
    req("/discovery/ingest", { method: "POST", body: JSON.stringify({ events }) }),
  stats: () => req("/stats"),
  setupStatus: () => req("/setup-status"),
  analyze: (payload) =>
    req("/analyze", { method: "POST", body: JSON.stringify(payload) }),
  findings: (params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null && v !== "")
    ).toString();
    return req("/findings" + (q ? `?${q}` : ""));
  },
  finding: (id) => req(`/findings/${id}`),
  setStatus: (id, status) =>
    req(`/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  bulkStatus: (ids, status) =>
    req("/findings/bulk-status", { method: "POST", body: JSON.stringify({ ids, status }) }),

  // --- admin settings ---
  updateTenant: (payload) =>
    req("/tenant", { method: "PATCH", body: JSON.stringify(payload) }),
  extensionToken: (device = "") =>
    req(`/extension/token${device ? `?device=${encodeURIComponent(device)}` : ""}`,
        { method: "POST" }),
  testAlert: () => req("/alerts/test", { method: "POST" }),
  testSiem: () => req("/siem/test", { method: "POST" }),
  testSiemS3: () => req("/siem/s3/test", { method: "POST" }),
  testArchiveS3: () => req("/siem/s3/archive/test", { method: "POST" }),
  siemStatus: () => req("/siem/status"),
  siemS3RoleSetup: () => req("/siem/s3/role-setup"),
  connectors: () => req("/discovery/connectors"),
  syncConnector: (id) => req(`/discovery/connectors/${id}/sync`, { method: "POST" }),
  slackInstallUrl: () => req("/slack/install"),
  exportFindings: async () => {
    const token = getToken();
    const res = await fetch(BASE + "/export/findings",
      { headers: token ? { authorization: `Bearer ${token}` } : {} });
    if (!res.ok) throw new Error(`${res.status}`);
    return res.text();
  },
  exportTenant: async (includeContent = false) => {
    const token = getToken();
    const res = await fetch(BASE + `/export/tenant?include_content=${includeContent ? "true" : "false"}`,
      { headers: token ? { authorization: `Bearer ${token}` } : {} });
    if (!res.ok) throw new Error(`${res.status}`);
    return res.text();
  },
  dpa: () => req("/tenant/dpa"),
  acceptDpa: (version) => req("/tenant/dpa", { method: "POST", body: JSON.stringify({ version: version || null }) }),
  deleteTenant: (confirm) => req("/tenant", { method: "DELETE", body: JSON.stringify({ confirm }) }),
  usage: () => req("/usage"),
  planCatalog: () => req("/plans"),
  demoLogin: () => req("/auth/demo", { method: "POST" }),
  billing: () => req("/billing"),
  billingCheckout: (seats, interval) =>
    req("/billing/checkout", { method: "POST", body: JSON.stringify({ seats, interval }) }),
  billingPortal: () => req("/billing/portal", { method: "POST" }),
  upgradeRequest: () => req("/plans/upgrade"),
  requestUpgrade: (plan, seats, note) =>
    req("/plans/upgrade", { method: "POST", body: JSON.stringify({ plan, seats, note }) }),
  audit: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    return req("/audit" + (q ? `?${q}` : ""));
  },
  upstreams: () => req("/upstreams"),
  setUpstream: (provider, payload) =>
    req(`/upstreams/${provider}`, { method: "PUT", body: JSON.stringify(payload) }),
  deleteUpstream: (provider) => req(`/upstreams/${provider}`, { method: "DELETE" }),
  auditSessions: (days = 7) => req(`/audit/sessions?days=${days}`),
  auditTimeline: (actor, days = 7) =>
    req(`/audit/timeline?actor=${encodeURIComponent(actor)}&days=${days}`),
  // Downloads the normalized cross-vendor audit as a file (jsonl | cef), raw text, not JSON.
  downloadAudit: async (days = 7, format = "jsonl") => {
    const headers = {};
    const token = getToken();
    if (token) headers.authorization = `Bearer ${token}`;
    const res = await fetch(`${BASE}/audit/export?days=${days}&format=${format}`, { headers });
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `palivane-audit.${format === "cef" ? "cef" : "jsonl"}`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  },
  judgeKey: () => req("/judge-key"),
  setJudgeKey: (payload) => req("/judge-key", { method: "PUT", body: JSON.stringify(payload) }),
  deleteJudgeKey: () => req("/judge-key", { method: "DELETE" }),
  oidc: () => req("/oidc"),
  setOidc: (payload) => req("/oidc", { method: "PUT", body: JSON.stringify(payload) }),
  deleteOidc: () => req("/oidc", { method: "DELETE" }),
  saml: () => req("/saml"),
  setSaml: (payload) => req("/saml", { method: "PUT", body: JSON.stringify(payload) }),
  deleteSaml: () => req("/saml", { method: "DELETE" }),
  logoutAll: () => req("/auth/logout-all", { method: "POST" }),
};
