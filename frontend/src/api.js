const BASE = "/api";
const TOKEN_KEY = "warden_token";

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
  if (res.status === 401) {
    setToken(null);
    onUnauthorized();
    throw new Error("session expired — please sign in again");
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  return res.json();
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
  me: () => req("/auth/me"),
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
  provision: (payload) =>
    req("/provision", { method: "POST", body: JSON.stringify(payload) }),
  policyPack: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    return req("/policy-pack" + (q ? `?${q}` : ""));
  },
  coverageReconcile: (events) =>
    req("/coverage/reconcile", { method: "POST", body: JSON.stringify({ events }) }),
  stats: () => req("/stats"),
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

  // --- admin settings ---
  updateTenant: (payload) =>
    req("/tenant", { method: "PATCH", body: JSON.stringify(payload) }),
  extensionToken: () => req("/extension/token", { method: "POST" }),
  usage: () => req("/usage"),
  audit: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    return req("/audit" + (q ? `?${q}` : ""));
  },
  upstreams: () => req("/upstreams"),
  setUpstream: (provider, payload) =>
    req(`/upstreams/${provider}`, { method: "PUT", body: JSON.stringify(payload) }),
  deleteUpstream: (provider) => req(`/upstreams/${provider}`, { method: "DELETE" }),
  oidc: () => req("/oidc"),
  setOidc: (payload) => req("/oidc", { method: "PUT", body: JSON.stringify(payload) }),
  deleteOidc: () => req("/oidc", { method: "DELETE" }),
  saml: () => req("/saml"),
  setSaml: (payload) => req("/saml", { method: "PUT", body: JSON.stringify(payload) }),
  deleteSaml: () => req("/saml", { method: "DELETE" }),
  logoutAll: () => req("/auth/logout-all", { method: "POST" }),
};
