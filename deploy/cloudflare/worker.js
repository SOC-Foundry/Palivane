// Warden front door: Cloudflare Worker that proxies warden.tachtech.net to the
// IAM-locked Cloud Run service, attaching a Google ID token for the warden-front
// service account. This keeps Cloud Run private (no allUsers invoker — org policy
// forbids it) while Cloudflare terminates public TLS and fronts every request;
// hitting the *.run.app URL directly gets 403 because only this Worker's SA may invoke.
//
// The token rides in X-Serverless-Authorization (checked and stripped by Cloud Run's
// IAM layer) so the app's own Authorization header (agent JWTs) passes through intact.
//
// Secret required: GCP_SA_KEY — the warden-front service-account JSON key
//   (npx wrangler secret put GCP_SA_KEY < warden-front-key.json)

const ORIGIN = 'https://warden-442729333907.us-central1.run.app';

// Per-isolate token cache; isolates live across many requests, so most requests
// skip the token exchange entirely.
let cache = { token: null, exp: 0 };

function b64url(data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToDer(pem) {
  const bin = atob(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

async function idToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cache.token && cache.exp - 120 > now) return cache.token;

  const key = JSON.parse(env.GCP_SA_KEY);
  const unsigned =
    b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' +
    b64url(JSON.stringify({
      iss: key.client_email,
      sub: key.client_email,
      aud: 'https://oauth2.googleapis.com/token',
      target_audience: ORIGIN,
      iat: now,
      exp: now + 3600,
    }));
  const pk = await crypto.subtle.importKey('pkcs8', pemToDer(key.private_key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pk, new TextEncoder().encode(unsigned));

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') +
      '&assertion=' + unsigned + '.' + b64url(sig),
  });
  if (!resp.ok) {
    throw new Error('GCP token exchange failed: ' + resp.status + ' ' + (await resp.text()).slice(0, 200));
  }
  const data = await resp.json();
  cache = { token: data.id_token, exp: now + 3600 };
  return data.id_token;
}

// --- Edge WAF -------------------------------------------------------------------------
// Cheap protections in front of the origin: scanner noise dies here (no Cloud Run
// invocation billed), and credential-stuffing floods hit a per-IP edge limit before the
// app's own stricter per-email throttles. Zone-level WAF/custom rules need dashboard
// access, so everything lives in the Worker where wrangler can deploy it.
// (Cloudflare's beta `ratelimit` unsafe binding deploys but never limits on this
// account, so the counters are ours: a Durable Object for exact global per-IP counts on
// auth endpoints, and a coarse in-isolate counter for general API floods.)

// Paths Warden never serves — WordPress/PHP probes, dotfile hunts, Exchange scans.
const BLOCKED_PATH = new RegExp(
  '^/(?:wp-(?:admin|login|content|includes)|wordpress|xmlrpc\\.php|phpmyadmin|pma|' +
  'cgi-bin|vendor/|\\.git|\\.env|\\.aws|\\.ssh|\\.svn|\\.DS_Store|owa/|autodiscover|' +
  'remote/|telescope/|actuator/|solr/|jenkins|HNAP1)', 'i');
const BLOCKED_EXT = /\.(?:php[0-9]?|asp|aspx|jsp|cgi|cfm)$/i;   // app serves none of these

// Credential-stuffing / enumeration magnets (POST only — GETs here are the SPA shell).
const AUTH_PATH = /^\/api\/auth\/(?:login|forgot|reset|mfa)|^\/api\/signup/;
const AUTH_LIMIT = 20;    // POSTs per IP per minute across all auth endpoints (exact, DO)
const API_LIMIT = 600;    // general /api + /v1 per IP per minute (coarse, per-isolate)

function deny(status, text) {
  return new Response(text + '\n', { status, headers: { 'content-type': 'text/plain' } });
}

// Exact per-IP minute counter: one Durable Object per IP, so a distributed stuffing run
// against many emails still converges on one counter per source address.
export class RateCounter {
  constructor() {
    this.counts = new Map();   // minute-window -> count (in-memory; a DO restart just
  }                            // resets the 60s window — fine for flood absorption)

  async fetch(request) {
    const { limit } = await request.json();
    const win = Math.floor(Date.now() / 60000);
    const n = (this.counts.get(win) || 0) + 1;
    this.counts.set(win, n);
    for (const w of this.counts.keys()) if (w < win) this.counts.delete(w);
    return new Response(n <= limit ? 'ok' : 'over');
  }
}

async function authOverLimit(env, ip) {
  try {
    const stub = env.RATE.get(env.RATE.idFromName(ip));
    const r = await stub.fetch('https://rate/', {
      method: 'POST', body: JSON.stringify({ limit: AUTH_LIMIT }),
    });
    return (await r.text()) === 'over';
  } catch {
    return false;   // fail open — the app still has its own throttles
  }
}

// Coarse general-API counter (per isolate): caps single-source floods at
// API_LIMIT × live isolates without a DO round-trip on every request.
const apiCounts = new Map();   // ip -> { win, n }
function apiOverLimit(ip) {
  const win = Math.floor(Date.now() / 60000);
  const c = apiCounts.get(ip);
  if (!c || c.win !== win) {
    if (apiCounts.size > 10000) apiCounts.clear();
    apiCounts.set(ip, { win, n: 1 });
    return false;
  }
  c.n += 1;
  return c.n > API_LIMIT;
}

// Rename cutover: the canonical host is palivane.tachtech.net. The legacy
// warden.tachtech.net stays live (same worker, both routes) and PROXIES all traffic
// transparently — but human/browser navigation (GET/HEAD for non-API paths: the console
// SPA and public site) is 301-redirected to the new host so people land on the new brand.
// API/gateway traffic (/api/*, /v1) is NEVER redirected: installed CLIs, the extension,
// and MDM clients POST there, and a 301 wouldn't replay their bodies — they keep hitting
// the old host transparently until they re-enroll against palivane.
const CANONICAL_HOST = 'palivane.tachtech.net';
const LEGACY_HOST = 'warden.tachtech.net';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'TRACE' || request.method === 'TRACK') {
      return deny(405, 'method not allowed');
    }
    if (BLOCKED_PATH.test(path) || BLOCKED_EXT.test(path)) {
      return deny(404, 'not found');
    }

    // Human navigation on the legacy host → move to the new brand hostname. Programmatic
    // API/gateway calls fall through and are proxied unchanged (see note above).
    const isApi = path.startsWith('/api/') || path.startsWith('/v1');
    const isNav = request.method === 'GET' || request.method === 'HEAD';
    if (url.hostname === LEGACY_HOST && isNav && !isApi) {
      return Response.redirect('https://' + CANONICAL_HOST + path + url.search, 301);
    }

    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (path.startsWith('/api/') || path.startsWith('/v1')) {
      if (request.method === 'POST' && AUTH_PATH.test(path) && await authOverLimit(env, ip)) {
        return deny(429, 'too many authentication attempts — slow down');
      }
      if (apiOverLimit(ip)) {
        return deny(429, 'rate limited');
      }
    }

    const headers = new Headers(request.headers);
    headers.set('X-Serverless-Authorization', 'Bearer ' + (await idToken(env)));
    // redirect: 'manual' so the app's own redirects (login flows) reach the browser
    // instead of being followed inside the Worker.
    return fetch(ORIGIN + path + url.search, {
      method: request.method,
      headers,
      body: request.body,
      redirect: 'manual',
    });
  },
};
