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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = new Headers(request.headers);
    headers.set('X-Serverless-Authorization', 'Bearer ' + (await idToken(env)));
    // redirect: 'manual' so the app's own redirects (login flows) reach the browser
    // instead of being followed inside the Worker.
    return fetch(ORIGIN + url.pathname + url.search, {
      method: request.method,
      headers,
      body: request.body,
      redirect: 'manual',
    });
  },
};
