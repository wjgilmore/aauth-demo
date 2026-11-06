// Person Server internals: pending requests, demo sessions, token minting, HTML layout.
import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';
import { b64url, envJwk, envUrl, escapeHtml, fromB64url, json, normalizeCode, now, randomId, requirementHeader, sha256, signJwt } from '../../../shared/aauth.mjs';

export const PENDING_TTL = 10 * 60; // seconds a person has to respond

export const psUrl = () => envUrl('PS_URL');
export const psKey = () => envJwk('PS_SIGNING_JWK');

const store = () => getStore({ name: 'pending', consistency: 'strong' });

// ---------------------------------------------------------------------------
// Pending requests (one per person-token or auth-token request awaiting the person)
// ---------------------------------------------------------------------------

export async function createPending(fields) {
  const id = randomId(18); // unguessable polling URL
  const pending = { id, status: 'pending', createdAt: now(), expiresAt: now() + PENDING_TTL, ...fields };
  await store().setJSON(`req/${id}`, pending);
  await store().set(`code/${normalizeCode(pending.code)}`, id);
  return pending;
}

/** What we remember about the agent that made a request (from its verified agent token). */
export function agentSummary(agent) {
  return {
    sub: agent.payload.sub,
    iss: agent.payload.iss,
    name: agent.meta.name || agent.payload.sub,
    callbackEndpoint: agent.meta.callback_endpoint || null,
    jwk: agent.jwk,
    jkt: agent.jkt,
    exp: agent.payload.exp,
  };
}

export function interactionResponse(pending) {
  return json(
    202,
    { status: 'pending' },
    {
      'AAuth-Requirement': requirementHeader('interaction', { url: `${psUrl()}/interact`, code: pending.code }),
      Location: `/aauth/pending/${pending.id}`,
      'Retry-After': '2',
      'Cache-Control': 'no-store',
    },
  );
}

export const getPending = (id) => store().get(`req/${id}`, { type: 'json' });
export const savePending = (p) => store().setJSON(`req/${p.id}`, p);

export async function pendingByCode(code) {
  const id = await store().get(`code/${normalizeCode(code)}`);
  return id ? getPending(id) : null;
}

export const consumeCode = (code) => store().delete(`code/${normalizeCode(code)}`);

// ---------------------------------------------------------------------------
// Demo sessions: a display name in an HMAC-signed cookie. Not real authentication.
// ---------------------------------------------------------------------------

const COOKIE = 'ps_session';
const hmac = (data) => b64url(crypto.createHmac('sha256', process.env.PS_SESSION_SECRET || '').update(data).digest());

export function readSession(req) {
  const raw = (req.headers.get('cookie') || '').split(/;\s*/).find((c) => c.startsWith(`${COOKIE}=`));
  if (!raw) return null;
  const [data, mac] = raw.slice(COOKIE.length + 1).split('.');
  if (!data || !mac || mac.length !== hmac(data).length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(hmac(data)))) return null;
  try {
    const session = JSON.parse(fromB64url(data));
    return session.exp > now() ? session : null;
  } catch {
    return null;
  }
}

/** Start a demo session. Returns the session and the Set-Cookie value for it. */
export function newSession(name) {
  const session = { uid: randomId(12), name, exp: now() + 86400 };
  const data = b64url(JSON.stringify(session));
  const secure = psUrl().startsWith('https:') ? '; Secure' : '';
  return { session, cookie: `${COOKIE}=${data}.${hmac(data)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${secure}` };
}

export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;

/**
 * Directed (pairwise) subject identifier: stable per person + resource, so two
 * resources can't correlate the same person by `sub`.
 */
export const pairwiseSub = (uid, resource) =>
  b64url(sha256(`${uid}|${resource}|${process.env.PS_SESSION_SECRET}`)).slice(0, 22);

// ---------------------------------------------------------------------------
// Remembered grants ("Always allow"): PS policy that lets the auth_token
// endpoint answer 200 directly instead of asking the person again.
// ---------------------------------------------------------------------------

// The auth_token request carries the resource, the person's pairwise sub (from the
// person token) and the agent identity; together they find the grant.
const grantKey = (resource, sub, agent) => b64url(sha256(`${resource}|${sub}|${agent.iss}|${agent.sub}`));

export const scopeCovered = (granted, requested) => {
  const have = new Set(String(granted).split(' '));
  return String(requested).split(' ').filter(Boolean).every((s) => have.has(s));
};

export async function saveGrant(pending, session) {
  const key = grantKey(pending.resource, pending.sub, pending.agent);
  const grant = {
    key,
    uid: session.uid,
    name: session.name,
    resource: pending.resource,
    resourceName: pending.resourceName,
    agentName: pending.agent.name,
    agentSub: pending.agent.sub,
    scope: pending.scope,
    scopeDescriptions: pending.scopeDescriptions,
    createdAt: now(),
  };
  await store().setJSON(`grant/${key}`, grant);
  await store().set(`usergrant/${session.uid}/${key}`, key); // index for the account page
  return grant;
}

export const findGrant = (resource, sub, agent) => store().get(`grant/${grantKey(resource, sub, agent)}`, { type: 'json' });

export async function listGrants(uid) {
  const { blobs } = await store().list({ prefix: `usergrant/${uid}/` });
  const grants = await Promise.all(blobs.map((b) => store().get(`grant/${b.key.split('/').pop()}`, { type: 'json' })));
  return grants.filter(Boolean).sort((a, b) => b.createdAt - a.createdAt);
}

/** Revoke every grant made in a session (used by "Start over"). Returns how many. */
export async function revokeAllGrants(uid) {
  const { blobs } = await store().list({ prefix: `usergrant/${uid}/` });
  for (const b of blobs) await revokeGrant(uid, b.key.split('/').pop());
  return blobs.length;
}

export async function revokeGrant(uid, key) {
  const grant = await store().get(`grant/${key}`, { type: 'json' });
  if (!grant || grant.uid !== uid) return false;
  await store().delete(`grant/${key}`);
  await store().delete(`usergrant/${uid}/${key}`);
  return true;
}

// ---------------------------------------------------------------------------
// Token minting
// ---------------------------------------------------------------------------

export function mintPersonToken(pending, session) {
  const t = now();
  const exp = Math.min(t + 3600, pending.agent.exp);
  const token = signJwt({
    typ: 'aa-person+jwt',
    jwk: psKey(),
    payload: {
      iss: psUrl(),
      dwk: 'aauth-person.json',
      aud: pending.resource,
      sub: pairwiseSub(session.uid, pending.resource),
      cnf: { jwk: pending.agent.jwk },
      jti: randomId(),
      iat: t,
      exp,
    },
  });
  return { field: 'person_token', token, expiresIn: exp - t };
}

export function mintAuthToken(pending, session) {
  const t = now();
  const exp = Math.min(t + 3600, pending.agent.exp, pending.presentedExp);
  const scopes = pending.scope.split(' ');
  const token = signJwt({
    typ: 'aa-auth+jwt',
    jwk: psKey(),
    payload: {
      iss: psUrl(),
      dwk: 'aauth-person.json',
      aud: pending.resource,
      ps: psUrl(),
      sub: pending.sub,
      cnf: { jwk: pending.agent.jwk },
      scope: pending.scope,
      ...(scopes.includes('profile') ? { name: session.name } : {}),
      jti: randomId(),
      iat: t,
      exp,
    },
  });
  return { field: 'auth_token', token, expiresIn: exp - t };
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

export const html = (status, body, headers = {}) =>
  new Response(page(body), { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...headers } });

export function page(body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Person Server</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body data-role="ps">
  <nav id="demo-nav" class="demo-nav" aria-label="Demo sites"></nav>
  <header class="site">
    <span class="badge">Person Server</span>
    <h1><a href="/">Your Person Server</a></h1>
  </header>
  <main>${body}</main>
  <footer>AAuth demo · Person Server · <a href="/.well-known/aauth-person.json">Metadata</a></footer>
  <script src="/nav.js"></script>
</body>
</html>`;
}

export const esc = escapeHtml;
