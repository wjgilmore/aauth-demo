// Minimal AAuth helpers shared by all three demo sites.
//
// Implements just enough of draft-hardt-oauth-aauth-protocol-11 and
// draft-hardt-httpbis-signature-key-09 for the demo:
//   * Ed25519 JWTs (agent, person, resource and auth tokens)
//   * RFC 9421 HTTP Message Signatures with the `jwt` Signature-Key scheme
//   * Issuer metadata / JWKS discovery
//
// Only Node built-ins are used so the code is easy to read and audit.

import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

export const b64url = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64url = (s) => Buffer.from(s, 'base64url');
export const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
export const randomId = (bytes = 16) => b64url(crypto.randomBytes(bytes));
export const now = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class AAuthError extends Error {
  constructor(status, error, detail, headers = {}) {
    super(detail || error);
    this.status = status;
    this.error = error;
    this.detail = detail;
    this.headers = headers;
  }
}

/** 401 carrying a Signature-Error header (signature-key draft, Section 5). */
export const signatureError = (code, detail) =>
  new AAuthError(401, code, detail, { 'Signature-Error': `error=${code}` });

export function problem(status, error, detail, headers = {}) {
  return new Response(JSON.stringify({ error, detail }), {
    status,
    headers: { 'content-type': 'application/problem+json', ...headers },
  });
}

export function errorResponse(err) {
  if (err instanceof AAuthError) return problem(err.status, err.error, err.detail, err.headers);
  console.error(err);
  return problem(500, 'server_error', 'Unexpected server error');
}

export function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** Generate an Ed25519 private JWK with `alg` and a thumbprint `kid`. */
export function generateJwk() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' });
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d, alg: 'Ed25519', kid: jwkThumbprint(jwk).slice(0, 16) };
}

export function publicJwk(jwk) {
  const { kty, crv, x, alg, kid } = jwk;
  return { kty, crv, x, alg, ...(kid ? { kid } : {}) };
}

/** RFC 7638 JWK thumbprint (OKP keys: crv, kty, x). */
export function jwkThumbprint(jwk) {
  return b64url(sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })));
}

function assertEd25519(jwk) {
  // The spec requires fully-specified algorithms and rejects kty/crv/alg mismatches.
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || jwk.alg !== 'Ed25519' || !jwk.x) {
    throw signatureError('invalid_key', 'Only Ed25519 OKP keys with alg "Ed25519" are supported by this demo');
  }
}

function keyObject(jwk) {
  assertEd25519(jwk);
  const material = { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
  return jwk.d
    ? crypto.createPrivateKey({ key: { ...material, d: jwk.d }, format: 'jwk' })
    : crypto.createPublicKey({ key: material, format: 'jwk' });
}

/** Read a private JWK from an environment variable. */
export function envJwk(name) {
  const raw = process.env[name];
  if (!raw) throw new Error(`Missing environment variable ${name}. Run "npm run keys" (see README).`);
  return JSON.parse(raw);
}

export function envUrl(name) {
  const raw = process.env[name] || (name.endsWith('_SELF') ? process.env.URL : undefined);
  if (!raw) throw new Error(`Missing environment variable ${name}. Run "npm run keys" (see README).`);
  return raw.replace(/\/+$/, '');
}

// ---------------------------------------------------------------------------
// JWTs
// ---------------------------------------------------------------------------

export function signJwt({ typ, payload, jwk }) {
  const header = { alg: 'Ed25519', typ, kid: jwk.kid };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = crypto.sign(null, Buffer.from(input), keyObject(jwk));
  return `${input}.${b64url(sig)}`;
}

export function decodeJwt(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw signatureError('invalid_jwt', 'Malformed JWT');
  try {
    return {
      header: JSON.parse(fromB64url(parts[0])),
      payload: JSON.parse(fromB64url(parts[1])),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: fromB64url(parts[2]),
    };
  } catch {
    throw signatureError('invalid_jwt', 'Malformed JWT');
  }
}

function verifyJwtSignature(decoded, jwk) {
  if (decoded.header.alg !== jwk.alg) throw signatureError('unsupported_algorithm', 'JWT alg does not match key alg');
  const ok = crypto.verify(null, Buffer.from(decoded.signingInput), keyObject(jwk), decoded.signature);
  if (!ok) throw signatureError('invalid_jwt', 'JWT signature is invalid');
}

/** Verify a JWT signed by a key we hold locally (e.g. a PS checking its own person token). */
export function verifyLocalJwt(token, { typ, jwk }) {
  const decoded = decodeJwt(token);
  if (decoded.header.typ !== typ) throw signatureError('invalid_jwt', `Expected typ ${typ}`);
  verifyJwtSignature(decoded, publicJwk(jwk));
  if (typeof decoded.payload.exp !== 'number' || decoded.payload.exp <= now()) {
    throw signatureError('expired_jwt', 'Token has expired');
  }
  return decoded;
}

// ---------------------------------------------------------------------------
// Discovery: {iss}/.well-known/{dwk} -> jwks_uri -> key by kid
// ---------------------------------------------------------------------------

const fetchCache = new Map();
const CACHE_MS = 60_000;

/**
 * Server identifiers must be HTTPS origins. http://localhost is allowed so the
 * demo can run under `netlify dev`.
 */
export function assertServerId(id) {
  let u;
  try {
    u = new URL(id);
  } catch {
    throw signatureError('issuer_missing', `Not a URL: ${id}`);
  }
  const local = ['localhost', '127.0.0.1'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) {
    throw signatureError('issuer_mismatch', `Server identifiers must be https: ${id}`);
  }
  if (u.origin !== id) throw signatureError('issuer_mismatch', `Server identifier must be a bare origin: ${id}`);
  return u;
}

export async function fetchJson(url, { fresh = false } = {}) {
  const hit = fetchCache.get(url);
  if (!fresh && hit && hit.expires > Date.now()) return hit.value;
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new AAuthError(502, 'unknown_key', `Fetching ${url} returned ${res.status}`);
  const value = await res.json();
  fetchCache.set(url, { value, expires: Date.now() + CACHE_MS });
  return value;
}

export async function fetchMetadata(iss, dwk) {
  assertServerId(iss);
  const meta = await fetchJson(`${iss}/.well-known/${dwk}`);
  if (meta.issuer !== iss) throw signatureError('issuer_mismatch', `Metadata issuer ${meta.issuer} != ${iss}`);
  return meta;
}

async function resolveKey(iss, dwk, kid) {
  const meta = await fetchMetadata(iss, dwk);
  let jwks = await fetchJson(meta.jwks_uri);
  let key = jwks.keys?.find((k) => k.kid === kid);
  if (!key) {
    jwks = await fetchJson(meta.jwks_uri, { fresh: true }); // refresh once on unknown kid
    key = jwks.keys?.find((k) => k.kid === kid);
  }
  if (!key) throw signatureError('unknown_key', `No key ${kid} in ${meta.jwks_uri}`);
  return { key, meta };
}

/** Verify a JWT issued by a remote AAuth server, discovering its key via iss + dwk. */
export async function verifyJwt(token, { typ, dwk }) {
  const decoded = decodeJwt(token);
  const { header, payload } = decoded;
  if (header.typ !== typ) throw signatureError('invalid_jwt', `Expected typ ${typ}, got ${header.typ}`);
  if (payload.dwk !== dwk) throw signatureError('invalid_jwt', `Expected dwk ${dwk}`);
  if (!payload.iss) throw signatureError('issuer_missing', 'JWT has no iss');
  const { key, meta } = await resolveKey(payload.iss, dwk, header.kid);
  verifyJwtSignature(decoded, key);
  if (typeof payload.exp !== 'number' || payload.exp <= now()) throw signatureError('expired_jwt', 'Token has expired');
  return { header, payload, meta };
}

// Token types and the metadata document their issuer publishes.
export const TOKEN_TYPES = {
  'aa-agent+jwt': 'aauth-agent.json',
  'aa-person+jwt': 'aauth-person.json',
  'aa-auth+jwt': 'aauth-person.json',
  'aa-resource+jwt': 'aauth-resource.json',
};

/**
 * The path as the client sent it. When a function returns 403 or 404, `netlify dev`
 * re-invokes it with pretty-URL fallbacks appended ("/index.html", ".html", ...),
 * which would break @path and route matching. Only applied under `netlify dev`.
 */
export function cleanPath(pathname) {
  if (!process.env.NETLIFY_DEV) return pathname;
  return pathname.replace(/(\/index)?\.html?$/, '') || '/';
}

export const requestPath = (req) => cleanPath(new URL(req.url).pathname);

// ---------------------------------------------------------------------------
// HTTP Message Signatures (RFC 9421), AAuth profile
// ---------------------------------------------------------------------------

const BASE_COMPONENTS = ['@method', '@authority', '@path', 'signature-key'];
const SIGNATURE_WINDOW = 60;

export const contentDigest = (body) => `sha-256=:${sha256(body).toString('base64')}:`;

function componentValue(name, { method, url, headers }) {
  switch (name) {
    case '@method':
      return method.toUpperCase();
    case '@authority':
      return url.host.toLowerCase();
    case '@path':
      return cleanPath(url.pathname);
    default: {
      const v = headers.get(name);
      if (v === null) throw signatureError('invalid_input', `Covered component ${name} is missing`);
      return v.trim();
    }
  }
}

function signatureBase(components, params, msg) {
  const lines = components.map((c) => `"${c}": ${componentValue(c, msg)}`);
  lines.push(`"@signature-params": ${params}`);
  return lines.join('\n');
}

/**
 * Make a signed AAuth request. `token` is the JWT carried in Signature-Key
 * (agent, person or auth token) and `jwk` is the private key bound to it via cnf.
 * Returns { response, request } where request is a loggable description.
 */
export async function signedFetch(url, { method = 'GET', body, token, jwk, headers: extra = {} }) {
  const u = new URL(url);
  const headers = new Headers(extra);
  const components = [...BASE_COMPONENTS];
  let bodyText;
  if (body !== undefined) {
    bodyText = JSON.stringify(body);
    headers.set('content-type', 'application/json');
    headers.set('content-digest', contentDigest(bodyText));
    components.push('content-type', 'content-digest');
  }
  headers.set('signature-key', `sig=jwt;jwt="${token}"`);
  const params = `(${components.map((c) => `"${c}"`).join(' ')});created=${now()}`;
  const base = signatureBase(components, params, { method, url: u, headers });
  const sig = crypto.sign(null, Buffer.from(base), keyObject(jwk));
  headers.set('signature-input', `sig=${params}`);
  headers.set('signature', `sig=:${sig.toString('base64')}:`);

  const response = await fetch(u, { method, headers, body: bodyText });
  return { response, request: { method, url: u.href, headers: Object.fromEntries(headers), body: body ?? null } };
}

/**
 * Verify a signed AAuth request arriving at a server.
 * `accept` lists the token types this endpoint accepts in Signature-Key.
 * Returns { typ, header, payload, meta, jwk, jkt, bodyText }.
 */
export async function verifySignedRequest(req, { accept }) {
  const sigKey = req.headers.get('signature-key');
  const sigInput = req.headers.get('signature-input');
  const sigHeader = req.headers.get('signature');
  if (!sigKey || !sigInput || !sigHeader) {
    throw new AAuthError(401, 'unauthorized', 'This endpoint requires an AAuth-signed request', {
      'AAuth-Requirement': 'requirement=agent-token',
    });
  }

  // Signature-Key: sig=jwt;jwt="<JWT>"  (agents MUST use the jwt scheme)
  const keyMatch = sigKey.match(/^sig=jwt;\s*jwt="([^"]+)"$/);
  if (!keyMatch) {
    const err = signatureError('unsupported_scheme', 'Use the jwt Signature-Key scheme with label "sig"');
    err.headers['Accept-Signature-Scheme'] = 'jwt';
    throw err;
  }
  const token = keyMatch[1];

  // Signature-Input: sig=("@method" ...);created=123
  const inputMatch = sigInput.match(/^sig=(\(([^)]*)\)(.*))$/);
  if (!inputMatch) throw signatureError('invalid_input', 'Malformed Signature-Input');
  const params = inputMatch[1];
  const components = (inputMatch[2].match(/"[^"]+"/g) || []).map((c) => c.slice(1, -1));
  const created = Number(params.match(/;created=(\d+)/)?.[1]);
  const expires = Number(params.match(/;expires=(\d+)/)?.[1]);
  if (/;alg=/.test(params)) throw signatureError('invalid_input', 'Agents must not send the alg parameter');

  const bodyText = req.method === 'GET' || req.method === 'HEAD' ? '' : await req.text();
  const required = [...BASE_COMPONENTS, ...(bodyText ? ['content-type', 'content-digest'] : [])];
  const missing = required.filter((c) => !components.includes(c));
  if (missing.length) throw signatureError('invalid_input', `Signature must cover: ${missing.join(', ')}`);

  if (!created) throw signatureError('invalid_input', 'Signature-Input must include created');
  const t = now();
  if (Math.abs(t - created) > SIGNATURE_WINDOW) throw signatureError('clock_skew', 'Signature created outside the 60s window');
  if (expires && expires < t) throw signatureError('invalid_signature', 'Signature has expired');

  if (bodyText && req.headers.get('content-digest') !== contentDigest(bodyText)) {
    throw signatureError('invalid_signature', 'Content-Digest does not match the body');
  }

  // Identify and verify the JWT carried in Signature-Key.
  const { header } = decodeJwt(token);
  if (!accept.includes(header.typ)) {
    throw signatureError('invalid_jwt', `This endpoint accepts ${accept.join(', ')}; got ${header.typ}`);
  }
  const verified = await verifyJwt(token, { typ: header.typ, dwk: TOKEN_TYPES[header.typ] });
  const jwk = verified.payload.cnf?.jwk;
  if (!jwk) throw signatureError('invalid_jwt', 'Token has no cnf.jwk');

  // Verify the HTTP signature with the key the token is bound to.
  const sigMatch = sigHeader.match(/^sig=:([A-Za-z0-9+/=]+):$/);
  if (!sigMatch) throw signatureError('invalid_signature', 'Malformed Signature header');
  const url = new URL(req.url);
  const base = signatureBase(components, params, { method: req.method, url, headers: req.headers });
  const ok = crypto.verify(null, Buffer.from(base), keyObject(jwk), Buffer.from(sigMatch[1], 'base64'));
  if (!ok) throw signatureError('invalid_signature', 'HTTP message signature is invalid');

  return { typ: header.typ, token, ...verified, jwk, jkt: jwkThumbprint(jwk), bodyText };
}

// ---------------------------------------------------------------------------
// AAuth-Requirement header
// ---------------------------------------------------------------------------

export function requirementHeader(requirement, params = {}) {
  return [`requirement=${requirement}`, ...Object.entries(params).map(([k, v]) => `${k}="${v}"`)].join('; ');
}

/** Parse e.g. `requirement=auth-token; resource-token="eyJ..."` into an object. */
export function parseRequirement(value) {
  const out = {};
  if (!value) return out;
  for (const part of value.split(';')) {
    const m = part.trim().match(/^([A-Za-z0-9_-]+)=(?:"((?:[^"\\]|\\.)*)"|(\S*))$/);
    if (m) out[m[1]] = m[2] ?? m[3];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Interaction codes: Crockford base32, 8 symbols (40 bits), shown as XXXX-XXXX
// ---------------------------------------------------------------------------

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function interactionCode() {
  let s = '';
  for (let i = 0; i < 8; i++) s += CROCKFORD[crypto.randomInt(32)];
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

export const normalizeCode = (code) => String(code || '').replace(/-/g, '').toUpperCase();

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

export const escapeHtml = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export const jwksResponse = (...jwks) => json(200, { keys: jwks.map(publicJwk) }, { 'cache-control': 'public, max-age=300' });
