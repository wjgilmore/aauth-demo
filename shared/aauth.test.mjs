// Run with: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  decodeJwt,
  generateJwk,
  interactionCode,
  jwkThumbprint,
  normalizeCode,
  parseRequirement,
  publicJwk,
  requirementHeader,
  signJwt,
  signedFetch,
  verifyLocalJwt,
  verifySignedRequest,
} from './aauth.mjs';

test('JWT round trip and tamper detection', () => {
  const jwk = generateJwk();
  const token = signJwt({ typ: 'aa-person+jwt', jwk, payload: { sub: 'x', exp: Math.floor(Date.now() / 1000) + 60 } });
  assert.equal(verifyLocalJwt(token, { typ: 'aa-person+jwt', jwk }).payload.sub, 'x');
  const [h, , s] = token.split('.');
  const forged = `${h}.${Buffer.from(JSON.stringify({ sub: 'y', exp: 9e9 })).toString('base64url')}.${s}`;
  assert.throws(() => verifyLocalJwt(forged, { typ: 'aa-person+jwt', jwk }));
  assert.throws(() => verifyLocalJwt(token, { typ: 'aa-auth+jwt', jwk }));
});

test('RFC 7638 thumbprint ignores private and optional members', () => {
  const jwk = generateJwk();
  assert.equal(jwkThumbprint(jwk), jwkThumbprint(publicJwk(jwk)));
});

test('AAuth-Requirement round trip', () => {
  const v = requirementHeader('interaction', { url: 'https://ps.example/interact', code: 'ABCD-EFGH' });
  assert.deepEqual(parseRequirement(v), { requirement: 'interaction', url: 'https://ps.example/interact', code: 'ABCD-EFGH' });
});

test('interaction codes are Crockford base32', () => {
  const code = interactionCode();
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.equal(normalizeCode(code.toLowerCase()), code.replace('-', ''));
});

test('signed request verifies end to end through issuer discovery', async () => {
  const providerKey = generateJwk();
  const agentKey = generateJwk();
  let issuer;
  let tamper = false;

  const server = http.createServer(async (req, res) => {
    if (req.url === '/.well-known/aauth-agent.json') return res.end(JSON.stringify({ issuer, jwks_uri: `${issuer}/jwks.json` }));
    if (req.url === '/jwks.json') return res.end(JSON.stringify({ keys: [publicJwk(providerKey)] }));
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let body = Buffer.concat(chunks).toString();
    if (tamper) body = body.replace('hello', 'HELLO');
    const request = new Request(`${issuer}${req.url}`, { method: req.method, headers: req.headers, body: body || undefined });
    try {
      const v = await verifySignedRequest(request, { accept: ['aa-agent+jwt'] });
      res.end(JSON.stringify({ ok: true, sub: v.payload.sub, body: v.bodyText }));
    } catch (e) {
      res.writeHead(e.status || 500, e.headers || {});
      res.end(JSON.stringify({ error: e.error, detail: e.detail }));
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  issuer = `http://127.0.0.1:${server.address().port}`;

  const now = Math.floor(Date.now() / 1000);
  const token = signJwt({
    typ: 'aa-agent+jwt',
    jwk: providerKey,
    payload: { iss: issuer, dwk: 'aauth-agent.json', sub: 'aauth:test@example', cnf: { jwk: publicJwk(agentKey) }, iat: now, exp: now + 60 },
  });

  try {
    const ok = await signedFetch(`${issuer}/api`, { method: 'POST', body: { message: 'hello' }, token, jwk: agentKey });
    assert.equal(ok.response.status, 200, await ok.response.clone().text());
    assert.equal((await ok.response.json()).sub, 'aauth:test@example');

    const get = await signedFetch(`${issuer}/api`, { token, jwk: agentKey });
    assert.equal(get.response.status, 200);

    // Signed with a key that isn't the one in cnf.
    const wrong = await signedFetch(`${issuer}/api`, { token, jwk: generateJwk() });
    assert.equal(wrong.response.status, 401);
    assert.equal(wrong.response.headers.get('signature-error'), 'error=invalid_signature');

    // Body altered in transit.
    tamper = true;
    const bad = await signedFetch(`${issuer}/api`, { method: 'POST', body: { message: 'hello' }, token, jwk: agentKey });
    assert.equal(bad.response.status, 401);
    assert.equal(decodeJwt(token).header.typ, 'aa-agent+jwt');
  } finally {
    server.close();
  }
});
