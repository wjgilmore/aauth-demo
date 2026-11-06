// The message board's API, an AAuth resource in "PS authorization" (three-party) mode.
//
//   GET  /api/posts   public, lists recent posts
//   POST /api/posts   AAuth-protected; requires an auth token with scope board.write
//
// A POST walks the agent through the AAuth challenges:
//   agent token   -> 401 requirement=person-token
//   person token  -> 401 requirement=auth-token; resource-token="..."
//   auth token    -> 201 Created

import { getStore } from '@netlify/blobs';
import {
  AAuthError,
  b64url,
  envJwk,
  envUrl,
  errorResponse,
  json,
  now,
  problem,
  randomId,
  requirementHeader,
  sha256,
  signJwt,
  verifySignedRequest,
} from '../../../shared/aauth.mjs';
import { checkMessage, cleanName } from '../../../shared/content.mjs';
import { peek, take } from '../../../shared/ratelimit.mjs';

const MAX_POSTS = 100;
const MAX_AGE_SECONDS = 24 * 60 * 60;
export const SCOPE = 'board.write profile';

const store = () => getStore({ name: 'posts', consistency: 'strong' });

// ---------------------------------------------------------------------------
// Rate limits. Agents call the board from their own servers, so IP addresses
// say little about who is posting. Instead the board limits what it can verify:
//   * each person (their PS + pairwise sub)
//   * each Person Server other than the demo's own, since anyone can run a PS
//     and mint unlimited "people"
//   * the board as a whole, as a final backstop
// Defaults can be overridden with the environment variables below.
// ---------------------------------------------------------------------------

const limitsStore = () => getStore({ name: 'ratelimit', consistency: 'strong' });
const envInt = (name, fallback) => {
  const v = Number(process.env[name]);
  return Number.isInteger(v) && v > 0 ? v : fallback;
};

function buckets({ iss, sub } = {}) {
  const list = [];
  if (iss && sub) {
    list.push({
      key: `person/${b64url(sha256(`${iss}|${sub}`))}`,
      who: 'you',
      limits: [
        { max: envInt('BOARD_RATE_PERSON_PER_MINUTE', 3), window: 60 },
        { max: envInt('BOARD_RATE_PERSON_PER_HOUR', 15), window: 3600 },
      ],
    });
  }
  if (iss && iss !== process.env.PS_URL) {
    list.push({
      key: `ps/${b64url(sha256(iss))}`,
      who: `people using ${new URL(iss).host}`,
      limits: [{ max: envInt('BOARD_RATE_PS_PER_HOUR', 30), window: 3600 }],
    });
  }
  list.push({ key: 'global', who: 'everyone combined', limits: [{ max: envInt('BOARD_RATE_GLOBAL_PER_HOUR', 120), window: 3600 }] });
  return list;
}

const humanize = (s) => (s < 90 ? `${s} seconds` : `${Math.ceil(s / 60)} minutes`);

function rateLimited(result) {
  return problem(429, 'rate_limited', `Too many posts from ${result.bucket.who}. Try again in ${humanize(result.retryAfter)}.`, {
    'Retry-After': String(result.retryAfter),
  });
}

async function listPosts() {
  const posts = (await store().get('all', { type: 'json' })) || [];
  const cutoff = Date.now() - MAX_AGE_SECONDS * 1000;
  // Re-apply the content rules on read too, so a rule change also hides older posts.
  return posts
    .filter((p) => Date.parse(p.createdAt) > cutoff && checkMessage(p.message).ok)
    .map((p) => ({ ...p, message: checkMessage(p.message).text, name: cleanName(p.name) }));
}

export default async (req) => {
  if (req.method === 'GET') return json(200, { posts: await listPosts() }, { 'cache-control': 'no-store' });
  if (req.method !== 'POST') return json(405, { error: 'method_not_allowed' });

  try {
    const BOARD_URL = envUrl('BOARD_URL');
    const signed = await verifySignedRequest(req, { accept: ['aa-agent+jwt', 'aa-person+jwt', 'aa-auth+jwt'] });
    const { typ, payload } = signed;

    // Plain text only: HTML stripped, links and explicit terms refused. Checked on
    // every attempt, so a bad message is refused before anyone is asked to approve it.
    let raw;
    try {
      raw = JSON.parse(signed.bodyText || '{}').message;
    } catch {
      throw new AAuthError(400, 'invalid_request', 'Body must be JSON');
    }
    const checked = checkMessage(raw);
    if (!checked.ok) throw new AAuthError(400, 'invalid_message', checked.error);

    // Refuse early (without recording) if this post would be over a limit, so
    // nobody is asked to approve a post the board will turn away.
    if (typ !== 'aa-auth+jwt') {
      const check = await peek(limitsStore(), buckets(typ === 'aa-person+jwt' ? payload : {}));
      if (!check.ok) return rateLimited(check);
    }

    // 1. Agent token only: we need to know which person the agent acts for.
    if (typ === 'aa-agent+jwt') {
      return json(
        401,
        { error: 'person_token_required', detail: 'Ask your Person Server for a person token for this board.' },
        { 'AAuth-Requirement': requirementHeader('person-token') },
      );
    }

    if (payload.aud !== BOARD_URL) throw new AAuthError(401, 'invalid_token', `Token audience must be ${BOARD_URL}`);

    // 2. Person token: we know who, now ask their PS to authorize the write.
    if (typ === 'aa-person+jwt') {
      const t = now();
      const resourceToken = signJwt({
        typ: 'aa-resource+jwt',
        jwk: envJwk('BOARD_SIGNING_JWK'),
        payload: {
          iss: BOARD_URL,
          dwk: 'aauth-resource.json',
          aud: payload.iss, // the person's PS
          ps: payload.iss,
          sub: payload.sub,
          presented_jti: payload.jti,
          agent_jkt: signed.jkt,
          scope: SCOPE,
          jti: randomId(),
          iat: t,
          exp: t + 300,
        },
      });
      return json(
        401,
        { error: 'auth_token_required', detail: 'Exchange the resource token at your Person Server.' },
        { 'AAuth-Requirement': requirementHeader('auth-token', { 'resource-token': resourceToken }) },
      );
    }

    // 3. Auth token: check scope and create the post.
    const scopes = String(payload.scope || '').split(' ');
    if (!scopes.includes('board.write')) throw new AAuthError(403, 'insufficient_scope', 'board.write is required');

    // Count the post against every limit; refuse if any is full.
    const taken = await take(limitsStore(), buckets(payload));
    if (!taken.ok) return rateLimited(taken);

    const post = {
      id: randomId(8),
      message: checked.text,
      name: cleanName(payload.name),
      ps: new URL(payload.iss).host,
      sub: payload.sub,
      agentJkt: signed.jkt,
      createdAt: new Date().toISOString(),
    };
    const posts = [post, ...(await listPosts())].slice(0, MAX_POSTS);
    await store().setJSON('all', posts);
    return json(201, { post });
  } catch (err) {
    return errorResponse(err);
  }
};

export const config = { path: '/api/posts' };
