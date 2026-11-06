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
  envJwk,
  envUrl,
  errorResponse,
  json,
  now,
  randomId,
  requirementHeader,
  signJwt,
  verifySignedRequest,
} from '../../../shared/aauth.mjs';

const MAX_POSTS = 100;
const MAX_AGE_SECONDS = 24 * 60 * 60;
const MAX_LENGTH = 280;
export const SCOPE = 'board.write profile';

const store = () => getStore({ name: 'posts', consistency: 'strong' });

async function listPosts() {
  const posts = (await store().get('all', { type: 'json' })) || [];
  const cutoff = Date.now() - MAX_AGE_SECONDS * 1000;
  return posts.filter((p) => Date.parse(p.createdAt) > cutoff);
}

export default async (req) => {
  if (req.method === 'GET') return json(200, { posts: await listPosts() }, { 'cache-control': 'no-store' });
  if (req.method !== 'POST') return json(405, { error: 'method_not_allowed' });

  try {
    const BOARD_URL = envUrl('BOARD_URL');
    const signed = await verifySignedRequest(req, { accept: ['aa-agent+jwt', 'aa-person+jwt', 'aa-auth+jwt'] });
    const { typ, payload } = signed;

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

    let message;
    try {
      message = String(JSON.parse(signed.bodyText || '{}').message || '').trim();
    } catch {
      throw new AAuthError(400, 'invalid_request', 'Body must be JSON');
    }
    if (!message || message.length > MAX_LENGTH) {
      throw new AAuthError(400, 'invalid_request', `message must be 1-${MAX_LENGTH} characters`);
    }

    const post = {
      id: randomId(8),
      message,
      name: String(payload.name || 'Anonymous').slice(0, 40),
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
