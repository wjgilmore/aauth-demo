// auth_token_endpoint: an agent exchanges a resource token (plus the person token it
// presented) for an auth token. The PS asks the person to approve the requested scope.
import { AAuthError, errorResponse, interactionCode, json, verifyJwt, verifyLocalJwt, verifySignedRequest } from '../../../shared/aauth.mjs';
import { agentSummary, createPending, findGrant, interactionResponse, mintAuthToken, noteNextStep, psKey, psUrl, scopeCovered } from '../lib/ps.mjs';

export default async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'method_not_allowed' });
  try {
    const agent = await verifySignedRequest(req, { accept: ['aa-agent+jwt'] });
    let body;
    try {
      body = JSON.parse(agent.bodyText || '{}');
    } catch {
      throw new AAuthError(400, 'invalid_request', 'Body must be JSON');
    }
    if (!body.resource_token || !body.presented_token) {
      throw new AAuthError(400, 'invalid_request', 'resource_token and presented_token are required');
    }

    // The resource token is signed by the resource and addressed to us.
    const rt = await verifyJwt(body.resource_token, { typ: 'aa-resource+jwt', dwk: 'aauth-resource.json' }).catch((e) => {
      throw new AAuthError(400, 'invalid_resource_token', e.detail || e.message);
    });
    const r = rt.payload;
    if (r.aud !== psUrl()) throw new AAuthError(400, 'invalid_resource_token', 'Resource token is not addressed to this PS');
    if (r.agent_jkt !== agent.jkt) throw new AAuthError(400, 'invalid_resource_token', 'Resource token was issued to a different agent key');

    // The presented token must be the person token we issued for this resource and agent.
    const pt = (() => {
      try {
        return verifyLocalJwt(body.presented_token, { typ: 'aa-person+jwt', jwk: psKey() }).payload;
      } catch (e) {
        throw new AAuthError(400, 'invalid_presented_token', e.detail || e.message);
      }
    })();
    const checks = [
      [pt.iss === psUrl(), 'issuer'],
      [pt.aud === r.iss, 'audience'],
      [pt.sub === r.sub, 'subject'],
      [pt.jti === r.presented_jti, 'presented_jti'],
      [pt.cnf?.jwk?.x === agent.jwk.x, 'agent key'],
    ];
    const failed = checks.find(([ok]) => !ok);
    if (failed) throw new AAuthError(400, 'invalid_presented_token', `Presented token ${failed[1]} mismatch`);

    const request = {
      resource: r.iss,
      resourceName: rt.meta.name || new URL(r.iss).host,
      scope: r.scope || '',
      scopeDescriptions: rt.meta.scope_descriptions || {},
      justification: typeof body.justification === 'string' ? body.justification.slice(0, 1000) : '',
      sub: r.sub,
      presentedExp: pt.exp,
      agent: agentSummary(agent),
    };

    // PS policy: if the person chose "Always allow" for this agent + resource and
    // the grant covers the requested scope, issue the auth token without asking.
    const grant = await findGrant(request.resource, request.sub, request.agent);
    if (grant && scopeCovered(grant.scope, request.scope)) {
      const minted = mintAuthToken(request, { name: grant.name });
      await noteNextStep(request.sub, request.agent.jkt, { auto: true });
      return json(200, { auth_token: minted.token, expires_in: minted.expiresIn }, { 'Cache-Control': 'no-store' });
    }

    const pending = await createPending({ kind: 'auth', code: interactionCode(), ...request });
    return interactionResponse(pending);
  } catch (err) {
    return errorResponse(err);
  }
};

export const config = { path: '/aauth/token' };
