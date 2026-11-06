// person_token_endpoint: an agent asks "who is my person, as far as resource X is concerned?"
// The PS always involves the person, so this returns 202 with an interaction requirement.
import { AAuthError, assertServerId, errorResponse, fetchMetadata, interactionCode, json, verifySignedRequest } from '../../../shared/aauth.mjs';
import { agentSummary, createPending, interactionResponse } from '../lib/ps.mjs';

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
    if (!body.resource) throw new AAuthError(400, 'invalid_request', 'resource is required');
    assertServerId(body.resource);

    const resourceMeta = await fetchMetadata(body.resource, 'aauth-resource.json').catch(() => null);
    const pending = await createPending({
      kind: 'person',
      code: interactionCode(),
      resource: body.resource,
      resourceName: resourceMeta?.name || new URL(body.resource).host,
      agent: agentSummary(agent),
    });
    return interactionResponse(pending);
  } catch (err) {
    return errorResponse(err);
  }
};

export const config = { path: '/aauth/person' };
