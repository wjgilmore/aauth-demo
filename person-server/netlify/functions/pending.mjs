// Polling URL (the Location from a 202). Only the agent whose key started the request may poll.
import { errorResponse, json, now, problem, requestPath, verifySignedRequest } from '../../../shared/aauth.mjs';
import { getPending } from '../lib/ps.mjs';

export default async (req) => {
  try {
    const agent = await verifySignedRequest(req, { accept: ['aa-agent+jwt'] });
    const pending = await getPending(requestPath(req).split('/').pop());
    if (!pending) return problem(410, 'invalid_code', 'Unknown or finished request');
    if (pending.agent.jkt !== agent.jkt) return problem(403, 'denied', 'This request belongs to a different agent');

    switch (pending.status) {
      case 'approved':
        // Retained until the issued token expires so a lost response can be re-polled.
        if (pending.result.exp <= now()) return problem(410, 'invalid_code', 'Result has expired');
        return json(200, { [pending.result.field]: pending.result.token, expires_in: pending.result.exp - now() }, { 'Cache-Control': 'no-store' });
      case 'denied':
        return problem(403, 'denied', 'The person declined this request');
      default:
        if (pending.expiresAt <= now()) return problem(408, 'expired', 'The person did not respond in time');
        return json(202, { status: pending.viewed ? 'interacting' : 'pending' }, { 'Retry-After': '2', 'Cache-Control': 'no-store' });
    }
  } catch (err) {
    return errorResponse(err);
  }
};

export const config = { path: '/aauth/pending/:id' };
