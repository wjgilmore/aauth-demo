// Agent provider metadata (/.well-known/aauth-agent.json) and JWKS.
// The JWKS holds the agent *provider* key that signs agent tokens; the agent's own
// request-signing key travels inside each agent token as cnf.jwk.
import { envJwk, envUrl, json, jwksResponse, requestPath } from '../../../shared/aauth.mjs';

export default async (req) => {
  if (requestPath(req) === '/jwks.json') return jwksResponse(envJwk('AGENT_PROVIDER_JWK'));
  const AGENT = envUrl('AGENT_URL');
  return json(
    200,
    {
      issuer: AGENT,
      jwks_uri: `${AGENT}/jwks.json`,
      callback_endpoint: `${AGENT}/callback`,
      name: 'Demo Posting Agent',
      description: 'A demo agent that posts messages to the AAuth demo board on your behalf.',
    },
    { 'cache-control': 'public, max-age=60', 'access-control-allow-origin': '*' },
  );
};

export const config = { path: ['/.well-known/aauth-agent.json', '/jwks.json'] };
