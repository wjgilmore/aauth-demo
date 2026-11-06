// Person Server metadata (/.well-known/aauth-person.json) and JWKS.
import { json, jwksResponse, requestPath } from '../../../shared/aauth.mjs';
import { psKey, psUrl } from '../lib/ps.mjs';

export default async (req) => {
  if (requestPath(req) === '/jwks.json') return jwksResponse(psKey());
  const PS = psUrl();
  return json(
    200,
    {
      issuer: PS,
      jwks_uri: `${PS}/jwks.json`,
      person_token_endpoint: `${PS}/aauth/person`,
      auth_token_endpoint: `${PS}/aauth/token`,
      scopes_supported: ['profile'],
      claims_supported: ['name'],
      accept_signature_algs: ['Ed25519'],
      name: 'AAuth Demo Person Server',
      description: 'A demo Person Server. Sign in with any display name; agents ask here before acting for you.',
    },
    { 'cache-control': 'public, max-age=60', 'access-control-allow-origin': '*' },
  );
};

export const config = { path: ['/.well-known/aauth-person.json', '/jwks.json'] };
