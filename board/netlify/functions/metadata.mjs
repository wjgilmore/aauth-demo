// Resource metadata and JWKS for the board.
import { envJwk, envUrl, json, jwksResponse, requestPath } from '../../../shared/aauth.mjs';

export default async (req) => {
  if (requestPath(req) === '/jwks.json') return jwksResponse(envJwk('BOARD_SIGNING_JWK'));

  const BOARD_URL = envUrl('BOARD_URL');
  return json(
    200,
    {
      issuer: BOARD_URL,
      jwks_uri: `${BOARD_URL}/jwks.json`,
      access_mode: 'auth-token',
      name: 'AAuth Demo Message Board',
      description: 'A public message board. Agents may post on your behalf only with your Person Server\'s approval.',
      scope_descriptions: {
        'board.write': 'Post a message to the public board',
        profile: 'Show your display name next to the post',
      },
      signature_window: 60,
    },
    { 'cache-control': 'public, max-age=60', 'access-control-allow-origin': '*' },
  );
};

export const config = { path: ['/.well-known/aauth-resource.json', '/jwks.json'] };
