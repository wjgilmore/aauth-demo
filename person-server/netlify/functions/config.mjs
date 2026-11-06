// Public links between the three demo sites, used by the static pages.
import { envUrl, json } from '../../../shared/aauth.mjs';

export default async () =>
  json(200, { psUrl: envUrl('PS_URL'), agentUrl: envUrl('AGENT_URL'), boardUrl: envUrl('BOARD_URL') });

export const config = { path: '/api/config' };
