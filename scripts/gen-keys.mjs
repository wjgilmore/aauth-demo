#!/usr/bin/env node
// Generates signing keys and environment files for the three sites.
//
// Local development (writes person-server/.env, agent/.env, board/.env):
//   npm run keys
//
// Production (writes deploy/*.env for `netlify env:import`):
//   npm run keys -- --ps https://my-ps.netlify.app \
//                   --agent https://my-agent.netlify.app \
//                   --board https://my-board.netlify.app --out deploy

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { generateJwk } from '../shared/aauth.mjs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);

const PS_URL = (args.ps || 'http://localhost:8881').replace(/\/+$/, '');
const AGENT_URL = (args.agent || 'http://localhost:8882').replace(/\/+$/, '');
const BOARD_URL = (args.board || 'http://localhost:8883').replace(/\/+$/, '');
const out = args.out;

const files = {
  'person-server': {
    PS_URL,
    AGENT_URL,
    BOARD_URL,
    PS_SIGNING_JWK: JSON.stringify(generateJwk()),
    PS_SESSION_SECRET: crypto.randomBytes(32).toString('base64url'),
  },
  agent: {
    AGENT_URL,
    PS_URL,
    BOARD_URL,
    AGENT_PROVIDER_JWK: JSON.stringify(generateJwk()),
    AGENT_JWK: JSON.stringify(generateJwk()),
  },
  board: {
    PS_URL,
    AGENT_URL,
    BOARD_URL,
    BOARD_SIGNING_JWK: JSON.stringify(generateJwk()),
  },
};

const root = path.resolve(import.meta.dirname, '..');
for (const [site, vars] of Object.entries(files)) {
  const target = out ? path.join(root, out, `${site}.env`) : path.join(root, site, '.env');
  if (!out && fs.existsSync(target) && !args.force) {
    console.log(`skip  ${path.relative(root, target)} (exists; pass --force to overwrite)`);
    continue;
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const body = Object.entries(vars)
    .map(([k, v]) => `${k}='${v}'`)
    .join('\n');
  fs.writeFileSync(target, `${body}\n`, { mode: 0o600 });
  console.log(`wrote ${path.relative(root, target)}`);
}

if (out) {
  console.log(`\nImport each file into its Netlify site, e.g.:
  (cd person-server && netlify env:import ../${out}/person-server.env)
  (cd agent && netlify env:import ../${out}/agent.env)
  (cd board && netlify env:import ../${out}/board.env)`);
}
