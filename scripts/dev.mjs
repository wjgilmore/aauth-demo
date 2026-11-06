#!/usr/bin/env node
// Runs all three sites with `netlify dev`, each on its own port:
//   Person Server  http://localhost:8881
//   Agent          http://localhost:8882
//   Board          http://localhost:8883

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const sites = [
  ['person-server', '\x1b[32m'],
  ['agent', '\x1b[35m'],
  ['board', '\x1b[33m'],
];

for (const [site] of sites) {
  if (!fs.existsSync(path.join(root, site, '.env'))) {
    console.error(`Missing ${site}/.env. Run "npm run keys" first.`);
    process.exit(1);
  }
}

const children = sites.map(([site, color]) => {
  const child = spawn('netlify', ['dev', '--offline'], { cwd: path.join(root, site), env: process.env });
  const prefix = `${color}[${site}]\x1b[0m `;
  const pipe = (stream, target) =>
    stream.on('data', (d) => target.write(d.toString().replace(/^(?=.)/gm, prefix)));
  pipe(child.stdout, process.stdout);
  pipe(child.stderr, process.stderr);
  child.on('exit', (code) => console.log(`${prefix}exited with ${code}`));
  return child;
});

const stop = () => {
  for (const c of children) c.kill('SIGINT');
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
