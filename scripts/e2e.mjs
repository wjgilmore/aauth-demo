#!/usr/bin/env node
// End-to-end check against running sites (local `npm run dev` or deployed URLs).
// Plays the person's part with plain HTTP requests: sign in, review, approve.
//
//   node scripts/e2e.mjs [--ps URL] [--agent URL] [--board URL]

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const PS = args.ps || 'http://localhost:8881';
const AGENT = args.agent || 'http://localhost:8882';
const BOARD = args.board || 'http://localhost:8883';

let failures = 0;
const check = (ok, label) => {
  console.log(`${ok ? '✓' : '✗'} ${label}`);
  if (!ok) failures++;
};
const section = (s) => console.log(`\n${s}`);
const cookieFrom = (res) => res.headers.get('set-cookie')?.split(';')[0];

// --- person at the PS ------------------------------------------------------
async function signIn(name, code) {
  const res = await fetch(`${PS}/interact/login`, { method: 'POST', body: new URLSearchParams({ name, code }), redirect: 'manual' });
  return { res, cookie: cookieFrom(res) };
}
const visit = (cookie, code) => fetch(`${PS}/interact?code=${encodeURIComponent(code)}`, { headers: { cookie }, redirect: 'manual' });
const decide = (cookie, code, decision, extra = {}) =>
  fetch(`${PS}/interact/decision`, { method: 'POST', headers: { cookie }, body: new URLSearchParams({ code, decision, ...extra }), redirect: 'manual' });

// --- browser at the agent --------------------------------------------------
function agentBrowser() {
  let cookie = '';
  return {
    async start(message) {
      const res = await fetch(`${AGENT}/api/tasks`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie },
        body: JSON.stringify({ message }),
      });
      cookie = cookieFrom(res) || cookie;
      return res.json();
    },
    advance: async (id) => (await fetch(`${AGENT}/api/tasks/${id}/advance`, { method: 'POST', headers: { cookie } })).json(),
  };
}
const titles = (task) => task.log.map((e) => e.title);

// ---------------------------------------------------------------------------
section('First post: sign in, approve with "Always allow"');
const browser = agentBrowser();
const message = `e2e check ${new Date().toISOString()}`;
let task = await browser.start(message);
check(task.status === 'waiting' && task.pending?.purpose === 'person', 'agent asks the PS for a person token and waits for the person');
check(!('sid' in task), 'agent never exposes its session id to the page');

const { res: loginRes, cookie: ada } = await signIn('Ada', task.pending.code);
check(loginRes.status === 200 && ada, 'signing in approves the identity request (no extra click)');

task = await browser.advance(task.id);
check(task.status === 'waiting' && task.pending?.purpose === 'auth', 'board issues a resource token; PS needs approval for the post');

const consent = await (await visit(ada, task.pending.code)).text();
check(consent.includes('board.write') && consent.includes(message) && consent.includes('Always allow'), 'consent page shows the scope, the message, and "Always allow"');

const { cookie: mallory } = await signIn('Mallory', task.pending.code);
check((await decide(mallory, task.pending.code, 'approve')).status === 403, 'a different person cannot approve it');

check((await decide(ada, task.pending.code, 'approve', { remember: '1' })).status === 200, 'person approves and ticks "Always allow"');
check((await visit(ada, task.pending.code)).status === 404, 'interaction code is single-use');

task = await browser.advance(task.id);
check(task.status === 'done' && task.post?.name === 'Ada', 'agent posts with the auth token');
const { posts } = await (await fetch(`${BOARD}/api/posts`)).json();
check(posts.some((p) => p.message === message), 'post appears on the board');

// ---------------------------------------------------------------------------
section('Second post from the same browser: no prompts at all');
task = await browser.start(`<b>${message}</b> <img src="x"> (again)`);
check(task.status === 'done', 'task completes in a single request');
check(task.post?.message === `${message} (again)`, 'HTML is stripped before posting');
check(titles(task).includes('Reuse your person token'), 'agent reuses the saved person token');
check(titles(task).includes('Approved by your standing permission'), 'PS issues the auth token directly (200, not 202)');

// ---------------------------------------------------------------------------
section('Revoking the permission');
const account = await (await fetch(`${PS}/account`, { headers: { cookie: ada } })).text();
const key = account.match(/name="key" value="([^"]+)"/)?.[1];
check(Boolean(key), 'remembered permission is listed on the account page');
const revoked = await fetch(`${PS}/account/revoke`, { method: 'POST', headers: { cookie: ada }, body: new URLSearchParams({ key }) });
check((await revoked.text()).includes('Revoked'), 'person revokes it');

task = await browser.start('after revoke');
check(task.status === 'waiting' && task.pending?.purpose === 'auth', 'the next post needs approval again');
await decide(ada, task.pending.code, 'deny');
task = await browser.advance(task.id);
check(task.status === 'failed' && /denied/.test(task.error), 'denial at the PS stops the agent');

// ---------------------------------------------------------------------------
section('New browser, already signed in at the PS');
const browser2 = agentBrowser();
task = await browser2.start('from a second browser');
check(task.status === 'waiting' && task.pending?.purpose === 'person', 'new agent session needs a person token');
check((await visit(ada, task.pending.code)).status === 200, 'PS approves the identity request on arrival (already signed in)');
task = await browser2.advance(task.id);
check(task.status === 'waiting' && task.pending?.purpose === 'auth', 'post still needs explicit approval');
await decide(ada, task.pending.code, 'deny');

// ---------------------------------------------------------------------------
section('Content rules');
for (const [m, label] of [
  ['look at https://example.com/pic.jpg', 'links are refused'],
  ['free porn here', 'explicit terms are refused'],
  ['<img src="https://example.com/x.png">', 'markup-only messages are refused'],
]) {
  const res = await fetch(`${AGENT}/api/tasks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: m }) });
  check(res.status === 400, `${label} (before anyone is asked to approve)`);
}
const csp = (await fetch(`${BOARD}/`)).headers.get('content-security-policy') || '';
check(/img-src 'self'/.test(csp), 'board blocks third-party images with a CSP');

section('Board protection');
const unsigned = await fetch(`${BOARD}/api/posts`, { method: 'POST', body: '{"message":"x"}' });
check(unsigned.status === 401 && unsigned.headers.get('aauth-requirement') === 'requirement=agent-token', 'unsigned writes are refused');

console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
process.exit(failures ? 1 : 0);
