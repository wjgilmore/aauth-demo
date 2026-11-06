#!/usr/bin/env node
// End-to-end check against running sites (local `npm run dev` or deployed URLs).
// Plays the person's part with plain HTTP requests: sign in, review, approve.
//
//   node scripts/e2e.mjs [--ps URL] [--agent URL] [--board URL]

import { decodeJwt, jwkThumbprint } from '../shared/aauth.mjs';

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
const connected = await loginRes.text();
check(loginRes.status === 200 && ada, 'signing in approves the identity request (no extra click)');
check(connected.includes('knows it') && connected.includes('Waiting for its request'), 'PS says what happened and waits for the next request');

task = await browser.advance(task.id);
check(task.status === 'waiting' && task.pending?.purpose === 'auth', 'board issues a resource token; PS needs approval for the post');

// The "knows it's you" page polls this and opens the permission request itself.
const agentJkt = jwkThumbprint(decodeJwt(task.log[0].tokens[0]).payload.cnf.jwk);
const next = await (await fetch(`${PS}/interact/next?resource=${encodeURIComponent(BOARD)}&agent=${encodeURIComponent(agentJkt)}&since=0`, { headers: { cookie: ada } })).json();
check(next.code === task.pending.code, 'PS tab finds the permission request on its own');
const strangerNext = await (await fetch(`${PS}/interact/next?resource=${encodeURIComponent(BOARD)}&agent=${encodeURIComponent(agentJkt)}&since=0`)).json();
check(!strangerNext.code, 'nobody else can see that request');

const consent = await (await visit(ada, task.pending.code)).text();
check(consent.includes('board.write') && consent.includes(message) && consent.includes('Always allow'), 'consent page shows the scope, the message, and "Always allow"');

const { cookie: mallory } = await signIn('Mallory', task.pending.code);
check((await decide(mallory, task.pending.code, 'approve')).status === 403, 'a different person cannot approve it');

const approvedPage = await decide(ada, task.pending.code, 'approve', { remember: '1' });
const approvedText = await approvedPage.text();
check(approvedPage.status === 200 && approvedText.includes('is posting your message') && approvedText.includes('See it on'), 'person approves with "Always allow"; PS says what happens next');
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
const arrival = await visit(ada, task.pending.code);
check(arrival.status === 200 && (await arrival.text()).includes('nothing to confirm'), 'PS approves the identity request on arrival and says why');
task = await browser2.advance(task.id);
check(task.status === 'waiting' && task.pending?.purpose === 'auth', 'post still needs explicit approval');
await decide(ada, task.pending.code, 'deny');

// ---------------------------------------------------------------------------
section('Rate limiting (3 posts per person per minute by default)');
const browser3 = agentBrowser();
task = await browser3.start('rate limit check 1');
const { cookie: grace } = await signIn('Grace', task.pending.code);
task = await browser3.advance(task.id);
await decide(grace, task.pending.code, 'approve', { remember: '1' });
task = await browser3.advance(task.id);
task = task.status === 'done' ? await browser3.start('rate limit check 2') : task;
task = task.status === 'done' ? await browser3.start('rate limit check 3') : task;
check(task.status === 'done', 'three posts in a minute are accepted');
task = await browser3.start('rate limit check 4');
check(task.status === 'failed' && /rate limiting/i.test(task.error), 'the fourth is refused (429)');
const limited = task.log.find((e) => e.response?.status === 429);
check(Boolean(limited?.response.headers['retry-after']) && !titles(task).includes('Approved by your standing permission'), 'refused with Retry-After, before the PS is asked');

// ---------------------------------------------------------------------------
section('Start over');
check((await (await fetch(`${PS}/reset`, { headers: { cookie: grace } })).text()).includes('Start over'), 'PS shows a Start over page');
const reset = await fetch(`${PS}/reset`, { method: 'POST', headers: { cookie: grace } });
check(/Max-Age=0/.test(reset.headers.get('set-cookie') || '') && (await reset.text()).includes('1 remembered permission was revoked'), 'Start over signs out and revokes the session\'s permissions');
check(!(await (await fetch(`${PS}/account`, { headers: { cookie: grace } })).text()).includes('name="key"'), 'no permissions remain');

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
