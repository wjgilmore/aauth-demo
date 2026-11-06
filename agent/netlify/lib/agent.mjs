// The agent's side of AAuth, written as a resumable state machine.
//
// A task is "post this message to the board". Each call to advance() runs steps
// until the task finishes or needs the person (an interaction at their PS). Every
// HTTP exchange is recorded in task.log for the protocol inspector.
import { getStore } from '@netlify/blobs';
import {
  envJwk,
  envUrl,
  fetchMetadata,
  jwkThumbprint,
  now,
  parseRequirement,
  publicJwk,
  randomId,
  signJwt,
  signedFetch,
  verifyJwt,
} from '../../../shared/aauth.mjs';

const store = () => getStore({ name: 'tasks', consistency: 'strong' });
export const getTask = (id) => store().get(id, { type: 'json' });
export const saveTask = (task) => store().setJSON(task.id, task);

// Per-browser memory (keyed by the agent_sid cookie): the person token from your PS.
// It identifies you to the board and is bound to this agent's key, so the agent can
// reuse it until it expires instead of sending you back to your PS every time.
const sessions = () => getStore({ name: 'sessions', consistency: 'strong' });
export const getSession = (sid) => (sid ? sessions().get(sid, { type: 'json' }) : null);
export const forgetSession = (sid) => sid && sessions().delete(sid);

async function rememberPersonToken(task) {
  if (!task.sid) return;
  const { exp } = JSON.parse(Buffer.from(task.tokens.person.split('.')[1], 'base64url'));
  await sessions().setJSON(task.sid, { personToken: task.tokens.person, psUrl: task.psUrl, boardUrl: task.boardUrl, exp });
}

const agentKey = () => envJwk('AGENT_JWK');
const agentUrl = () => envUrl('AGENT_URL');
export const agentSub = () => `aauth:demo-agent@${new URL(agentUrl()).host}`;

/** The agent is its own (self-hosted) agent provider, so it issues its own agent token. */
function mintAgentToken(psUrl) {
  const t = now();
  return signJwt({
    typ: 'aa-agent+jwt',
    jwk: envJwk('AGENT_PROVIDER_JWK'),
    payload: {
      iss: agentUrl(),
      dwk: 'aauth-agent.json',
      sub: agentSub(),
      cnf: { jwk: publicJwk(agentKey()) },
      ps: psUrl,
      jti: randomId(),
      iat: t,
      exp: t + 3600,
    },
  });
}

export async function createTask({ message, psUrl, sid }) {
  const task = {
    id: randomId(18),
    sid,
    message,
    psUrl,
    boardUrl: envUrl('BOARD_URL'),
    status: 'running',
    step: 'call-board',
    tokens: { agent: mintAgentToken(psUrl) },
    log: [],
    createdAt: new Date().toISOString(),
  };
  task.log.push({
    title: 'Agent token minted',
    explain: 'This agent is a self-hosted agent provider. It signs its own agent token, binding its per-agent key (cnf.jwk) to its identity. Every request below is signed with that key.',
    tokens: [task.tokens.agent],
  });

  const saved = await getSession(sid);
  if (saved && saved.psUrl === psUrl && saved.boardUrl === task.boardUrl && saved.exp > now() + 120) {
    task.tokens.person = saved.personToken;
    task.reusedPersonToken = true;
    task.step = 'discover-ps';
    task.log.push({
      title: 'Reuse your person token',
      explain: `Your PS already identified you to the board earlier. That person token is bound to this agent's key and is valid for another ${Math.round((saved.exp - now()) / 60)} minutes, so the agent skips that step.`,
      tokens: [saved.personToken],
    });
  }
  await saveTask(task);
  return task;
}

const RESPONSE_HEADERS = ['aauth-requirement', 'location', 'retry-after', 'signature-error', 'accept-signature-scheme', 'content-type'];

async function exchange(task, title, explain, url, opts) {
  const { response, request } = await signedFetch(url, { jwk: agentKey(), ...opts });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  const headers = Object.fromEntries(RESPONSE_HEADERS.filter((h) => response.headers.has(h)).map((h) => [h, response.headers.get(h)]));
  task.log.push({ title, explain, request, response: { status: response.status, headers, body } });
  return { status: response.status, headers, body, requirement: parseRequirement(headers['aauth-requirement']) };
}

function fail(task, message) {
  task.status = 'failed';
  task.error = message;
  task.log.push({ title: 'Failed', explain: message });
}

/** Explain why the board turned the agent away, using the board's own message when it gives one. */
function boardRefused(task, res) {
  const detail = res.body?.detail;
  if (res.status === 429) return fail(task, `The board is rate limiting posts. ${detail || 'Try again later.'}`);
  fail(task, detail ? `The board refused the post (${res.status}): ${detail}` : `Unexpected board response ${res.status}`);
}

function waitForPerson(task, res, purpose) {
  const r = res.requirement;
  if (res.status !== 202 || r.requirement !== 'interaction') return fail(task, `Expected 202 interaction from the PS, got ${res.status}`);
  const callback = `${agentUrl()}/callback?task=${task.id}`;
  task.pending = {
    purpose,
    location: new URL(res.headers.location, task.psUrl).href,
    code: r.code,
    url: `${r.url}?code=${encodeURIComponent(r.code)}&callback=${encodeURIComponent(callback)}`,
  };
  task.status = 'waiting';
  task.step = 'poll';
}

async function step(task) {
  const board = `${task.boardUrl}/api/posts`;
  const body = { message: task.message };

  switch (task.step) {
    case 'call-board': {
      const res = await exchange(task, 'Try the board with just an agent token', 'The board can verify which agent is calling, but not which person it acts for.', board, {
        method: 'POST',
        body,
        token: task.tokens.agent,
      });
      if (res.status === 401 && res.requirement.requirement === 'person-token') task.step = 'discover-ps';
      else boardRefused(task, res);
      return;
    }

    case 'discover-ps': {
      const meta = await fetchMetadata(task.psUrl, 'aauth-person.json');
      task.ps = { person_token_endpoint: meta.person_token_endpoint, auth_token_endpoint: meta.auth_token_endpoint, name: meta.name };
      task.log.push({
        title: 'Discover the Person Server',
        explain: `Fetched ${task.psUrl}/.well-known/aauth-person.json to find its endpoints.`,
        request: { method: 'GET', url: `${task.psUrl}/.well-known/aauth-person.json` },
        response: { status: 200, body: meta },
      });
      task.step = task.tokens.person ? 'call-board-person' : 'person-token';
      return;
    }

    case 'person-token': {
      const res = await exchange(task, 'Ask the PS for a person token', 'The PS needs the person to sign in and agree before it says who they are.', task.ps.person_token_endpoint, {
        method: 'POST',
        body: { resource: task.boardUrl, capabilities: ['interaction'] },
        token: task.tokens.agent,
      });
      if (res.status === 200 && res.body.person_token) {
        task.tokens.person = res.body.person_token;
        await rememberPersonToken(task);
        task.step = 'call-board-person';
      } else waitForPerson(task, res, 'person');
      return;
    }

    case 'poll': {
      const res = await exchange(task, 'Poll the PS', 'Waiting for the person to respond at their Person Server.', task.pending.location, {
        method: 'GET',
        token: task.tokens.agent,
      });
      if (res.status === 202) {
        task.log.pop(); // don't flood the inspector with identical polls
        task.pendingStatus = res.body?.status;
        return 'wait';
      }
      const purpose = task.pending.purpose;
      task.pending = null;
      task.status = 'running';
      if (res.status === 200 && purpose === 'person' && res.body.person_token) {
        task.tokens.person = res.body.person_token;
        await rememberPersonToken(task);
        task.step = 'call-board-person';
      } else if (res.status === 200 && purpose === 'auth' && res.body.auth_token) {
        task.tokens.auth = res.body.auth_token;
        task.step = 'call-board-auth';
      } else if (res.status === 403) fail(task, 'The person denied the request at their Person Server.');
      else if (res.status === 408) fail(task, 'The request expired before the person responded.');
      else fail(task, `Unexpected polling response ${res.status}`);
      return;
    }

    case 'call-board-person': {
      const res = await exchange(task, 'Retry the board with the person token', 'Now the board knows who the person is (pseudonymously) and which PS speaks for them. It replies with a resource token that describes the access it wants approved.', board, {
        method: 'POST',
        body,
        token: task.tokens.person,
      });
      const rt = res.requirement['resource-token'];
      if (task.reusedPersonToken && res.status === 401 && res.requirement.requirement !== 'auth-token') {
        // The saved token was refused (expired, revoked, keys rotated): start over.
        await forgetSession(task.sid);
        task.reusedPersonToken = false;
        delete task.tokens.person;
        task.log.push({ title: 'Saved person token refused', explain: 'Asking the PS for a fresh one.' });
        task.step = 'person-token';
        return;
      }
      if (res.status !== 401 || res.requirement.requirement !== 'auth-token' || !rt) return boardRefused(task, res);

      // Check the resource token before forwarding it to our PS.
      const { payload } = await verifyJwt(rt, { typ: 'aa-resource+jwt', dwk: 'aauth-resource.json' });
      if (payload.iss !== task.boardUrl) return fail(task, 'Resource token was not issued by the board');
      if (payload.agent_jkt !== jwkThumbprint(agentKey())) return fail(task, 'Resource token is bound to a different agent key');
      if (payload.aud !== task.psUrl) return fail(task, 'Resource token is addressed to a different PS');
      task.tokens.resource = rt;
      task.step = 'auth-token';
      return;
    }

    case 'auth-token': {
      const res = await exchange(task, 'Exchange the resource token at the PS', 'The PS checks that the board signed the resource token and that it matches the person token, then asks the person to approve.', task.ps.auth_token_endpoint, {
        method: 'POST',
        body: {
          resource_token: task.tokens.resource,
          presented_token: task.tokens.person,
          justification: `Post this message to the board: "${task.message}"`,
        },
        token: task.tokens.agent,
      });
      if (res.status === 200 && res.body.auth_token) {
        task.tokens.auth = res.body.auth_token;
        task.log.push({
          title: 'Approved by your standing permission',
          explain: 'You chose "Always allow" for this agent at this board, so your Person Server issued the auth token right away (200 instead of 202). You can revoke that at your PS under Remembered permissions.',
        });
        task.step = 'call-board-auth';
      } else waitForPerson(task, res, 'auth');
      return;
    }

    case 'call-board-auth': {
      const res = await exchange(task, 'Post with the auth token', 'The board verifies the PS signature, that the token is addressed to it, that it grants board.write, and that the request is signed with the key the token is bound to.', board, {
        method: 'POST',
        body,
        token: task.tokens.auth,
      });
      if (res.status === 201) {
        task.status = 'done';
        task.post = res.body.post;
        task.step = 'done';
      } else boardRefused(task, res);
      return;
    }

    default:
      return 'wait';
  }
}

/** Run steps until the task is done, failed, or waiting on the person. */
export async function advance(task) {
  for (let i = 0; i < 10 && ['running', 'waiting'].includes(task.status); i++) {
    try {
      if ((await step(task)) === 'wait' || task.status === 'waiting') break;
    } catch (err) {
      fail(task, err.detail || err.message);
    }
  }
  await saveTask(task);
  return task;
}
