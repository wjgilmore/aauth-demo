// The agent's own (non-AAuth) API used by its web UI.
//
//   POST   /api/tasks                 { message, psUrl? } -> start a task
//   GET    /api/tasks/:id             -> current state
//   POST   /api/tasks/:id/advance     -> run the next steps (polls the PS if waiting)
//   GET    /api/session               -> what the agent remembers about this browser
//   DELETE /api/session               -> forget it (next post starts from scratch)
import { assertServerId, envUrl, json, now, randomId, requestPath } from '../../../shared/aauth.mjs';
import { advance, createTask, forgetSession, getSession, getTask } from '../lib/agent.mjs';

const COOKIE = 'agent_sid';

// Never echo the session id back to the page (the cookie is HttpOnly for a reason).
const view = ({ sid, ...task }) => task;

function readSid(req) {
  const raw = (req.headers.get('cookie') || '').split(/;\s*/).find((c) => c.startsWith(`${COOKIE}=`));
  const sid = raw?.slice(COOKIE.length + 1);
  return sid && /^[A-Za-z0-9_-]{16,64}$/.test(sid) ? sid : null;
}

function sidCookie(sid, maxAge = 86400) {
  const secure = envUrl('AGENT_URL').startsWith('https:') ? '; Secure' : '';
  return `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export default async (req) => {
  const path = requestPath(req);
  const sid = readSid(req);

  if (path === '/api/session') {
    if (req.method === 'DELETE') {
      await forgetSession(sid);
      return json(200, { remembered: false }, { 'Set-Cookie': sidCookie('', 0) });
    }
    const s = await getSession(sid);
    const valid = Boolean(s && s.exp > now());
    return json(200, { remembered: valid, expiresIn: valid ? s.exp - now() : 0 }, { 'cache-control': 'no-store' });
  }

  // /api/tasks, /api/tasks/:id or /api/tasks/:id/advance
  const id = path.split('/')[3];

  if (!id) {
    if (req.method !== 'POST') return json(405, { error: 'method_not_allowed' });
    const body = await req.json().catch(() => ({}));
    const message = String(body.message || '').trim();
    if (!message || message.length > 280) return json(400, { error: 'invalid_request', detail: 'message must be 1-280 characters' });
    const psUrl = String(body.psUrl || envUrl('PS_URL')).replace(/\/+$/, '');
    try {
      assertServerId(psUrl);
    } catch (e) {
      return json(400, { error: 'invalid_request', detail: e.detail || e.message });
    }
    const browserSid = sid || randomId(18);
    const task = await advance(await createTask({ message, psUrl, sid: browserSid }));
    return json(201, view(task), sid ? {} : { 'Set-Cookie': sidCookie(browserSid) });
  }

  const task = await getTask(id);
  if (!task) return json(404, { error: 'not_found' });
  if (req.method === 'POST' && path.endsWith('/advance')) return json(200, view(await advance(task)));
  return json(200, view(task));
};

export const config = { path: ['/api/tasks', '/api/tasks/:id', '/api/tasks/:id/advance', '/api/session'] };
