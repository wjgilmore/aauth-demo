// The person-facing side of the PS: the interaction URL from AAuth-Requirement.
//
//   GET  /interact?code=XXXX-XXXX[&callback=...]   review a pending request
//   POST /interact/login                          demo sign-in (display name only)
//   POST /interact/decision                       approve or deny
//   GET  /account, POST /account/revoke           remembered permissions
//   GET  /reset, POST /reset                     start over: sign out and forget permissions
//   GET  /logout
//
// PS policy in this demo:
//   * Person-token requests (identify you to a resource) are approved by signing in.
//     If you're already signed in, they're approved without another click.
//   * Auth-token requests (permission to act) always need an explicit "Allow",
//     unless you previously ticked "Always allow" for that agent and resource.
import { now, requestPath } from '../../../shared/aauth.mjs';
import { cleanName } from '../../../shared/content.mjs';
import {
  clearCookie,
  consumeCode,
  esc,
  html,
  listGrants,
  mintAuthToken,
  mintPersonToken,
  newSession,
  pairwiseSub,
  pendingByCode,
  readSession,
  revokeAllGrants,
  revokeGrant,
  saveGrant,
  savePending,
} from '../lib/ps.mjs';

const redirect = (location, headers = {}) => new Response(null, { status: 303, headers: { Location: location, ...headers } });

/** Only redirect back to the callback endpoint the agent provider published in its metadata. */
function safeCallback(pending, callback) {
  if (!callback || !pending?.agent.callbackEndpoint) return null;
  try {
    const u = new URL(callback);
    const allowed = new URL(pending.agent.callbackEndpoint);
    return u.origin === allowed.origin && u.pathname === allowed.pathname ? u.href : null;
  } catch {
    return null;
  }
}

const interactUrl = (code, callback) =>
  `/interact?code=${encodeURIComponent(code)}${callback ? `&callback=${encodeURIComponent(callback)}` : ''}`;

const isLive = (p) => p && p.status === 'pending' && p.expiresAt > now();

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

function codeForm(message = '') {
  return `<section class="card">
    <h2>Enter a code</h2>
    ${message ? `<p class="error">${esc(message)}</p>` : '<p>If an agent showed you a code, enter it here to review what it\'s asking for.</p>'}
    <form method="get" action="/interact" class="inline">
      <input name="code" placeholder="XXXX-XXXX" autocomplete="off" required>
      <button>Continue</button>
    </form>
  </section>`;
}

function hidden(p, callback) {
  return `<input type="hidden" name="code" value="${esc(p.code)}">
      <input type="hidden" name="callback" value="${esc(callback || '')}">`;
}

function loginForm(p, callback) {
  const intro =
    p.kind === 'person'
      ? `<h2>Let ${esc(p.agent.name)} identify you to ${esc(p.resourceName)}</h2>
    <p>Signing in lets your Person Server give <strong>${esc(p.resourceName)}</strong> a pseudonymous ID for you, unique to that site. It doesn't share your name, and it doesn't let the agent <em>do</em> anything. You'll be asked separately before it acts.</p>`
      : `<h2>Sign in to your Person Server</h2>
    <p>${esc(p.agent.name)} is waiting for your approval at ${esc(p.resourceName)}.</p>`;
  return `<section class="card">
    ${intro}
    <p class="code">Code <strong>${esc(p.code)}</strong>. Check that it matches what the agent showed you.</p>
    <form method="post" action="/interact/login">
      ${hidden(p, callback)}
      <label>Display name <input name="name" maxlength="40" required autofocus placeholder="e.g. Ada" autocomplete="off" data-1p-ignore data-lpignore="true"></label>
      <p class="muted">This is a demo, so there's no password. The name is stored only in a cookie on this site.</p>
      <div class="actions">
        <button formaction="/interact/decision" formnovalidate name="decision" value="deny" class="secondary">Cancel</button>
        <button>${p.kind === 'person' ? 'Sign in and continue' : 'Sign in'}</button>
      </div>
    </form>
    ${agentDetails(p)}
  </section>`;
}

function agentDetails(p) {
  return `<details class="tech"><summary>Technical details</summary>
    <dl>
      <dt>Request</dt><dd>${p.kind === 'person' ? 'person token (identity only)' : 'auth token (permission)'}</dd>
      <dt>Agent</dt><dd><code>${esc(p.agent.sub)}</code></dd>
      <dt>Agent provider</dt><dd><code>${esc(p.agent.iss)}</code></dd>
      <dt>Agent key thumbprint</dt><dd><code>${esc(p.agent.jkt)}</code></dd>
      <dt>Resource</dt><dd><code>${esc(p.resource)}</code></dd>
      ${p.scope ? `<dt>Scope</dt><dd><code>${esc(p.scope)}</code></dd>` : ''}
    </dl>
  </details>`;
}

function scopeList(scope, descriptions, name) {
  return scope
    .split(' ')
    .filter(Boolean)
    .map((s) => {
      const desc = s === 'profile' ? `Share your display name (<strong>${esc(name)}</strong>)` : esc(descriptions?.[s] || s);
      return `<li>${desc} <code>${esc(s)}</code></li>`;
    })
    .join('');
}

function consent(p, session, callback) {
  const blocked = pairwiseSub(session.uid, p.resource) !== p.sub;
  return `<section class="card consent">
    <p class="muted">Signed in as <strong>${esc(session.name)}</strong> · <a href="/logout">Not you?</a></p>
    <h2>Approve an action</h2>
    <p class="code">Code <strong>${esc(p.code)}</strong>. Check that it matches what the agent showed you.</p>
    <p><strong>${esc(p.agent.name)}</strong> is asking for permission at <strong>${esc(p.resourceName)}</strong> to:</p>
    <ul class="scopes">${scopeList(p.scope, p.scopeDescriptions, session.name)}</ul>
    ${p.justification ? `<p class="muted">The agent says:</p><blockquote>${esc(p.justification)}</blockquote>` : ''}
    ${blocked ? '<p class="error">This request was started for a different person. Only they can approve it.</p>' : ''}
    <form method="post" action="/interact/decision">
      ${hidden(p, callback)}
      ${
        blocked
          ? ''
          : `<label class="check"><input type="checkbox" name="remember" value="1">
        Always allow ${esc(p.agent.name)} to do this at ${esc(p.resourceName)}. You can revoke it under <a href="/account" target="_blank">Remembered permissions</a>.</label>`
      }
      <div class="actions">
        <button name="decision" value="deny" class="secondary">Deny</button>
        ${blocked ? '' : '<button name="decision" value="approve">Allow</button>'}
      </div>
    </form>
    ${agentDetails(p)}
  </section>`;
}

function donePage(p, approved, { autoSession } = {}) {
  const why = autoSession
    ? `<p>You're signed in as <strong>${esc(autoSession.name)}</strong>, so your Person Server confirmed it's you to <strong>${esc(p.resourceName)}</strong> without asking again.</p>
      <p class="muted">Not you, or want to go through the whole flow again? <a href="/reset">Start over</a></p>`
    : '';
  return html(
    200,
    `<section class="card"><h2>${approved ? 'Done' : 'Cancelled'}</h2>
      ${why}
      <p>You can close this tab and return to <strong>${esc(p.agent.name)}</strong>. It will notice within a few seconds.</p></section>`,
  );
}

function resetPage(session) {
  if (!session) {
    return html(
      200,
      `<section class="card"><h2>Start over</h2>
        <p>You're signed out, and this Person Server isn't remembering anything for you. The next time an agent asks, you'll sign in and approve again.</p></section>`,
    );
  }
  return html(
    200,
    `<section class="card"><h2>Start over</h2>
      <p>You're signed in as <strong>${esc(session.name)}</strong>. Starting over will:</p>
      <ul>
        <li>sign you out of this Person Server, and</li>
        <li>revoke every "Always allow" permission you gave in this session.</li>
      </ul>
      <p>The next time an agent asks, you'll enter your name and approve again.</p>
      <form method="post" action="/reset" class="actions"><a class="button secondary" href="/account">See permissions first</a><button>Start over</button></form>
    </section>`,
  );
}

async function accountPage(session, message = '') {
  const grants = await listGrants(session.uid);
  const rows = grants.length
    ? grants
        .map(
          (g) => `<li class="card">
        <p><strong>${esc(g.agentName)}</strong> at <strong>${esc(g.resourceName)}</strong></p>
        <ul class="scopes">${scopeList(g.scope, g.scopeDescriptions, g.name)}</ul>
        <p class="muted">Allowed ${esc(new Date(g.createdAt * 1000).toLocaleString('en-US', { timeZone: 'UTC' }))} UTC</p>
        <form method="post" action="/account/revoke"><input type="hidden" name="key" value="${esc(g.key)}"><button class="secondary">Revoke</button></form>
      </li>`,
        )
        .join('')
    : '<li class="muted">Nothing yet. When you tick "Always allow" on an approval, it shows up here.</li>';
  return html(
    200,
    `<section>
      <p class="muted">Signed in as <strong>${esc(session.name)}</strong> · <a href="/logout">Sign out</a></p>
      <h2>Remembered permissions</h2>
      ${message ? `<p class="success">${esc(message)}</p>` : ''}
      <p>Agents listed here can get an auth token from this Person Server without asking you. Revoking stops new tokens immediately. A token that was already issued stays valid until it expires (at most an hour).</p>
      <ul class="grants">${rows}</ul>
    </section>`,
  );
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

async function decide(p, session, approve, { remember = false } = {}) {
  if (approve) {
    const minted = p.kind === 'person' ? mintPersonToken(p, session) : mintAuthToken(p, session);
    if (remember && p.kind === 'auth') await saveGrant(p, session);
    await savePending({
      ...p,
      status: 'approved',
      decidedAt: now(),
      result: { field: minted.field, token: minted.token, exp: now() + minted.expiresIn },
    });
  } else {
    await savePending({ ...p, status: 'denied', decidedAt: now() });
  }
  await consumeCode(p.code); // codes are single-use
}

/** After a decision, send the person back to the agent (or show a done page). */
function finish(p, approved, callbackParam, headers = {}, pageOpts = {}) {
  const callback = safeCallback(p, callbackParam);
  if (callback) return redirect(callback, headers);
  const res = donePage(p, approved, pageOpts);
  for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
  return res;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export default async (req) => {
  const url = new URL(req.url);
  const path = requestPath(req);

  if (path === '/logout') return redirect('/', { 'Set-Cookie': clearCookie() });

  if (path === '/reset') {
    const session = readSession(req);
    if (req.method !== 'POST') return resetPage(session);
    const revoked = session ? await revokeAllGrants(session.uid) : 0;
    return html(
      200,
      `<section class="card"><h2>All clear</h2>
        <p>You're signed out${revoked ? ` and ${revoked} remembered permission${revoked === 1 ? ' was' : 's were'} revoked` : ''}. The next time an agent asks, you'll enter your name and approve again.</p>
        <p class="muted">You can close this tab.</p></section>`,
      { 'Set-Cookie': clearCookie() },
    );
  }

  if (path === '/account') {
    const session = readSession(req);
    if (!session) return html(200, '<section class="card"><h2>Remembered permissions</h2><p>You\'re not signed in. Permissions are tied to the session you signed in with.</p></section>');
    if (req.method === 'GET') return accountPage(session);
  }

  if (req.method === 'GET' && path === '/interact') {
    const code = url.searchParams.get('code');
    if (!code) return html(200, codeForm());
    const p = await pendingByCode(code);
    if (!isLive(p)) return html(404, codeForm('That code is unknown, already used, or expired.'));
    const callback = url.searchParams.get('callback');
    const session = readSession(req);
    if (!session) return html(200, loginForm(p, safeCallback(p, callback)));

    // Already signed in: identifying you to a resource needs no further click.
    if (p.kind === 'person') {
      await decide(p, session, true);
      return finish(p, true, callback, {}, { autoSession: session });
    }
    if (!p.viewed) await savePending({ ...p, viewed: true });
    return html(200, consent(p, session, safeCallback(p, callback)));
  }

  if (req.method !== 'POST') return new Response('Not found', { status: 404 });
  const form = await req.formData();

  if (path === '/account/revoke') {
    const session = readSession(req);
    if (!session) return redirect('/account');
    const ok = await revokeGrant(session.uid, String(form.get('key') || ''));
    return accountPage(session, ok ? 'Revoked. The agent will have to ask you next time.' : '');
  }

  const code = String(form.get('code') || '');
  const callbackParam = String(form.get('callback') || '');
  const p = await pendingByCode(code);
  if (!isLive(p)) return html(404, codeForm('That code is unknown, already used, or expired.'));

  if (path === '/interact/login') {
    if (!String(form.get('name') || '').trim()) return redirect(interactUrl(code, callbackParam));
    const name = cleanName(form.get('name')); // plain text; links or explicit terms become "Anonymous"
    const { session, cookie } = newSession(name);
    // For an identity request, signing in *is* the consent (the page said so).
    if (p.kind === 'person') {
      await decide(p, session, true);
      return finish(p, true, callbackParam, { 'Set-Cookie': cookie });
    }
    return redirect(interactUrl(code, callbackParam), { 'Set-Cookie': cookie });
  }

  if (path === '/interact/decision') {
    const approve = form.get('decision') === 'approve';
    const session = readSession(req);
    if (!approve) {
      await decide(p, session, false); // anyone holding the code may cancel
      return finish(p, false, callbackParam);
    }
    if (!session) return redirect(interactUrl(code, callbackParam));
    if (p.kind === 'auth' && pairwiseSub(session.uid, p.resource) !== p.sub) {
      return html(403, consent(p, session, safeCallback(p, callbackParam)));
    }
    await decide(p, session, true, { remember: form.get('remember') === '1' });
    return finish(p, true, callbackParam);
  }

  return new Response('Not found', { status: 404 });
};

export const config = { path: ['/interact', '/interact/login', '/interact/decision', '/account', '/account/revoke', '/reset', '/logout'] };
