# AAuth Demo: Person Server, Agent, and Message Board

A small, readable, three-site demo of [AAuth](https://github.com/dickhardt/AAuth), the agent authorization protocol. An **agent** wants to post to a **message board** on your behalf. It can only do that after your **Person Server** asks you and you say yes.

| Site | AAuth role | What it does |
|---|---|---|
| `person-server/` | Person Server (PS) | Demo sign-in (display name only). Shows you each agent request and issues person tokens and auth tokens if you approve. |
| `agent/` | Agent + self-hosted agent provider | Takes a message from you and walks the AAuth flow to post it. A **protocol inspector** shows every request and response, with JWTs decoded. |
| `board/` | Resource | A public message board. Accepts writes only with a valid auth token from the author's PS. |

Each folder deploys as its own Netlify site, so the three roles run on three real origins.

**Live demo:** start at the [agent](https://aauth-demo-agent.netlify.app), then watch the [message board](https://aauth-demo-board.netlify.app). Your [Person Server](https://aauth-demo-person-server.netlify.app) handles sign-in and approvals.

Implements a subset of [`draft-hardt-oauth-aauth-protocol-11`](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) (Sept 2026) and [`draft-hardt-httpbis-signature-key-09`](https://datatracker.ietf.org/doc/draft-hardt-httpbis-signature-key/). It uses the three-party "PS authorization" mode.

## The flow

```
Agent                          Board (resource)                 Person Server            You
  │ POST /api/posts  [agent token]  │                                  │                    │
  │────────────────────────────────▶│                                  │                    │
  │ 401 AAuth-Requirement: requirement=person-token                   │                    │
  │◀────────────────────────────────│                                  │                    │
  │ POST /aauth/person {resource}   [agent token]                      │                    │
  │───────────────────────────────────────────────────────────────────▶│                    │
  │ 202 requirement=interaction; url; code   Location: /aauth/pending/…│                    │
  │◀───────────────────────────────────────────────────────────────────│  sign in           │
  │                                 │                                  │◀───────────────────│
  │ GET /aauth/pending/… (poll) → 200 {person_token}                   │                    │
  │ POST /api/posts  [person token] │                                  │                    │
  │────────────────────────────────▶│                                  │                    │
  │ 401 requirement=auth-token; resource-token="…"                    │                    │
  │◀────────────────────────────────│                                  │                    │
  │ POST /aauth/token {resource_token, presented_token}  [agent token] │                    │
  │───────────────────────────────────────────────────────────────────▶│ review scope +     │
  │ 202 interaction … poll → 200 {auth_token}                          │ message, "Allow"   │
  │   (or 200 {auth_token} right away if you chose "Always allow")     │                    │
  │ POST /api/posts  [auth token]   │                                  │◀───────────────────│
  │────────────────────────────────▶│                                  │                    │
  │ 201 Created                     │                                  │                    │
```

The token in `[brackets]` is carried in the `Signature-Key` header (`sig=jwt;jwt="…"`). Each request is signed with RFC 9421 HTTP Message Signatures, using the agent key that token is bound to (`cnf.jwk`).

### Why there are two PS steps

The **person token** only *identifies* you to the board: a pseudonymous ID, unique to that board, plus which PS speaks for you. The spec says it can't carry a scope. The **auth token** is the actual *permission*, for the scope the board asked for in its resource token. The PS can't know that scope until the board has seen the person token, so the two steps can't be merged.

What the demo PS does, to keep that from feeling repetitive:

| Situation | Identity (person token) | Permission (auth token) |
|---|---|---|
| First post | Signing in *is* the consent, so there's no extra click | You review the scope and the message, then click Allow |
| Already signed in at the PS | Approved on arrival; you bounce straight back | Asked, unless you chose "Always allow" |
| Same browser again | The agent reuses its saved person token (valid up to an hour), so no trip to the PS | Issued immediately (200) if "Always allow" is on |

You can see and revoke "Always allow" grants at `/account` on the PS. The agent's **Forget me** link discards its saved person token.

What each party checks:

- **Board** discovers the token issuer via `{iss}/.well-known/{dwk}` and its JWKS, then verifies the JWT and the HTTP signature with `cnf.jwk`. It also checks `aud`, `typ`, and `scope`.
- **PS** verifies the agent token against the agent provider's metadata. It verifies the board's resource token and checks that `agent_jkt`, `sub`, and `presented_jti` match the person token it issued. Only the same person can approve the auth request.
- **Agent** verifies the resource token before forwarding it to its PS.

## Run it locally

Requires Node 20+ and the [Netlify CLI](https://docs.netlify.com/cli/get-started/) (`npm i -g netlify-cli`).

```bash
npm install
npm run keys     # generates Ed25519 keys + person-server/.env, agent/.env, board/.env
npm run dev      # Person Server :8881, Agent :8882, Board :8883
```

Open http://localhost:8882, type a message, and follow the prompts.

```bash
npm test                  # unit tests for the JWT / HTTP-signature layer
node scripts/e2e.mjs      # plays the person over HTTP and checks the whole flow (needs `npm run dev`)
```

## Deploy to Netlify

1. Push this repo to GitHub.
2. In Netlify, create **three sites** from the same repo, one for each folder. For each site, set **Base directory** to `person-server`, `agent`, or `board`. Each folder's `netlify.toml` handles the rest.
3. Note the three site URLs, then generate production keys and environment files:

   ```bash
   npm run keys -- --ps https://YOUR-PS.netlify.app \
                   --agent https://YOUR-AGENT.netlify.app \
                   --board https://YOUR-BOARD.netlify.app --out deploy
   ```

4. Import each file into its site. You can also paste the values in the Netlify UI under Site configuration → Environment variables.

   ```bash
   (cd person-server && netlify link && netlify env:import ../deploy/person-server.env)
   (cd agent && netlify link && netlify env:import ../deploy/agent.env)
   (cd board && netlify link && netlify env:import ../deploy/board.env)
   ```

5. Redeploy all three sites, then check the deployment:

   ```bash
   node scripts/e2e.mjs --ps https://YOUR-PS.netlify.app --agent https://YOUR-AGENT.netlify.app --board https://YOUR-BOARD.netlify.app
   ```

`deploy/` and `.env` files contain private keys and are git-ignored. Storage uses [Netlify Blobs](https://docs.netlify.com/blobs/overview/), so no database setup is needed.

## Layout

```
shared/aauth.mjs           JWTs, RFC 9421 signing/verification, discovery. Node built-ins only.
shared/style.css           Styles; `npm run sync-css` copies them into each site's public/
person-server/netlify/     metadata, person_token + auth_token endpoints, polling, consent UI
agent/netlify/lib/agent.mjs  the agent's AAuth state machine (read this first)
board/netlify/functions/   resource metadata and the protected /api/posts
scripts/                   key generation, local dev runner, e2e check
```

## Simplifications (it's a demo)

- **Sign-in is a display name in a signed cookie.** There is no real authentication. Anyone can claim any name, and the board says which PS vouched for each post.
- **Ed25519 only.** The spec also asks for ES256 support.
- **The agent is self-hosted** and is its own agent provider. One agent key is shared by all visitors. A real agent would hold a key per user or per instance.
- **Remembered consent is per PS session.** A grant belongs to the session you signed in with, so signing out and back in makes you a "new person", with a new pairwise ID and no grants. There's no support for missions, token revocation, or AS (four-party) mode. Revoking a grant stops new tokens, but already-issued auth tokens stay valid until they expire (an hour at most).
- **Identity approval happens on a GET** when you're already signed in. That's convenient for a demo; a production PS would want a click or a stronger link to the agent's request.
- **The board accepts any PS.** This is intentional: AAuth resources trust the issuer of the token, not a fixed list.
- **No replay cache.** It relies on the 60-second signature window, which the spec makes optional.
- **The abuse limits are basic:** 280 characters, the newest 100 posts, and expiry after 24 hours. Add rate limiting before you promote a public deployment widely.
- **`netlify dev` quirk:** when a function returns 403 or 404, `netlify dev` re-invokes it with `.html` or `/index.html` appended. `cleanPath()` in `shared/aauth.mjs` undoes that, but only under `NETLIFY_DEV`.

AAuth is a moving draft that is migrating to the OpenID Foundation, so field names may change between versions.

## License

MIT
