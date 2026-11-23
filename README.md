# Fabric MCP

Use Fabric from Claude, ChatGPT, Cursor or any MCP client, signed in as yourself.

The Carbon Thread team (Brian, Clelia, editors, designers…) can read their clients' strategy, knowledge and content, and push work back into Fabric: notes, call transcripts, strategy proposals and content drafts. A client contact can connect their own Claude or ChatGPT to their workspace, as in the Skills & AI mockup ("Use Fabric inside their AI"). They see only their own workspace, never Carbon Thread's skill instructions, and what they send comes back into Fabric for the team.

**Everything written from an AI app lands as a note, a draft or a proposal that a person reviews in Fabric. The MCP can never approve, send to a client, schedule, publish or delete.**

Fabric was called ThreadOS until November 2026. Names that existing connections depend on keep the old spelling: the OAuth scopes `threados:read` / `threados:write`, the `THREADOS_*` env vars (still read; `FABRIC_*` is preferred), the `X-ThreadOS-Via` header, the CSRF cookie and the Railway URLs. The two tools that had ThreadOS in their name were renamed (`fabric_whoami`, `share_with_fabric`), and the old names (`threados_whoami`, `share_with_threados`) are still registered, marked deprecated, so saved setups keep working.

## Connecting

The connector URL is `https://<mcp host>/mcp`. The first time, the app opens a Fabric sign-in page. You sign in with your Fabric email and password and choose read-only or read + drafts. After that the app acts as you.

| App | How |
| --- | --- |
| Claude (claude.ai, Desktop, mobile) | Settings › Connectors › Add custom connector › paste the URL. On Team/Enterprise plans, an owner adds it once for the organization. |
| Claude Code | `claude mcp add --transport http fabric https://<mcp host>/mcp`, then `/mcp` to sign in |
| ChatGPT | Settings › Connectors › Advanced › Developer mode › Create, paste the URL, choose OAuth |
| Cursor / VS Code / Windsurf | Add `{"mcpServers": {"fabric": {"url": "https://<mcp host>/mcp"}}}` to the MCP config |
| Apps that only run local (stdio) servers | `npx mcp-remote https://<mcp host>/mcp` |

To disconnect, remove the connector in the app (it revokes the token, and the Fabric session it held is signed out). Deactivating someone in Fabric, or a password reset that ends their sessions, also closes their connections on the next call.

## How access is decided

Three layers decide every tool call, and all three must allow it:

1. **The connection's scope.** `threados:read`, or `threados:read` + `threados:write`. The person picks it on the sign-in page, and it can only narrow what the app asked for.
2. **The person's Fabric role and client assignments.** The MCP holds that person's own Fabric session and calls the Fabric API with it, so the backend's `require_permission` checks and assigned-client restrictions apply exactly as they do in the app. The MCP also reads the role (`/users/me`, refreshed every minute) to hide tools the role can't use. It checks `client_id`s against the person's assignments before calling, too. A role change or a removed assignment applies within a minute.
3. **A fixed list of API calls** (`src/policy.ts`). The MCP can only reach the endpoints on that list. Approve, send, share, schedule, publish, delete, payments, users, roles, settings and direct brief-section edits aren't on it. Even piece review accepts only `submit` (hand a draft to internal review). Episode and piece edits can't touch `stage` or `status`.

Team logins get the team tools; client logins (portal-only permissions) get the portal tools. Nobody gets both.

### What each role gets (default Fabric roles)

| Role | Reads | Writes |
| --- | --- | --- |
| Administrator | everything below | notes, transcripts, strategy proposals, episodes, episode briefs, drafts, quick posts, submit for review |
| Strategist / Account Manager | clients, strategy, knowledge, calls, Brain, shows, episodes, content | same as above (their permissions include strategy:edit, content:create/edit, knowledge:create) |
| Production Lead | assigned clients only | notes, transcripts, episodes, briefs, drafts, quick posts, edits, submit (no strategy proposals: no strategy:edit) |
| Editor | assigned clients only | episodes, briefs, drafts, quick posts, edits, submit (no notes or transcripts: no knowledge:create) |
| Newsletter Team | assigned clients only | episodes, briefs, drafts, quick posts, edits, submit |
| Designer | assigned clients only | edit episode details and drafts, submit for review |
| Developer | everything, read-only | nothing (a read-only role sees no write tools) |
| Client contact | their own workspace: shared strategy, episodes, calendar, what's waiting on them, review history | share an idea/story with Fabric (story bank), comment on an episode brief |

Custom roles work the same way: a tool appears when the role holds the permission it names.

## Tools

Team (each needs the Fabric permission shown):

| Tool | Permission | What it does |
| --- | --- | --- |
| `fabric_whoami` (old name `threados_whoami` still works) | | who you're signed in as, your role, clients, and what the connection can't do |
| `list_clients`, `get_client`, `get_waiting_queue` | client:view | clients, one client, what's waiting on the team and on the client |
| `get_strategy`, `list_strategy_proposals` | strategy:view | the strategy brief, open change sets |
| `search_knowledge`, `get_document`, `list_calls`, `get_call`, `ask_brain` | knowledge:view | library, calls, the Brain |
| `list_shows`, `list_episodes`, `get_episode`, `list_content`, `get_content` | content:view | shows, episodes, pieces |
| `add_knowledge_note`, `add_call_transcript` | knowledge:create | save thinking from the chat or a transcript to the library |
| `propose_strategy_change`, `propose_strategy_from_notes` | strategy:edit | a change set for the brief; someone with strategy:approve accepts it in Fabric |
| `create_episode`, `draft_episode_brief`, `create_content_draft`, `create_quick_posts` | content:create | new episodes, research, drafts |
| `update_episode`, `update_content_draft`, `submit_draft_for_review` | content:edit | edit episode details and drafts (draft status only), hand a draft to internal review |

Client contact: `get_my_workspace`, `get_my_strategy`, `list_my_episodes`, `get_my_calendar`, `get_waiting_on_me`, `get_my_review_history` (portal:view), `share_with_fabric` (old name `share_with_threados` still works), `comment_on_episode` (portal:create).

## Authentication, in detail

This server is its own OAuth 2.1 authorization server, as MCP clients expect: discovery metadata, dynamic client registration, PKCE (S256 only) and RFC 8707 resource indicators. Tokens are issued for `/mcp` only.

- `/authorize` shows the Fabric sign-in page. The form is CSRF-protected (a cookie plus a form field), rate-limited, and shows where it will send you back. The email and password go to Fabric's `/auth/login`, so Fabric's lockout after repeated wrong passwords applies.
- The Fabric access and refresh tokens are stored only encrypted (AES-256-GCM, `TOKEN_ENCRYPTION_KEY`). The AI app never sees them.
- Our own access tokens (1 hour) and refresh tokens (30 days, rotating) are random and stored as SHA-256 hashes. A refresh token or authorization code used twice revokes the whole connection.
- Fabric refresh tokens rotate too, and Fabric signs a person out everywhere if one is reused. So refreshing holds a per-connection lock (a `SELECT … FOR UPDATE` on Postgres, so it works across instances).
- Redirect URIs for self-registered apps must be https, loopback http, or a known editor scheme (`cursor://`, `vscode://`…). `ALLOWED_REDIRECT_HOSTS` can pin https to known hosts.
- Every write is logged as one JSON line (`event: "mcp.write"`) with the person, role, app, client and record. Fabric's own activity log records the same change under the person's name.

## Running it

```bash
npm install
cp .env.example .env    # set FABRIC_API_URL and TOKEN_ENCRYPTION_KEY (openssl rand -hex 32)
npm run dev             # http://localhost:8787/mcp
npm test                # OAuth flow, RBAC per role, policy, token refresh, Postgres store
```

Try it locally with the MCP Inspector: `npx @modelcontextprotocol/inspector`, transport Streamable HTTP, URL `http://localhost:8787/mcp`.

### Deploying (Railway)

Deployed as the `mcp` service in the `thread-os` project, from `main`, in the backend's region:

| Environment | Connector URL | Fabric backend | Store |
| --- | --- | --- | --- |
| production | `https://threados-mcp.up.railway.app/mcp` | backend-production-3174 | the backend's Supabase database |
| development | `https://thrreados-mcp-dev.up.railway.app/mcp` | thread-os-dev-backend | the backend's Supabase dev database |

Variables:

- `PUBLIC_URL`: the service's public https URL (e.g. `https://mcp.thecarbonthread.com`)
- `FABRIC_API_URL`: the backend's URL including `/api` (the old name `THREADOS_API_URL` is still read when this is unset, so the current Railway variables keep working)
- `FABRIC_APP_URL`: `https://app.thecarbonthread.com` (or the old `THREADOS_APP_URL`)
- `DATABASE_URL`: the Fabric database, `${{backend.DATABASE_URL}}`. The server creates five tables in `public`, all named `mcp_*` (Fabric's database role can't create schemas). They have row-level security on with no policies, like every Fabric table, so Supabase's `anon` and `authenticated` roles can't read them. The backend's Alembic env skips `mcp_*` tables, so autogenerate never proposes dropping them. Don't give a backend model an `mcp_` name.
- `TOKEN_ENCRYPTION_KEY`: `openssl rand -hex 32`, kept secret. Changing it disconnects everyone.
- `NODE_ENV=production` (refuses to start without `DATABASE_URL`)

Keep `JWT_IP_CHECK_ENABLED` off on the backend (the default). Calls come from this service, not from the person's browser.

## Not done yet (needs backend changes)

- **Client drafts for review.** Brian's spec has clients drafting in their own AI with "drafts coming back into Fabric for review". The portal API has no endpoint for a client to submit a draft piece, so today a client's AI can share ideas and stories (`/portal/assistant`) and comment on episode briefs, but can't create a draft. A `POST /portal/drafts` that creates a piece in `draft` with `source: "client_ai"`, shown in the team's review queue, would close that gap.
- **"Via Claude" on records.** Writes appear in Fabric under the person's name. The MCP sends `X-ThreadOS-Via: mcp` on every call (the header keeps its pre-rename name, shared with the backend), so the backend could record that in the activity log and show "via Claude" on drafts.
- **A connections screen.** Settings › AI could list a person's connected apps and let them (or an admin) revoke one. Revoking today is done from the AI app, or by deactivating the person.
- **Google sign-in.** Fabric signs in with email and password only today. If it adds Google sign-in, the sign-in page here should offer it too.
