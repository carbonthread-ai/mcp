import { createHash, randomBytes } from "node:crypto";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createApp } from "../src/server.js";
import { MemoryStore } from "../src/store/memory.js";
import { assertCallAllowed, PolicyError, SCOPE_READ, SCOPE_WRITE } from "../src/policy.js";
import { CLIENT_A, CLIENT_B, PIECE_APPROVED, PIECE_B, PIECE_DRAFT, startFakeThreadOS, type FakeThreadOS } from "./fake-threados.js";

const PUBLIC = "http://localhost:8787";
const MCP = `${PUBLIC}/mcp`;
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

let fake: FakeThreadOS;
let app: ReturnType<typeof createApp>["app"];

beforeAll(async () => {
  fake = await startFakeThreadOS();
  const config = loadConfig({
    PUBLIC_URL: PUBLIC, THREADOS_API_URL: fake.url, THREADOS_APP_URL: "https://app.threados.test",
    TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("hex"), TRUST_PROXY: "false", RATE_LIMITS: "off",
  } as NodeJS.ProcessEnv);
  app = createApp(config, new MemoryStore()).app;
});
afterAll(async () => fake.close());
beforeEach(() => { fake.calls.length = 0; });

const b64url = (b: Buffer) => b.toString("base64url");

async function register() {
  const res = await request(app).post("/register").send({ client_name: "Claude", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" });
  expect(res.status).toBe(201);
  return res.body.client_id as string;
}

/** The whole OAuth flow a connector runs: register, /authorize, sign in on our page, exchange the code. */
async function connect(email: string, password: string, opts: { write?: boolean; scope?: string } = {}) {
  const clientId = await register();
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const page = await request(app).get("/authorize").query({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "S256",
    state: "xyz", resource: MCP, ...(opts.scope ? { scope: opts.scope } : {}),
  });
  expect(page.status).toBe(200);
  const pending = /name="pending" value="([^"]+)"/.exec(page.text)![1]!;
  const csrf = /name="csrf" value="([^"]+)"/.exec(page.text)![1]!;
  const cookie = page.headers["set-cookie"]![0]!.split(";")[0]!;
  const form: Record<string, string> = { pending, csrf, email, password, decision: "allow" };
  if (opts.write !== false) form.write = "1";
  const signIn = await request(app).post("/oauth/sign-in").set("Cookie", cookie).type("form").send(form);
  if (signIn.status !== 302) return { status: signIn.status, text: signIn.text };
  const location = new URL(signIn.headers.location!);
  expect(location.origin + location.pathname).toBe(REDIRECT);
  expect(location.searchParams.get("state")).toBe("xyz");
  const token = await request(app).post("/token").type("form").send({
    grant_type: "authorization_code", code: location.searchParams.get("code")!, code_verifier: verifier, client_id: clientId, redirect_uri: REDIRECT, resource: MCP,
  });
  expect(token.status).toBe(200);
  return { status: 302, clientId, code: location.searchParams.get("code")!, verifier, ...token.body } as any;
}

let rpcId = 1;
async function rpc(token: string, method: string, params: unknown = {}) {
  const res = await request(app).post("/mcp").set("Authorization", `Bearer ${token}`)
    .set("Accept", "application/json, text/event-stream").send({ jsonrpc: "2.0", id: rpcId++, method, params });
  return res;
}
async function tools(token: string): Promise<string[]> {
  const res = await rpc(token, "tools/list");
  expect(res.status).toBe(200);
  return res.body.result.tools.map((t: any) => t.name);
}
async function call(token: string, name: string, args: Record<string, unknown> = {}) {
  const res = await rpc(token, "tools/call", { name, arguments: args });
  expect(res.status).toBe(200);
  const result = res.body.result;
  return { isError: Boolean(result.isError), text: result.content[0].text as string };
}
const hit = (method: string, path: string) => fake.calls.some((c) => c.method === method && c.path === path);

describe("OAuth", () => {
  it("publishes discovery metadata for connectors", async () => {
    const as = await request(app).get("/.well-known/oauth-authorization-server");
    expect(as.body.registration_endpoint).toBe(`${PUBLIC}/register`);
    expect(as.body.code_challenge_methods_supported).toContain("S256");
    expect(as.body.scopes_supported).toEqual([SCOPE_READ, SCOPE_WRITE]);
    const prm = await request(app).get("/.well-known/oauth-protected-resource/mcp");
    expect(prm.body.resource).toBe(MCP);
  });

  it("asks for a token, with the resource metadata, when none is sent", async () => {
    const res = await request(app).post("/mcp").send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toContain("resource_metadata=");
  });

  it("refuses redirect URIs that aren't https, loopback or a known app scheme", async () => {
    const res = await request(app).post("/register").send({ client_name: "Evil", redirect_uris: ["http://evil.example/cb"] });
    expect(res.status).toBe(400);
    const ok = await request(app).post("/register").send({ client_name: "Cursor", redirect_uris: ["cursor://anysphere.cursor-retrieval/oauth/callback"], token_endpoint_auth_method: "none" });
    expect(ok.status).toBe(201);
  });

  it("shows the sign-in again on a wrong password, without issuing anything", async () => {
    const res = await connect("brian@thecarbonthread.com", "wrong");
    expect(res.status).toBe(401);
    expect(res.text).toContain("don&#39;t match a ThreadOS account");
  });

  it("rejects a sign-in form without the browser's CSRF cookie", async () => {
    const clientId = await register();
    const page = await request(app).get("/authorize").query({
      response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: "x".repeat(43), code_challenge_method: "S256",
    });
    const pending = /name="pending" value="([^"]+)"/.exec(page.text)![1]!;
    const csrf = /name="csrf" value="([^"]+)"/.exec(page.text)![1]!;
    const res = await request(app).post("/oauth/sign-in").type("form").send({ pending, csrf, email: "brian@thecarbonthread.com", password: "pw-admin", decision: "allow" });
    expect(res.status).toBe(400);
    expect(fake.calls.some((c) => c.path === "/api/auth/login")).toBe(false);
  });

  it("refuses a code used twice and revokes what it produced", async () => {
    const conn = await connect("brian@thecarbonthread.com", "pw-admin");
    const again = await request(app).post("/token").type("form").send({
      grant_type: "authorization_code", code: conn.code, code_verifier: conn.verifier, client_id: conn.clientId, redirect_uri: REDIRECT,
    });
    expect(again.status).toBe(400);
    expect((await rpc(conn.access_token, "tools/list")).status).toBe(401);
  });

  it("rotates refresh tokens and closes the connection when one is reused", async () => {
    const conn = await connect("brian@thecarbonthread.com", "pw-admin");
    const first = await request(app).post("/token").type("form").send({ grant_type: "refresh_token", refresh_token: conn.refresh_token, client_id: conn.clientId });
    expect(first.status).toBe(200);
    expect((await rpc(first.body.access_token, "tools/list")).status).toBe(200);
    const replay = await request(app).post("/token").type("form").send({ grant_type: "refresh_token", refresh_token: conn.refresh_token, client_id: conn.clientId });
    expect(replay.status).toBe(400);
    expect((await rpc(first.body.access_token, "tools/list")).status).toBe(401);
  });

  it("disconnects on revoke and signs the ThreadOS session out", async () => {
    const conn = await connect("brian@thecarbonthread.com", "pw-admin");
    const res = await request(app).post("/revoke").type("form").send({ token: conn.access_token, client_id: conn.clientId });
    expect(res.status).toBe(200);
    expect(hit("POST", "/api/auth/logout")).toBe(true);
    expect((await rpc(conn.access_token, "tools/list")).status).toBe(401);
  });
});

describe("RBAC: tools follow the person's ThreadOS role", () => {
  it("administrator: every team tool, no portal tools", async () => {
    const { access_token } = await connect("brian@thecarbonthread.com", "pw-admin");
    const names = await tools(access_token);
    expect(names).toEqual(expect.arrayContaining(["list_clients", "get_strategy", "propose_strategy_change", "create_content_draft", "submit_draft_for_review"]));
    expect(names).not.toContain("share_with_threados");
  });

  it("no tool approves, sends, publishes or deletes, for anyone", async () => {
    for (const [email, pw] of [["brian@thecarbonthread.com", "pw-admin"], ["quincy@client.com", "pw-client"]]) {
      const { access_token } = await connect(email!, pw!);
      const names = await tools(access_token);
      expect(names.filter((n) => /approve|publish|send_to|schedule|delete|remove|invite|payment|setting|role/.test(n))).toEqual([]);
    }
  });

  it("editor: no strategy proposals (no strategy:edit), only assigned clients", async () => {
    const { access_token } = await connect("editor@thecarbonthread.com", "pw-editor");
    const names = await tools(access_token);
    expect(names).toContain("create_content_draft");
    expect(names).not.toContain("propose_strategy_change");
    const clients = await call(access_token, "list_clients");
    expect(clients.text).toContain(CLIENT_A);
    expect(clients.text).not.toContain(CLIENT_B);
    const other = await call(access_token, "list_content", { client_id: CLIENT_B });
    expect(other.isError).toBe(true);
    expect(other.text).toContain("do not have access to this client");
    expect(hit("GET", `/api/clients/${CLIENT_B}/pieces`)).toBe(false);
    // An id that belongs to another client is caught after reading it, before any change
    const edit = await call(access_token, "update_content_draft", { piece_id: PIECE_B, body: "x" });
    expect(edit.isError).toBe(true);
    expect(hit("PATCH", `/api/pieces/${PIECE_B}`)).toBe(false);
  });

  it("developer: read-only role sees no write tools even with the write scope", async () => {
    const { access_token } = await connect("dev@e2m.solutions", "pw-dev");
    const names = await tools(access_token);
    expect(names).toContain("list_content");
    expect(names.some((n) => /^(create|update|add|propose|submit|draft)_/.test(n))).toBe(false);
  });

  it("a read-only connection hides writes for an administrator too", async () => {
    const { access_token } = await connect("brian@thecarbonthread.com", "pw-admin", { write: false });
    const names = await tools(access_token);
    expect(names).toContain("get_strategy");
    expect(names).not.toContain("create_content_draft");
  });

  it("a client contact gets only their own portal, never team tools", async () => {
    const { access_token } = await connect("quincy@client.com", "pw-client");
    const names = await tools(access_token);
    expect(names).toEqual(expect.arrayContaining(["get_my_workspace", "get_my_strategy", "share_with_threados", "get_waiting_on_me"]));
    expect(names).not.toContain("list_clients");
    expect(names).not.toContain("get_strategy");
    const shared = await call(access_token, "share_with_threados", { text: "We doubled retention by calling every churned user." });
    expect(shared.isError).toBe(false);
    const other = await call(access_token, "get_my_workspace", { client_id: CLIENT_B });
    expect(other.isError).toBe(true);
  });

  it("an account deactivated in ThreadOS loses the connection on its next call", async () => {
    const { access_token } = await connect("editor@thecarbonthread.com", "pw-editor");
    const editor = fake.users.find((u) => u.email === "editor@thecarbonthread.com")!;
    editor.active = false;
    try {
      expect((await rpc(access_token, "tools/list")).status).toBe(401);
      editor.active = true;
      // Closed for good: reactivating the account needs a new connection
      expect((await rpc(access_token, "tools/list")).status).toBe(401);
    } finally {
      editor.active = true;
    }
  });
});

describe("Writes land as drafts and proposals", () => {
  it("proposes a strategy change instead of editing the brief", async () => {
    const { access_token } = await connect("brian@thecarbonthread.com", "pw-admin");
    const res = await call(access_token, "propose_strategy_change", { client_id: CLIENT_A, instruction: "Tighten the ICP to founders of 10-50 person firms" });
    expect(res.isError).toBe(false);
    expect(res.text).toContain("Proposed for review");
    expect(hit("POST", `/api/clients/${CLIENT_A}/brief/instructions`)).toBe(true);
    expect(hit("POST", `/api/clients/${CLIENT_A}/brief/approve`)).toBe(false);
  });

  it("creates a draft, edits it, and hands it to internal review, never approving it", async () => {
    const { access_token } = await connect("editor@thecarbonthread.com", "pw-editor");
    const created = await call(access_token, "create_content_draft", { client_id: CLIENT_A, channel: "linkedin", title: "From Claude", body: "Hello" });
    expect(created.isError).toBe(false);
    const edited = await call(access_token, "update_content_draft", { piece_id: PIECE_DRAFT, body: "v2" });
    expect(edited.isError).toBe(false);
    expect(fake.pieces.get(PIECE_DRAFT).body).toBe("v2");
    const submitted = await call(access_token, "submit_draft_for_review", { piece_id: PIECE_DRAFT });
    expect(submitted.isError).toBe(false);
    expect(fake.pieces.get(PIECE_DRAFT).status).toBe("internal_review");
    expect(fake.calls.filter((c) => c.path.endsWith("/review")).map((c: any) => c.body.action)).toEqual(["submit"]);
  });

  it("won't edit a piece that's already approved", async () => {
    const { access_token } = await connect("brian@thecarbonthread.com", "pw-admin");
    const res = await call(access_token, "update_content_draft", { piece_id: PIECE_APPROVED, body: "sneaky" });
    expect(res.isError).toBe(true);
    expect(fake.pieces.get(PIECE_APPROVED).body).toBe("final");
  });
});

describe("Policy: the fixed list of ThreadOS calls", () => {
  const all = [SCOPE_READ, SCOPE_WRITE];
  it.each([
    ["POST", `/clients/${CLIENT_A}/brief/approve`],
    ["POST", `/clients/${CLIENT_A}/brief/send`],
    ["PUT", "/brief/sections/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
    ["DELETE", `/pieces/${PIECE_DRAFT}`],
    ["POST", `/portal/approvals/piece/${PIECE_DRAFT}`],
    ["POST", `/proposals/${PIECE_DRAFT}/send`],
    ["PUT", "/settings/brief_template"],
    ["POST", "/users/invite"],
    ["GET", "/settings"],
  ])("blocks %s %s", (method, path) => {
    expect(() => assertCallAllowed(method, path, {}, all)).toThrow(PolicyError);
  });

  it("allows only 'submit' on review", () => {
    expect(() => assertCallAllowed("POST", `/pieces/${PIECE_DRAFT}/review`, { action: "submit" }, all)).not.toThrow();
    for (const action of ["approve", "send_to_client", "changes", "reopen"]) {
      expect(() => assertCallAllowed("POST", `/pieces/${PIECE_DRAFT}/review`, { action }, all)).toThrow(PolicyError);
    }
  });

  it("keeps an episode's stage and a piece's status out of edits", () => {
    expect(() => assertCallAllowed("PATCH", `/episodes/${PIECE_DRAFT}`, { stage: "published" }, all)).toThrow(PolicyError);
    expect(() => assertCallAllowed("PATCH", `/pieces/${PIECE_DRAFT}`, { status: "approved" }, all)).toThrow(PolicyError);
  });

  it("refuses writes on a read-only connection", () => {
    expect(() => assertCallAllowed("POST", `/clients/${CLIENT_A}/pieces`, {}, [SCOPE_READ])).toThrow(/read access only/);
  });
});

describe("ThreadOS tokens", () => {
  it("refreshes an expiring ThreadOS token once per connection, even under concurrent calls", async () => {
    fake.expireAccessTokens();
    const { access_token } = await connect("brian@thecarbonthread.com", "pw-admin");
    const results = await Promise.all(Array.from({ length: 6 }, () => call(access_token, "list_clients")));
    expect(results.every((r) => !r.isError)).toBe(true);
    expect(fake.reuseDetected).toBe(0);
    expect(fake.calls.some((c) => c.path === "/api/auth/refresh")).toBe(true);
  });
});
