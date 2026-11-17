import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterAll, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createApp } from "../src/server.js";
import { MemoryStore } from "../src/store/memory.js";
import { CLIENT_A, startFakeThreadOS } from "./fake-threados.js";

// The official MCP client, over real HTTP: initialize, list tools, call one
const closers: (() => Promise<void>)[] = [];
afterAll(async () => { for (const c of closers) await c(); });

it("works with the MCP SDK client end to end", async () => {
  const fake = await startFakeThreadOS();
  closers.push(fake.close);
  const port = 40000 + Math.floor(Math.random() * 10000);
  const base = `http://localhost:${port}`;
  const { app } = createApp(loadConfig({
    PUBLIC_URL: base, THREADOS_API_URL: fake.url, TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("hex"), TRUST_PROXY: "false", RATE_LIMITS: "off",
  } as NodeJS.ProcessEnv), new MemoryStore());
  const server = app.listen(port);
  closers.push(() => new Promise((r) => server.close(() => r())));

  const redirect = "http://127.0.0.1:9999/callback";
  const reg = await (await fetch(`${base}/register`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Test agent", redirect_uris: [redirect], token_endpoint_auth_method: "none" }) })).json();
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const page = await fetch(`${base}/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: "S256" })}`);
  const html = await page.text();
  const field = (n: string) => new RegExp(`name="${n}" value="([^"]+)"`).exec(html)![1]!;
  const signIn = await fetch(`${base}/oauth/sign-in`, {
    method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded", cookie: page.headers.get("set-cookie")!.split(";")[0]! },
    body: new URLSearchParams({ pending: field("pending"), csrf: field("csrf"), email: "brian@thecarbonthread.com", password: "pw-admin", write: "1", decision: "allow" }),
  });
  const code = new URL(signIn.headers.get("location")!).searchParams.get("code")!;
  const tokens = await (await fetch(`${base}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: reg.client_id, redirect_uri: redirect }) })).json();

  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${tokens.access_token}` } } }));
  closers.unshift(() => client.close());
  expect(client.getInstructions()).toContain("Brian Fitch");
  const { tools } = await client.listTools();
  const draft = tools.find((t) => t.name === "create_content_draft")!;
  expect(draft.annotations?.readOnlyHint).toBe(false);
  expect(draft.inputSchema.required).toEqual(expect.arrayContaining(["client_id", "channel", "title"]));
  const result: any = await client.callTool({ name: "create_content_draft", arguments: { client_id: CLIENT_A, channel: "linkedin", title: "Hi", body: "From the SDK" } });
  expect(result.isError).toBeFalsy();
  expect(result.content[0].text).toContain("app.thecarbonthread.com/clients/");
});
