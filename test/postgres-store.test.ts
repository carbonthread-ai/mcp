import { PGlite } from "@electric-sql/pglite";
import { PGLiteSocketServer } from "@electric-sql/pglite-socket";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresStore } from "../src/store/postgres.js";
import type { Grant } from "../src/store/types.js";

// The production store, against an embedded Postgres (PGlite) over the wire protocol
let db: PGlite;
let socket: PGLiteSocketServer;
let store: PostgresStore;

beforeAll(async () => {
  db = await PGlite.create();
  const port = 50000 + Math.floor(Math.random() * 10000);
  socket = new PGLiteSocketServer({ db, port, host: "127.0.0.1" });
  await socket.start();
  // PGlite serves one connection at a time, so the pool keeps to one
  store = await PostgresStore.connect(`postgres://postgres@127.0.0.1:${port}/postgres?sslmode=disable`, 1);
});
afterAll(async () => {
  await store?.close();
  await socket?.stop();
  await db?.close();
});

const grant = (id: string): Grant => ({
  id, clientId: "c1", userId: "u1", userEmail: "u@x.com", scopes: ["threados:read"], upstreamAccessSealed: "a1",
  upstreamRefreshSealed: "r1", upstreamAccessExpiresAt: 1, createdAt: Date.now(),
});

describe("PostgresStore", () => {
  it("creates its tables in public, mcp_* only, with row-level security on", async () => {
    const { rows } = await (store as any).pool.query("SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' ORDER BY 1");
    expect(rows.map((r: any) => r.tablename)).toEqual(["mcp_auth_codes", "mcp_grants", "mcp_oauth_clients", "mcp_pending_authorizations", "mcp_tokens"]);
    expect(rows.every((r: any) => r.rowsecurity)).toBe(true);
  });

  it("stores clients, pending and grants", async () => {
    await store.saveClient({ client_id: "c1", redirect_uris: ["https://claude.ai/cb"] } as any);
    expect((await store.getClient("c1"))?.redirect_uris).toEqual(["https://claude.ai/cb"]);
    await store.savePending({ id: "p1", clientId: "c1", redirectUri: "https://claude.ai/cb", codeChallenge: "x", scopes: ["threados:read"], csrf: "k", expiresAt: Date.now() + 1000 });
    expect((await store.takePending("p1"))?.csrf).toBe("k");
    expect(await store.takePending("p1")).toBeUndefined();
    await store.saveGrant(grant("g1"));
    expect((await store.getGrant("g1"))?.scopes).toEqual(["threados:read"]);
  });

  it("uses a code once and reports the second use", async () => {
    await store.saveCode({ codeHash: "h1", grantId: "g1", clientId: "c1", redirectUri: "https://claude.ai/cb", codeChallenge: "x", expiresAt: Date.now() + 1000 });
    expect((await store.useCode("h1"))?.usedAt).toBeUndefined();
    expect((await store.useCode("h1"))?.usedAt).toBeTypeOf("number");
  });

  it("rotates refresh tokens and revokes a grant's tokens", async () => {
    await store.saveToken({ tokenHash: "t1", grantId: "g1", clientId: "c1", kind: "refresh", scopes: ["threados:read"], expiresAt: Date.now() + 1000 });
    expect((await store.useRefreshToken("t1"))?.usedAt).toBeUndefined();
    expect((await store.useRefreshToken("t1"))?.usedAt).toBeTypeOf("number");
    await store.revokeGrant("g1");
    expect((await store.getToken("t1"))?.revokedAt).toBeTypeOf("number");
    expect((await store.getGrant("g1"))?.revokedAt).toBeTypeOf("number");
  });

  it("saves and revokes inside the grant lock", async () => {
    await store.saveGrant(grant("g2"));
    await store.withGrantLock("g2", async (g, ops) => {
      expect(g?.upstreamAccessSealed).toBe("a1");
      await ops.save({ accessSealed: "a2", refreshSealed: "r2", accessExpiresAt: 5 });
    });
    expect((await store.getGrant("g2"))?.upstreamAccessSealed).toBe("a2");
    await store.withGrantLock("g2", async (_g, ops) => ops.revoke());
    expect((await store.getGrant("g2"))?.revokedAt).toBeTypeOf("number");
  });

  it("rolls back when the locked work fails", async () => {
    await store.saveGrant(grant("g3"));
    await expect(store.withGrantLock("g3", async (_g, ops) => {
      await ops.save({ accessSealed: "zz", refreshSealed: "zz", accessExpiresAt: 9 });
      throw new Error("boom");
    })).rejects.toThrow("boom");
    expect((await store.getGrant("g3"))?.upstreamAccessSealed).toBe("a1");
  });

  it("sweeps expired rows", async () => {
    await store.savePending({ id: "old", clientId: "c1", redirectUri: "x", codeChallenge: "x", scopes: [], csrf: "k", expiresAt: 1 });
    await store.sweep(Date.now());
    expect(await store.getPending("old")).toBeUndefined();
  });
});
