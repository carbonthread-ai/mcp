import express from "express";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

/**
 * A small stand-in for the ThreadOS API with the same rules that matter here: per-role permission codes (copied
 * from the backend's catalog), restriction to assigned clients, portal-only client logins, rotating refresh tokens
 * with reuse detection, and the approve/send endpoints, so tests can prove the MCP never reaches them.
 */

export const CLIENT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const CLIENT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const PIECE_DRAFT = "11111111-1111-4111-8111-111111111111";
export const PIECE_APPROVED = "22222222-2222-4222-8222-222222222222";
export const PIECE_B = "33333333-3333-4333-8333-333333333333";

const codes = (grants: Record<string, string[]>) => Object.entries(grants).flatMap(([r, as]) => as.map((a) => `${r}:${a}`));

const ROLES: Record<string, { display: string; restrict: boolean; permissions: string[] }> = {
  administrator: {
    display: "Administrator", restrict: false,
    permissions: codes({ client: ["view", "create", "edit", "approve", "export", "delete"], knowledge: ["view", "create", "edit", "export", "delete"],
      strategy: ["view", "create", "edit", "approve", "export", "delete"], content: ["view", "create", "edit", "approve", "export", "delete"],
      user: ["view", "create", "edit", "delete"], settings: ["view", "edit"] }),
  },
  editor: {
    display: "Editor", restrict: true,
    permissions: codes({ client: ["view"], knowledge: ["view", "export"], plan: ["view"], strategy: ["view"], content: ["view", "create", "edit", "export"], support: ["create"] }),
  },
  developer: {
    display: "Developer", restrict: false,
    permissions: codes({ client: ["view"], knowledge: ["view"], strategy: ["view"], content: ["view"], support: ["view", "create", "edit"] }),
  },
  client: { display: "Client", restrict: true, permissions: codes({ portal: ["view", "create", "approve"] }) },
};

interface FakeUser { id: string; email: string; password: string; fullName: string; role: string; clients: string[]; active: boolean }

export const USERS: FakeUser[] = [
  { id: randomUUID(), email: "brian@thecarbonthread.com", password: "pw-admin", fullName: "Brian Fitch", role: "administrator", clients: [], active: true },
  { id: randomUUID(), email: "editor@thecarbonthread.com", password: "pw-editor", fullName: "Eddie Editor", role: "editor", clients: [CLIENT_A], active: true },
  { id: randomUUID(), email: "dev@e2m.solutions", password: "pw-dev", fullName: "Dev", role: "developer", clients: [], active: true },
  { id: randomUUID(), email: "quincy@client.com", password: "pw-client", fullName: "Quincy Avery", role: "client", clients: [CLIENT_A], active: true },
];

export interface FakeThreadOS {
  url: string;
  calls: { method: string; path: string; user?: string; body?: unknown }[];
  pieces: Map<string, any>;
  users: FakeUser[];
  /** Make the next access tokens expire immediately (to exercise refreshing). */
  expireAccessTokens(): void;
  /** Tokens blacklisted because a refresh token was used twice (ThreadOS signs the user out everywhere). */
  reuseDetected: number;
  close(): Promise<void>;
}

export async function startFakeThreadOS(): Promise<FakeThreadOS> {
  const app = express();
  app.use(express.json());
  const access = new Map<string, string>(); // token → user id
  const refresh = new Map<string, { user: string; used: boolean }>();
  const state = {
    calls: [] as FakeThreadOS["calls"],
    reuseDetected: 0,
    pieces: new Map<string, any>([
      [PIECE_DRAFT, { id: PIECE_DRAFT, clientId: CLIENT_A, channel: "linkedin", title: "Draft post", body: "v1", status: "draft" }],
      [PIECE_APPROVED, { id: PIECE_APPROVED, clientId: CLIENT_A, channel: "linkedin", title: "Approved post", body: "final", status: "approved" }],
      [PIECE_B, { id: PIECE_B, clientId: CLIENT_B, channel: "x", title: "B's post", body: "b", status: "draft" }],
    ]),
  };
  let expireSoon = false;

  const issue = (userId: string) => {
    const a = `fake_at_${randomUUID()}`;
    const r = `fake_rt_${randomUUID()}`;
    access.set(a, userId);
    refresh.set(r, { user: userId, used: false });
    const user = USERS.find((u) => u.id === userId)!;
    return {
      accessToken: a, refreshToken: r, tokenType: "bearer", expiresIn: expireSoon ? 1 : 3600,
      user: { id: user.id, email: user.email, fullName: user.fullName, role: { id: randomUUID(), name: user.role, displayName: ROLES[user.role]!.display } },
    };
  };

  app.use((req, _res, next) => {
    state.calls.push({ method: req.method, path: req.path, body: req.body });
    next();
  });

  app.post("/api/auth/login", (req, res) => {
    const user = USERS.find((u) => u.email === req.body.email && u.password === req.body.password);
    if (!user) return void res.status(401).json({ detail: "Invalid email or password" });
    if (!user.active) return void res.status(403).json({ detail: "This account has been deactivated" });
    res.json(issue(user.id));
  });
  app.post("/api/auth/refresh", (req, res) => {
    const rec = refresh.get(req.body.refreshToken);
    if (!rec) return void res.status(401).json({ detail: "Invalid refresh token" });
    if (rec.used) {
      state.reuseDetected++;
      for (const [t, u] of access) if (u === rec.user) access.delete(t);
      return void res.status(401).json({ detail: "Refresh token has already been used" });
    }
    rec.used = true;
    res.json(issue(rec.user));
  });

  // Everything below needs a valid access token
  const authed = express.Router();
  authed.use((req, res, next) => {
    const token = (req.headers.authorization ?? "").replace(/^Bearer /, "");
    const userId = access.get(token);
    const user = USERS.find((u) => u.id === userId);
    if (!user || !user.active) return void res.status(401).json({ detail: "Token has been revoked" });
    (req as any).user = user;
    state.calls[state.calls.length - 1]!.user = user.email;
    next();
  });
  app.use("/api", authed);

  const user = (req: express.Request) => (req as any).user as FakeUser;
  const perm = (code: string): express.RequestHandler => (req, res, next) =>
    ROLES[user(req).role]!.permissions.includes(code) ? next() : void res.status(403).json({ detail: `Missing permission: ${code}` });
  const clientAccess = (id: string, req: express.Request) => !ROLES[user(req).role]!.restrict || user(req).clients.includes(id);
  const access403 = (res: express.Response) => res.status(403).json({ detail: "You do not have access to this client" });

  authed.post("/auth/logout", (req, res) => {
    access.delete((req.headers.authorization ?? "").replace(/^Bearer /, ""));
    res.json({ message: "Signed out" });
  });
  authed.get("/users/me", (req, res) => {
    const u = user(req);
    const role = ROLES[u.role]!;
    res.json({ id: u.id, email: u.email, fullName: u.fullName, role: { id: "r", name: u.role, displayName: role.display }, permissions: role.permissions, restrictToAssignedClients: role.restrict });
  });
  authed.get("/users/me/clients", (req, res) => { res.json({ userId: user(req).id, clientIds: user(req).clients }); });

  authed.get("/clients", perm("client:view"), (req, res) => {
    res.json([{ id: CLIENT_A, name: "Quincy Avery Co" }, { id: CLIENT_B, name: "Other Co" }].filter((c) => clientAccess(c.id, req)));
  });
  authed.get("/clients/:id/brief", perm("strategy:view"), (req, res) => {
    if (!clientAccess(String(req.params.id), req)) return void access403(res);
    res.json({ clientId: req.params.id, status: "approved", sections: [{ id: randomUUID(), title: "Voice", content: "Direct, warm." }] });
  });
  authed.post("/clients/:id/brief/instructions", perm("strategy:edit"), (req, res) => {
    if (!clientAccess(String(req.params.id), req)) return void access403(res);
    res.status(202).json({ id: randomUUID(), status: "drafting", instruction: req.body.instruction, changes: [] });
  });
  authed.post("/clients/:id/brief/approve", perm("strategy:approve"), (_req, res) => { res.json({ approved: true }); });

  authed.get("/clients/:id/pieces", perm("content:view"), (req, res) => {
    if (!clientAccess(String(req.params.id), req)) return void access403(res);
    res.json([...state.pieces.values()].filter((p) => p.clientId === req.params.id));
  });
  authed.post("/clients/:id/pieces", perm("content:create"), (req, res) => {
    if (!clientAccess(String(req.params.id), req)) return void access403(res);
    const piece = { id: randomUUID(), clientId: req.params.id, status: "draft", ...req.body };
    state.pieces.set(piece.id, piece);
    res.status(201).json(piece);
  });
  authed.get("/pieces/:id", perm("content:view"), (req, res) => {
    const piece = state.pieces.get(String(req.params.id));
    if (!piece) return void res.status(404).json({ detail: "Piece not found" });
    if (!clientAccess(piece.clientId, req)) return void access403(res);
    res.json(piece);
  });
  authed.patch("/pieces/:id", perm("content:edit"), (req, res) => {
    const piece = state.pieces.get(String(req.params.id));
    if (!clientAccess(piece.clientId, req)) return void access403(res);
    Object.assign(piece, req.body);
    res.json(piece);
  });
  authed.post("/pieces/:id/review", perm("content:edit"), (req, res) => {
    const piece = state.pieces.get(String(req.params.id));
    if (!clientAccess(piece.clientId, req)) return void access403(res);
    if (req.body.action === "approve" && !ROLES[user(req).role]!.permissions.includes("content:approve")) return void res.status(403).json({ detail: "Missing permission: content:approve" });
    piece.status = req.body.action === "submit" ? "internal_review" : req.body.action === "approve" ? "approved" : piece.status;
    res.json(piece);
  });
  authed.delete("/pieces/:id", perm("content:delete"), (req, res) => {
    state.pieces.delete(String(req.params.id));
    res.status(204).end();
  });

  authed.get("/portal/me", perm("portal:view"), (req, res) => { res.json({ client: { id: user(req).clients[0], name: "Quincy Avery Co" } }); });
  authed.get("/portal/approvals", perm("portal:view"), (_req, res) => { res.json({ pieces: [], sequences: [] }); });
  authed.post("/portal/assistant", perm("portal:create"), (req, res) => { res.json([{ role: "assistant", text: `Saved: ${req.body.text}` }]); });
  authed.post("/portal/approvals/:kind/:id", perm("portal:approve"), (_req, res) => { res.json({ approved: true }); });

  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/api`,
    get calls() { return state.calls; },
    pieces: state.pieces,
    users: USERS,
    get reuseDetected() { return state.reuseDetected; },
    expireAccessTokens() { expireSoon = true; },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
