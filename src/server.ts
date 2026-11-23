import express, { type Request, type Response } from "express";
import { rateLimit } from "express-rate-limit";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Config } from "./config.js";
import { Sealer } from "./crypto.js";
import { SUPPORTED_SCOPES } from "./policy.js";
import { FabricOAuthProvider } from "./auth/provider.js";
import { signInRouter } from "./auth/routes.js";
import { ConnectionLostError, FabricAuth, FabricClient, FabricError } from "./fabric/api.js";
import { loadIdentity } from "./fabric/identity.js";
import { buildMcpServer, describeError } from "./tools/index.js";
import type { ToolContext } from "./tools/registry.js";
import type { Store } from "./store/types.js";

function audit(event: string, fields: Record<string, unknown>) {
  console.info(JSON.stringify({ at: new Date().toISOString(), event, ...fields }));
}

export function createApp(config: Config, store: Store) {
  const sealer = new Sealer(config.encryptionKey);
  const upstream = new FabricAuth(config.fabricApiUrl);
  const provider = new FabricOAuthProvider(config, store, sealer, upstream);

  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", config.trustProxy ? 1 : false);

  // OAuth 2.1: metadata, dynamic client registration, /authorize, /token, /revoke
  app.use(mcpAuthRouter({
    provider,
    issuerUrl: config.publicUrl,
    resourceServerUrl: config.mcpUrl,
    scopesSupported: SUPPORTED_SCOPES,
    resourceName: "Fabric",
    ...(config.rateLimits ? {} : {
      authorizationOptions: { rateLimit: false }, clientRegistrationOptions: { rateLimit: false },
      tokenOptions: { rateLimit: false }, revocationOptions: { rateLimit: false },
    }),
  }));
  app.use(signInRouter({ store, sealer, upstream, provider, rateLimits: config.rateLimits }));

  app.get("/health", (_req, res) => { res.json({ ok: true }); });
  app.get("/", (_req, res) => {
    res.type("text").send(`Fabric MCP server.\n\nAdd it to Claude, ChatGPT or any MCP client as a custom connector:\n  ${config.mcpUrl.href}\n\nYou'll be asked to sign in with your Fabric account.\n`);
  });

  const bearer = requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(config.mcpUrl),
    expectedResource: config.mcpUrl,
  });
  const perConnection = !config.rateLimits ? ((_req: Request, _res: Response, next: () => void) => next()) : rateLimit({
    windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false,
    // Runs after bearer auth, so every request here has a connection to count against
    keyGenerator: (req) => String(req.auth?.extra?.grantId ?? "unauthenticated"),
  });

  // Browser-based MCP clients (e.g. the MCP Inspector). Auth is a bearer token, never a cookie, so any origin is fine
  app.use("/mcp", (req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Protocol-Version, Mcp-Session-Id");
    res.setHeader("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS");
    if (req.method === "OPTIONS") return void res.status(204).end();
    next();
  });

  app.post("/mcp", bearer, perConnection, express.json({ limit: "4mb" }), async (req: Request, res: Response) => {
    const auth = req.auth!;
    const grantId = String(auth.extra?.grantId);
    const userId = String(auth.extra?.userId);
    const api = new FabricClient(config.fabricApiUrl, upstream, store, sealer, grantId, auth.scopes);

    let identity;
    try {
      identity = await loadIdentity(grantId, api);
    } catch (error) {
      if (error instanceof ConnectionLostError || (error instanceof FabricError && (error.status === 401 || error.status === 403))) {
        // The Fabric sign-in ended or the account was deactivated: close the connection and make the app reconnect
        await provider.disconnect(grantId);
        res.status(401)
          .set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Fabric sign-in ended", resource_metadata="${getOAuthProtectedResourceMetadataUrl(config.mcpUrl)}"`)
          .json({ error: "invalid_token", error_description: describeError(error) });
        return;
      }
      res.status(502).json({ jsonrpc: "2.0", error: { code: -32603, message: describeError(error) }, id: null });
      return;
    }

    const ctx: ToolContext = {
      api, identity, scopes: auth.scopes, appUrl: config.fabricAppUrl,
      assertClient(clientId: string) {
        if (identity.clientIds !== null && !identity.clientIds.includes(clientId)) {
          throw new FabricError(403, "You do not have access to this client");
        }
      },
      audit(action, details) {
        audit("mcp.write", { action, userId, email: identity.email, role: identity.role.name, oauthClient: auth.clientId, ...details });
      },
    };

    const server = buildMcpServer(ctx);
    // Stateless: each request carries its own token, so a role or assignment change applies to the next call
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error("mcp request failed", error);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  });

  const notAllowed = (_req: Request, res: Response) => {
    res.status(405).set("Allow", "POST").json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
  };
  app.get("/mcp", notAllowed);
  app.delete("/mcp", notAllowed);

  return { app, provider };
}
