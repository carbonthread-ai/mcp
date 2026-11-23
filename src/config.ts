import { createHash } from "node:crypto";

export interface Config {
  /** Where this server is reached from outside, e.g. https://mcp.thecarbonthread.com (no trailing slash). */
  publicUrl: URL;
  /** The MCP endpoint, publicUrl + /mcp. Tokens are issued for this resource only. */
  mcpUrl: URL;
  port: number;
  /** Fabric backend base, including the API prefix, e.g. https://<backend>.up.railway.app/api */
  fabricApiUrl: string;
  /** The Fabric web app, linked from tool results so people finish reviews there. */
  fabricAppUrl: string;
  /** postgres://… for production; empty runs on the in-memory store (one process, lost on restart). */
  databaseUrl: string | null;
  /** 32-byte key that encrypts the Fabric tokens held for each connection. */
  encryptionKey: Buffer;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  /** Redirect URIs a dynamically registered client may use (see policy.redirectUriAllowed). */
  extraRedirectSchemes: string[];
  allowedRedirectHosts: string[] | null;
  trustProxy: boolean;
  /** Rate limits on registration, sign-in, tokens and tool calls. Off only for the test suite. */
  rateLimits: boolean;
}

/** The first of these env vars that is set; the later names are old ones still accepted (THREADOS_* before the rename). */
function required(env: NodeJS.ProcessEnv, name: string, ...oldNames: string[]): string {
  const value = firstOf(env, name, ...oldNames);
  if (!value) throw new Error(`${name}${oldNames.length ? ` (or the old ${oldNames.join(", ")})` : ""} is required`);
  return value;
}

function firstOf(env: NodeJS.ProcessEnv, ...names: string[]): string | undefined {
  for (const name of names) {
    const value = env[name]?.trim();
    if (value) return value;
  }
  return undefined;
}

function list(value: string | undefined): string[] {
  return (value ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

export function encryptionKeyFrom(raw: string): Buffer {
  // A base64 or hex 32-byte key is used as is; anything else (a passphrase) is stretched with SHA-256
  if (/^[0-9a-f]{64}$/i.test(raw)) return Buffer.from(raw, "hex");
  const b64 = Buffer.from(raw, "base64");
  if (b64.length === 32 && /^[A-Za-z0-9+/=_-]+$/.test(raw)) return b64;
  if (raw.length < 32) throw new Error("TOKEN_ENCRYPTION_KEY must be a 32-byte key (hex or base64) or a passphrase of 32+ characters");
  return createHash("sha256").update(raw).digest();
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const publicUrl = new URL(required(env, "PUBLIC_URL").replace(/\/+$/, ""));
  if (publicUrl.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(publicUrl.hostname)) {
    throw new Error("PUBLIC_URL must be https (OAuth 2.1 requires it outside localhost)");
  }
  const hosts = list(env.ALLOWED_REDIRECT_HOSTS);
  return {
    publicUrl,
    mcpUrl: new URL("/mcp", publicUrl),
    port: Number(env.PORT ?? 8787),
    fabricApiUrl: required(env, "FABRIC_API_URL", "THREADOS_API_URL").replace(/\/+$/, ""),
    fabricAppUrl: (firstOf(env, "FABRIC_APP_URL", "THREADOS_APP_URL") ?? "https://app.thecarbonthread.com").replace(/\/+$/, ""),
    databaseUrl: env.DATABASE_URL?.trim() || null,
    encryptionKey: encryptionKeyFrom(required(env, "TOKEN_ENCRYPTION_KEY")),
    accessTokenTtlSeconds: Number(env.ACCESS_TOKEN_TTL_SECONDS ?? 3600),
    refreshTokenTtlSeconds: Number(env.REFRESH_TOKEN_TTL_SECONDS ?? 30 * 24 * 3600),
    extraRedirectSchemes: list(env.EXTRA_REDIRECT_SCHEMES ?? "cursor,vscode,vscode-insiders,windsurf,zed"),
    allowedRedirectHosts: hosts.length ? hosts : null,
    trustProxy: (env.TRUST_PROXY ?? "true") !== "false",
    rateLimits: env.RATE_LIMITS !== "off",
  };
}
