import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

/** An /authorize request waiting for the person to sign in and consent. */
export interface PendingAuthorization {
  id: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  scopes: string[];
  resource?: string;
  /** Ties the sign-in form to the browser that opened it. */
  csrf: string;
  expiresAt: number;
}

/**
 * One person's connection from one MCP client (e.g. Brian's Claude). It holds that person's Fabric tokens,
 * sealed; every tool call runs on them, so Fabric's own roles and client access decide what the call can touch.
 */
export interface Grant {
  id: string;
  clientId: string;
  userId: string;
  userEmail: string;
  scopes: string[];
  resource?: string;
  upstreamAccessSealed: string;
  upstreamRefreshSealed: string;
  upstreamAccessExpiresAt: number;
  createdAt: number;
  revokedAt?: number;
}

export interface AuthCode {
  codeHash: string;
  grantId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  expiresAt: number;
  usedAt?: number;
}

export type TokenKind = "access" | "refresh";

export interface IssuedToken {
  tokenHash: string;
  grantId: string;
  clientId: string;
  kind: TokenKind;
  scopes: string[];
  expiresAt: number;
  revokedAt?: number;
  /** Refresh tokens rotate: once used, a second use means it leaked, and the whole grant is revoked. */
  usedAt?: number;
}

export interface UpstreamTokens {
  accessSealed: string;
  refreshSealed: string;
  accessExpiresAt: number;
}

/** Writes made while holding a grant's lock (on Postgres, inside the same transaction as the row lock). */
export interface GrantLockOps {
  save(tokens: UpstreamTokens): Promise<void>;
  revoke(): Promise<void>;
}

export interface Store {
  getClient(clientId: string): Promise<OAuthClientInformationFull | undefined>;
  saveClient(client: OAuthClientInformationFull): Promise<void>;

  savePending(pending: PendingAuthorization): Promise<void>;
  /** Reads and deletes: a pending authorization is used once. */
  takePending(id: string): Promise<PendingAuthorization | undefined>;
  getPending(id: string): Promise<PendingAuthorization | undefined>;

  saveGrant(grant: Grant): Promise<void>;
  getGrant(id: string): Promise<Grant | undefined>;
  revokeGrant(id: string): Promise<void>;
  /**
   * Runs `fn` while holding the grant's lock (across processes on Postgres). Fabric treats a reused refresh token
   * as theft and signs the person out everywhere, so two refreshes of the same grant must never run at once.
   */
  withGrantLock<T>(id: string, fn: (grant: Grant | undefined, ops: GrantLockOps) => Promise<T>): Promise<T>;

  saveCode(code: AuthCode): Promise<void>;
  /** Marks the code used and returns it as it was; a code already used comes back with usedAt set. */
  useCode(codeHash: string): Promise<AuthCode | undefined>;
  peekCode(codeHash: string): Promise<AuthCode | undefined>;

  saveToken(token: IssuedToken): Promise<void>;
  getToken(tokenHash: string): Promise<IssuedToken | undefined>;
  /** Marks a refresh token used; returns it as it was before. */
  useRefreshToken(tokenHash: string): Promise<IssuedToken | undefined>;
  revokeToken(tokenHash: string): Promise<void>;

  /** Drops expired pending authorizations, codes and tokens. */
  sweep(now: number): Promise<void>;
  close(): Promise<void>;
}
