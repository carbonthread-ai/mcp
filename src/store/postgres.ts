import pg from "pg";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthCode, Grant, GrantLockOps, IssuedToken, PendingAuthorization, Store, UpstreamTokens } from "./types.js";

// Its own schema, so it can share the ThreadOS database without touching ThreadOS's tables (or use a database of its own)
const SCHEMA = `
CREATE SCHEMA IF NOT EXISTS threados_mcp;
CREATE TABLE IF NOT EXISTS threados_mcp.clients (
  client_id TEXT PRIMARY KEY,
  info JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS threados_mcp.pending (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  expires_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS threados_mcp.grants (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  user_email TEXT NOT NULL,
  scopes TEXT[] NOT NULL,
  resource TEXT,
  upstream_access_sealed TEXT NOT NULL,
  upstream_refresh_sealed TEXT NOT NULL,
  upstream_access_expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  revoked_at BIGINT
);
CREATE INDEX IF NOT EXISTS grants_user_idx ON threados_mcp.grants (user_id);
CREATE TABLE IF NOT EXISTS threados_mcp.codes (
  code_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES threados_mcp.grants(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at BIGINT
);
CREATE TABLE IF NOT EXISTS threados_mcp.tokens (
  token_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES threados_mcp.grants(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  scopes TEXT[] NOT NULL,
  expires_at BIGINT NOT NULL,
  revoked_at BIGINT,
  used_at BIGINT
);
CREATE INDEX IF NOT EXISTS tokens_grant_idx ON threados_mcp.tokens (grant_id);
`;

const num = (v: unknown) => (v === null || v === undefined ? undefined : Number(v));

function grantRow(r: any): Grant {
  return {
    id: r.id, clientId: r.client_id, userId: r.user_id, userEmail: r.user_email, scopes: r.scopes,
    resource: r.resource ?? undefined, upstreamAccessSealed: r.upstream_access_sealed,
    upstreamRefreshSealed: r.upstream_refresh_sealed, upstreamAccessExpiresAt: Number(r.upstream_access_expires_at),
    createdAt: Number(r.created_at), revokedAt: num(r.revoked_at),
  };
}

function codeRow(r: any): AuthCode {
  return {
    codeHash: r.code_hash, grantId: r.grant_id, clientId: r.client_id, redirectUri: r.redirect_uri,
    codeChallenge: r.code_challenge, expiresAt: Number(r.expires_at), usedAt: num(r.used_at),
  };
}

function tokenRow(r: any): IssuedToken {
  return {
    tokenHash: r.token_hash, grantId: r.grant_id, clientId: r.client_id, kind: r.kind, scopes: r.scopes,
    expiresAt: Number(r.expires_at), revokedAt: num(r.revoked_at), usedAt: num(r.used_at),
  };
}

export class PostgresStore implements Store {
  private constructor(private readonly pool: pg.Pool) {}

  static async connect(url: string, max = 10): Promise<PostgresStore> {
    const pool = new pg.Pool({ connectionString: url, max });
    await pool.query(SCHEMA);
    return new PostgresStore(pool);
  }

  async getClient(clientId: string) {
    const { rows } = await this.pool.query("SELECT info FROM threados_mcp.clients WHERE client_id = $1", [clientId]);
    return rows[0]?.info as OAuthClientInformationFull | undefined;
  }

  async saveClient(client: OAuthClientInformationFull) {
    await this.pool.query(
      "INSERT INTO threados_mcp.clients (client_id, info) VALUES ($1, $2) ON CONFLICT (client_id) DO UPDATE SET info = EXCLUDED.info",
      [client.client_id, client],
    );
  }

  async savePending(p: PendingAuthorization) {
    await this.pool.query("INSERT INTO threados_mcp.pending (id, data, expires_at) VALUES ($1, $2, $3)", [p.id, p, p.expiresAt]);
  }

  async getPending(id: string) {
    const { rows } = await this.pool.query("SELECT data FROM threados_mcp.pending WHERE id = $1", [id]);
    return rows[0]?.data as PendingAuthorization | undefined;
  }

  async takePending(id: string) {
    const { rows } = await this.pool.query("DELETE FROM threados_mcp.pending WHERE id = $1 RETURNING data", [id]);
    return rows[0]?.data as PendingAuthorization | undefined;
  }

  async saveGrant(g: Grant) {
    await this.pool.query(
      `INSERT INTO threados_mcp.grants (id, client_id, user_id, user_email, scopes, resource, upstream_access_sealed,
         upstream_refresh_sealed, upstream_access_expires_at, created_at, revoked_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [g.id, g.clientId, g.userId, g.userEmail, g.scopes, g.resource ?? null, g.upstreamAccessSealed, g.upstreamRefreshSealed,
        g.upstreamAccessExpiresAt, g.createdAt, g.revokedAt ?? null],
    );
  }

  async getGrant(id: string) {
    const { rows } = await this.pool.query("SELECT * FROM threados_mcp.grants WHERE id = $1", [id]);
    return rows[0] ? grantRow(rows[0]) : undefined;
  }

  async revokeGrant(id: string) {
    const now = Date.now();
    await this.pool.query("UPDATE threados_mcp.grants SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1", [id, now]);
    await this.pool.query("UPDATE threados_mcp.tokens SET revoked_at = COALESCE(revoked_at, $2) WHERE grant_id = $1", [id, now]);
  }

  async withGrantLock<T>(id: string, fn: (grant: Grant | undefined, ops: GrantLockOps) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // The row lock holds other instances back until this refresh is saved
      const { rows } = await client.query("SELECT * FROM threados_mcp.grants WHERE id = $1 FOR UPDATE", [id]);
      const save = async (t: UpstreamTokens) => {
        await client.query(
          `UPDATE threados_mcp.grants SET upstream_access_sealed = $2, upstream_refresh_sealed = $3, upstream_access_expires_at = $4
           WHERE id = $1`,
          [id, t.accessSealed, t.refreshSealed, t.accessExpiresAt],
        );
      };
      const revoke = async () => {
        const now = Date.now();
        await client.query("UPDATE threados_mcp.grants SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1", [id, now]);
        await client.query("UPDATE threados_mcp.tokens SET revoked_at = COALESCE(revoked_at, $2) WHERE grant_id = $1", [id, now]);
      };
      const result = await fn(rows[0] ? grantRow(rows[0]) : undefined, { save, revoke });
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async saveCode(c: AuthCode) {
    await this.pool.query(
      `INSERT INTO threados_mcp.codes (code_hash, grant_id, client_id, redirect_uri, code_challenge, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [c.codeHash, c.grantId, c.clientId, c.redirectUri, c.codeChallenge, c.expiresAt],
    );
  }

  async peekCode(codeHash: string) {
    const { rows } = await this.pool.query("SELECT * FROM threados_mcp.codes WHERE code_hash = $1", [codeHash]);
    return rows[0] ? codeRow(rows[0]) : undefined;
  }

  async useCode(codeHash: string) {
    // Returns the row as it was before this call marked it, so a second use is visible to the caller
    const { rows } = await this.pool.query(
      `UPDATE threados_mcp.codes c SET used_at = COALESCE(c.used_at, $2)
       FROM (SELECT code_hash, used_at FROM threados_mcp.codes WHERE code_hash = $1 FOR UPDATE) old
       WHERE c.code_hash = old.code_hash
       RETURNING c.*, old.used_at AS previous_used_at`,
      [codeHash, Date.now()],
    );
    return rows[0] ? { ...codeRow(rows[0]), usedAt: num(rows[0].previous_used_at) } : undefined;
  }

  async saveToken(t: IssuedToken) {
    await this.pool.query(
      `INSERT INTO threados_mcp.tokens (token_hash, grant_id, client_id, kind, scopes, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
      [t.tokenHash, t.grantId, t.clientId, t.kind, t.scopes, t.expiresAt],
    );
  }

  async getToken(tokenHash: string) {
    const { rows } = await this.pool.query("SELECT * FROM threados_mcp.tokens WHERE token_hash = $1", [tokenHash]);
    return rows[0] ? tokenRow(rows[0]) : undefined;
  }

  async useRefreshToken(tokenHash: string) {
    const { rows } = await this.pool.query(
      `UPDATE threados_mcp.tokens t SET used_at = COALESCE(t.used_at, $2)
       FROM (SELECT token_hash, used_at FROM threados_mcp.tokens WHERE token_hash = $1 FOR UPDATE) old
       WHERE t.token_hash = old.token_hash
       RETURNING t.*, old.used_at AS previous_used_at`,
      [tokenHash, Date.now()],
    );
    return rows[0] ? { ...tokenRow(rows[0]), usedAt: num(rows[0].previous_used_at) } : undefined;
  }

  async revokeToken(tokenHash: string) {
    await this.pool.query("UPDATE threados_mcp.tokens SET revoked_at = COALESCE(revoked_at, $2) WHERE token_hash = $1", [tokenHash, Date.now()]);
  }

  async sweep(now: number) {
    await this.pool.query("DELETE FROM threados_mcp.pending WHERE expires_at < $1", [now]);
    await this.pool.query("DELETE FROM threados_mcp.codes WHERE expires_at < $1", [now]);
    await this.pool.query("DELETE FROM threados_mcp.tokens WHERE expires_at < $1", [now]);
  }

  async close() {
    await this.pool.end();
  }
}
