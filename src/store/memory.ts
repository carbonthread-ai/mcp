import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthCode, Grant, GrantLockOps, IssuedToken, PendingAuthorization, Store, UpstreamTokens } from "./types.js";

/** Single-process store for local development and tests. Production runs on Postgres (DATABASE_URL). */
export class MemoryStore implements Store {
  private clients = new Map<string, OAuthClientInformationFull>();
  private pending = new Map<string, PendingAuthorization>();
  private grants = new Map<string, Grant>();
  private codes = new Map<string, AuthCode>();
  private tokens = new Map<string, IssuedToken>();
  private locks = new Map<string, Promise<unknown>>();

  async getClient(clientId: string) { return this.clients.get(clientId); }
  async saveClient(client: OAuthClientInformationFull) { this.clients.set(client.client_id, client); }

  async savePending(p: PendingAuthorization) { this.pending.set(p.id, p); }
  async getPending(id: string) { return this.pending.get(id); }
  async takePending(id: string) {
    const p = this.pending.get(id);
    this.pending.delete(id);
    return p;
  }

  async saveGrant(grant: Grant) { this.grants.set(grant.id, { ...grant }); }
  async getGrant(id: string) {
    const g = this.grants.get(id);
    return g && { ...g };
  }
  async revokeGrant(id: string) {
    const g = this.grants.get(id);
    if (g && !g.revokedAt) g.revokedAt = Date.now();
    for (const t of this.tokens.values()) if (t.grantId === id && !t.revokedAt) t.revokedAt = Date.now();
  }

  async withGrantLock<T>(id: string, fn: (grant: Grant | undefined, ops: GrantLockOps) => Promise<T>): Promise<T> {
    const previous = this.locks.get(id) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((resolve) => (release = resolve));
    const chained = previous.then(() => mine);
    this.locks.set(id, chained);
    await previous;
    try {
      const save = async (t: UpstreamTokens) => {
        const g = this.grants.get(id);
        if (g) Object.assign(g, { upstreamAccessSealed: t.accessSealed, upstreamRefreshSealed: t.refreshSealed, upstreamAccessExpiresAt: t.accessExpiresAt });
      };
      return await fn(await this.getGrant(id), { save, revoke: () => this.revokeGrant(id) });
    } finally {
      release();
      if (this.locks.get(id) === chained) this.locks.delete(id);
    }
  }

  async saveCode(code: AuthCode) { this.codes.set(code.codeHash, { ...code }); }
  async peekCode(codeHash: string) { return this.codes.get(codeHash); }
  async useCode(codeHash: string) {
    const c = this.codes.get(codeHash);
    if (!c) return undefined;
    const before = { ...c };
    c.usedAt ??= Date.now();
    return before;
  }

  async saveToken(token: IssuedToken) { this.tokens.set(token.tokenHash, { ...token }); }
  async getToken(tokenHash: string) {
    const t = this.tokens.get(tokenHash);
    return t && { ...t };
  }
  async useRefreshToken(tokenHash: string) {
    const t = this.tokens.get(tokenHash);
    if (!t) return undefined;
    const before = { ...t };
    t.usedAt ??= Date.now();
    return before;
  }
  async revokeToken(tokenHash: string) {
    const t = this.tokens.get(tokenHash);
    if (t && !t.revokedAt) t.revokedAt = Date.now();
  }

  async sweep(now: number) {
    for (const [k, p] of this.pending) if (p.expiresAt < now) this.pending.delete(k);
    for (const [k, c] of this.codes) if (c.expiresAt < now) this.codes.delete(k);
    for (const [k, t] of this.tokens) if (t.expiresAt < now) this.tokens.delete(k);
  }

  async close() {}
}
