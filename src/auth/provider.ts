import type { Response } from "express";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  InvalidClientMetadataError, InvalidGrantError, InvalidScopeError, InvalidTargetError, InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { Config } from "../config.js";
import { randomToken, sha256, type Sealer } from "../crypto.js";
import { normalizeScopes, redirectUriAllowed } from "../policy.js";
import type { ThreadOSAuth } from "../threados/api.js";
import { forgetIdentity } from "../threados/identity.js";
import type { Grant, Store } from "../store/types.js";
import { renderSignIn, signInCsp } from "./pages.js";

const PENDING_TTL_MS = 10 * 60_000;
const CODE_TTL_MS = 60_000;
export const CSRF_COOKIE = "threados_mcp_csrf";

function sameResource(a: string | URL | undefined, b: URL): boolean {
  if (!a) return true;
  const strip = (u: string) => u.replace(/#.*$/, "").replace(/\/$/, "");
  return strip(String(a)) === strip(b.href);
}

export class ThreadOSOAuthProvider implements OAuthServerProvider {
  constructor(
    private readonly config: Config,
    private readonly store: Store,
    private readonly sealer: Sealer,
    private readonly upstream: ThreadOSAuth,
  ) {}

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (id) => this.store.getClient(id),
      registerClient: async (client) => {
        const bad = (client.redirect_uris ?? []).filter((uri) => !redirectUriAllowed(String(uri), {
          extraSchemes: this.config.extraRedirectSchemes, allowedHosts: this.config.allowedRedirectHosts,
        }));
        if (!client.redirect_uris?.length || bad.length) {
          throw new InvalidClientMetadataError(`redirect_uris not allowed: ${bad.join(", ") || "(none given)"}`);
        }
        const full = client as OAuthClientInformationFull;
        await this.store.saveClient(full);
        return full;
      },
    };
  }

  /** Shows the ThreadOS sign-in and consent page; POST /oauth/sign-in finishes it (auth/routes.ts). */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (!sameResource(params.resource, this.config.mcpUrl)) {
      throw new InvalidTargetError(`This server issues tokens for ${this.config.mcpUrl.href} only`);
    }
    const id = randomToken(18);
    const csrf = randomToken(18);
    await this.store.savePending({
      id, csrf, clientId: client.client_id, redirectUri: params.redirectUri, codeChallenge: params.codeChallenge,
      state: params.state, scopes: normalizeScopes(params.scopes), resource: params.resource?.href,
      expiresAt: Date.now() + PENDING_TTL_MS,
    });
    res.cookie(CSRF_COOKIE, csrf, {
      httpOnly: true, sameSite: "lax", secure: this.config.publicUrl.protocol === "https:", path: "/oauth", maxAge: PENDING_TTL_MS,
    });
    res.setHeader("Content-Security-Policy", signInCsp(params.redirectUri));
    res.setHeader("X-Frame-Options", "DENY");
    res.status(200).type("html").send(renderSignIn({ pendingId: id, csrf, client, redirectUri: params.redirectUri, scopes: normalizeScopes(params.scopes) }));
  }

  /** Called by the sign-in route once ThreadOS accepted the person's email and password. */
  async completeAuthorization(
    pendingId: string,
    input: Pick<Grant, "userId" | "userEmail" | "scopes" | "upstreamAccessSealed" | "upstreamRefreshSealed" | "upstreamAccessExpiresAt">,
  ): Promise<string> {
    const pending = await this.store.takePending(pendingId);
    if (!pending || pending.expiresAt < Date.now()) throw new InvalidGrantError("This sign-in expired. Start connecting again from your AI app.");
    // The person can narrow what the AI app asked for (untick writing), never widen it
    const scopes = input.scopes.filter((s) => pending.scopes.includes(s));
    const grant: Grant = {
      ...input, scopes, id: randomToken(18), clientId: pending.clientId, createdAt: Date.now(),
      resource: pending.resource ?? this.config.mcpUrl.href,
    };
    await this.store.saveGrant(grant);
    const code = randomToken(32);
    await this.store.saveCode({
      codeHash: sha256(code), grantId: grant.id, clientId: pending.clientId, redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge, expiresAt: Date.now() + CODE_TTL_MS,
    });
    const url = new URL(pending.redirectUri);
    url.searchParams.set("code", code);
    if (pending.state) url.searchParams.set("state", pending.state);
    return url.href;
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const code = await this.store.peekCode(sha256(authorizationCode));
    if (!code || code.clientId !== client.client_id || code.expiresAt < Date.now()) throw new InvalidGrantError("Invalid authorization code");
    return code.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull, authorizationCode: string, _verifier?: string, redirectUri?: string, resource?: URL,
  ): Promise<OAuthTokens> {
    const code = await this.store.useCode(sha256(authorizationCode));
    if (!code || code.clientId !== client.client_id) throw new InvalidGrantError("Invalid authorization code");
    if (code.usedAt) {
      // A code used twice was intercepted: whatever it already produced is revoked too
      await this.store.revokeGrant(code.grantId);
      throw new InvalidGrantError("Authorization code already used");
    }
    if (code.expiresAt < Date.now()) throw new InvalidGrantError("Authorization code expired");
    if (redirectUri && redirectUri !== code.redirectUri) throw new InvalidGrantError("redirect_uri doesn't match the authorization request");
    if (!sameResource(resource, this.config.mcpUrl)) throw new InvalidTargetError("Wrong resource");
    const grant = await this.store.getGrant(code.grantId);
    if (!grant || grant.revokedAt) throw new InvalidGrantError("This connection was revoked");
    return this.issue(grant, grant.scopes);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    const token = await this.store.useRefreshToken(sha256(refreshToken));
    if (!token || token.kind !== "refresh" || token.clientId !== client.client_id) throw new InvalidGrantError("Invalid refresh token");
    if (token.usedAt) {
      // Refresh tokens rotate; a second use means it leaked, so the connection is closed
      await this.store.revokeGrant(token.grantId);
      throw new InvalidGrantError("Refresh token already used. Reconnect ThreadOS.");
    }
    if (token.revokedAt || token.expiresAt < Date.now()) throw new InvalidGrantError("Refresh token expired or revoked");
    if (!sameResource(resource, this.config.mcpUrl)) throw new InvalidTargetError("Wrong resource");
    const grant = await this.store.getGrant(token.grantId);
    if (!grant || grant.revokedAt) throw new InvalidGrantError("This connection was revoked");
    const wanted = scopes?.length ? scopes : token.scopes;
    if (wanted.some((s) => !grant.scopes.includes(s))) throw new InvalidScopeError("Can't widen the scopes of a connection; reconnect instead");
    return this.issue(grant, wanted);
  }

  async verifyAccessToken(raw: string): Promise<AuthInfo> {
    const token = await this.store.getToken(sha256(raw));
    if (!token || token.kind !== "access" || token.revokedAt || token.expiresAt < Date.now()) throw new InvalidTokenError("Invalid or expired token");
    const grant = await this.store.getGrant(token.grantId);
    if (!grant || grant.revokedAt) throw new InvalidTokenError("This connection was revoked");
    return {
      token: raw, clientId: token.clientId, scopes: token.scopes, expiresAt: Math.floor(token.expiresAt / 1000),
      resource: new URL(grant.resource ?? this.config.mcpUrl.href),
      extra: { grantId: grant.id, userId: grant.userId },
    };
  }

  /** Revoking either token disconnects the whole connection and signs its ThreadOS session out. */
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const token = await this.store.getToken(sha256(request.token));
    if (!token || token.clientId !== client.client_id) return;
    await this.disconnect(token.grantId);
  }

  async disconnect(grantId: string): Promise<void> {
    const grant = await this.store.getGrant(grantId);
    if (!grant) return;
    await this.store.revokeGrant(grantId);
    forgetIdentity(grantId);
    if (!grant.revokedAt) {
      try {
        await this.upstream.logout(this.sealer.open(grant.upstreamAccessSealed), this.sealer.open(grant.upstreamRefreshSealed));
      } catch {
        // The ThreadOS session runs out on its own; the connection is already closed here
      }
    }
  }

  private async issue(grant: Grant, scopes: string[]): Promise<OAuthTokens> {
    const access = `tmcp_at_${randomToken(32)}`;
    const refresh = `tmcp_rt_${randomToken(32)}`;
    const now = Date.now();
    const base = { grantId: grant.id, clientId: grant.clientId, scopes };
    await this.store.saveToken({ ...base, tokenHash: sha256(access), kind: "access", expiresAt: now + this.config.accessTokenTtlSeconds * 1000 });
    await this.store.saveToken({ ...base, tokenHash: sha256(refresh), kind: "refresh", expiresAt: now + this.config.refreshTokenTtlSeconds * 1000 });
    return {
      access_token: access, token_type: "bearer", expires_in: this.config.accessTokenTtlSeconds,
      refresh_token: refresh, scope: scopes.join(" "),
    };
  }
}
