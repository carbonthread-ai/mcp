import type { Sealer } from "../crypto.js";
import { assertCallAllowed } from "../policy.js";
import type { Grant, Store } from "../store/types.js";

/** An error the ThreadOS API returned (its status and message are passed to the AI as they are). */
export class ThreadOSError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "ThreadOSError";
  }
}

/** The person's ThreadOS sign-in no longer works (signed out, password changed, deactivated): reconnect. */
export class ConnectionLostError extends Error {
  constructor(message = "Your ThreadOS sign-in has ended. Reconnect ThreadOS in your AI app to continue.") {
    super(message);
    this.name = "ConnectionLostError";
  }
}

export interface UpstreamLogin {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: { id: string; email: string; fullName?: string; role?: { name: string; displayName?: string } };
}

const USER_AGENT = "ThreadOS-MCP/0.1";

function pick<T = unknown>(obj: any, camel: string, snake: string): T {
  return (obj?.[camel] ?? obj?.[snake]) as T;
}

async function readError(res: Response): Promise<string> {
  const text = await res.text().catch(() => "");
  try {
    const data = JSON.parse(text);
    const detail = data.detail ?? data.message ?? data.error ?? text;
    if (Array.isArray(detail)) return detail.map((d: any) => `${(d.loc ?? []).slice(1).join(".")}: ${d.msg}`).join("; ");
    return typeof detail === "string" ? detail : JSON.stringify(detail);
  } catch {
    return text || res.statusText;
  }
}

function toLogin(data: any): UpstreamLogin {
  const user = data.user ?? {};
  return {
    accessToken: pick(data, "accessToken", "access_token"),
    refreshToken: pick(data, "refreshToken", "refresh_token"),
    expiresIn: Number(pick(data, "expiresIn", "expires_in") ?? 3600),
    user: { id: String(user.id), email: user.email, fullName: pick(user, "fullName", "full_name"), role: user.role },
  };
}

/** The unauthenticated part of the ThreadOS API: signing in, refreshing and signing out. */
export class ThreadOSAuth {
  constructor(private readonly baseUrl: string) {}

  async login(email: string, password: string): Promise<UpstreamLogin> {
    const res = await fetch(`${this.baseUrl}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) throw new ThreadOSError(res.status, await readError(res));
    return toLogin(await res.json());
  }

  async refresh(refreshToken: string): Promise<UpstreamLogin> {
    const res = await fetch(`${this.baseUrl}/auth/refresh`, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT },
      body: JSON.stringify({ refreshToken }),
    });
    if (!res.ok) throw new ThreadOSError(res.status, await readError(res));
    return toLogin(await res.json());
  }

  async logout(accessToken: string, refreshToken: string): Promise<void> {
    await fetch(`${this.baseUrl}/auth/logout`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}`, "user-agent": USER_AGENT },
      body: JSON.stringify({ refreshToken }),
    }).catch(() => undefined);
  }
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | string[] | undefined | null>;
  json?: unknown;
  /** Sent as multipart/form-data (the ThreadOS endpoints that also take files). */
  form?: Record<string, string | undefined | null>;
}

const REFRESH_MARGIN_MS = 60_000;

/**
 * Calls the ThreadOS API as the person behind one grant. Every call passes policy.assertCallAllowed first, then runs
 * on that person's own ThreadOS token, so the backend applies their role and client access as it would in the app.
 */
export class ThreadOSClient {
  constructor(
    private readonly baseUrl: string,
    private readonly auth: ThreadOSAuth,
    private readonly store: Store,
    private readonly sealer: Sealer,
    private readonly grantId: string,
    private readonly scopes: string[],
  ) {}

  get<T = any>(path: string, query?: RequestOptions["query"]) { return this.request<T>("GET", path, { query }); }
  post<T = any>(path: string, json?: unknown) { return this.request<T>("POST", path, { json }); }
  patch<T = any>(path: string, json: unknown) { return this.request<T>("PATCH", path, { json }); }
  postForm<T = any>(path: string, form: RequestOptions["form"]) { return this.request<T>("POST", path, { form }); }

  async request<T = any>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    assertCallAllowed(method, path, opts.json ?? opts.form, this.scopes);
    let token = await this.accessToken();
    let res = await this.send(method, path, opts, token);
    if (res.status === 401) {
      token = await this.refresh(token);
      res = await this.send(method, path, opts, token);
      if (res.status === 401) throw new ConnectionLostError();
    }
    if (!res.ok) throw new ThreadOSError(res.status, await readError(res));
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private async send(method: string, path: string, opts: RequestOptions, token: string): Promise<Response> {
    const url = new URL(`${this.baseUrl}${path}`);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined || v === null || v === "") continue;
      if (Array.isArray(v)) v.forEach((item) => url.searchParams.append(k, item));
      else url.searchParams.set(k, String(v));
    }
    const headers: Record<string, string> = { authorization: `Bearer ${token}`, "user-agent": USER_AGENT, "x-threados-via": "mcp" };
    let body: BodyInit | undefined;
    if (opts.form) {
      const form = new FormData();
      for (const [k, v] of Object.entries(opts.form)) if (v !== undefined && v !== null) form.append(k, v);
      body = form;
    } else if (opts.json !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(opts.json);
    }
    return fetch(url, { method, headers, body });
  }

  private async liveGrant(): Promise<Grant> {
    const grant = await this.store.getGrant(this.grantId);
    if (!grant || grant.revokedAt) throw new ConnectionLostError();
    return grant;
  }

  private async accessToken(): Promise<string> {
    const grant = await this.liveGrant();
    const token = this.sealer.open(grant.upstreamAccessSealed);
    if (grant.upstreamAccessExpiresAt - REFRESH_MARGIN_MS > Date.now()) return token;
    return this.refresh(token);
  }

  /**
   * Swaps the refresh token for a new pair under the grant's lock. If another request (or instance) already did,
   * its new token is used instead: ThreadOS signs the person out everywhere when a refresh token is used twice.
   */
  private async refresh(staleAccess: string): Promise<string> {
    // null = ThreadOS refused the refresh: the grant is revoked inside the lock, then the caller is told to reconnect
    const token = await this.store.withGrantLock<string | null>(this.grantId, async (grant, { save, revoke }) => {
      if (!grant || grant.revokedAt) return null;
      const current = this.sealer.open(grant.upstreamAccessSealed);
      if (current !== staleAccess && grant.upstreamAccessExpiresAt - REFRESH_MARGIN_MS > Date.now()) return current;
      let next: UpstreamLogin;
      try {
        next = await this.auth.refresh(this.sealer.open(grant.upstreamRefreshSealed));
      } catch (error) {
        if (error instanceof ThreadOSError && error.status < 500) {
          await revoke();
          return null;
        }
        throw error;
      }
      await save({
        accessSealed: this.sealer.seal(next.accessToken),
        refreshSealed: this.sealer.seal(next.refreshToken),
        accessExpiresAt: Date.now() + next.expiresIn * 1000,
      });
      return next.accessToken;
    });
    if (token === null) throw new ConnectionLostError();
    return token;
  }
}
