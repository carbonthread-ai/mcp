import express, { type Request, type Response } from "express";
import { rateLimit } from "express-rate-limit";
import type { Sealer } from "../crypto.js";
import { safeEqual } from "../crypto.js";
import { SCOPE_READ, SCOPE_WRITE } from "../policy.js";
import { ThreadOSError, type ThreadOSAuth } from "../threados/api.js";
import type { Store } from "../store/types.js";
import { renderMessage, renderSignIn, signInCsp } from "./pages.js";
import { CSRF_COOKIE, type ThreadOSOAuthProvider } from "./provider.js";

function cookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return undefined;
}

function signInMessage(error: unknown): string {
  if (error instanceof ThreadOSError) {
    if (error.status === 401 || error.status === 422) return "That email and password don't match a ThreadOS account.";
    if (error.status === 429) return error.message;
    if (error.status === 403) return error.message || "This ThreadOS account can't sign in.";
  }
  return "ThreadOS couldn't be reached. Try again in a moment.";
}

/** POST /oauth/sign-in: the form on the consent page. Signs in to ThreadOS as the person and finishes /authorize. */
export function signInRouter(deps: { store: Store; sealer: Sealer; upstream: ThreadOSAuth; provider: ThreadOSOAuthProvider; rateLimits: boolean }) {
  const router = express.Router();
  router.use(express.urlencoded({ extended: false, limit: "16kb" }));
  // On top of ThreadOS's own lockout after repeated wrong passwords
  if (deps.rateLimits) router.use("/oauth/sign-in", rateLimit({ windowMs: 15 * 60_000, limit: 30, standardHeaders: true, legacyHeaders: false }));

  router.post("/oauth/sign-in", async (req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    const { pending: pendingId, csrf, email, password, decision } = req.body ?? {};
    const pending = typeof pendingId === "string" ? await deps.store.getPending(pendingId) : undefined;
    const fromCookie = cookie(req, CSRF_COOKIE);
    if (!pending || pending.expiresAt < Date.now() || typeof csrf !== "string" || !fromCookie
      || !safeEqual(csrf, pending.csrf) || !safeEqual(fromCookie, pending.csrf)) {
      res.status(400).type("html").send(renderMessage("This sign-in expired", "Start connecting ThreadOS again from your AI app."));
      return;
    }
    res.setHeader("Content-Security-Policy", signInCsp(pending.redirectUri));
    const client = await deps.store.getClient(pending.clientId);
    if (!client) {
      res.status(400).type("html").send(renderMessage("Unknown app", "Start connecting ThreadOS again from your AI app."));
      return;
    }

    if (decision !== "allow") {
      await deps.store.takePending(pending.id);
      const url = new URL(pending.redirectUri);
      url.searchParams.set("error", "access_denied");
      url.searchParams.set("error_description", "The person cancelled connecting ThreadOS");
      if (pending.state) url.searchParams.set("state", pending.state);
      res.redirect(302, url.href);
      return;
    }

    const again = (error: string, status = 401) =>
      res.status(status).type("html").send(renderSignIn({
        pendingId: pending.id, csrf: pending.csrf, client, redirectUri: pending.redirectUri, scopes: pending.scopes,
        email: typeof email === "string" ? email : undefined, error,
      }));

    if (typeof email !== "string" || typeof password !== "string" || !email || !password) {
      again("Enter your email and password.", 400);
      return;
    }

    let login;
    try {
      login = await deps.upstream.login(email.trim(), password);
    } catch (error) {
      again(signInMessage(error), error instanceof ThreadOSError && error.status < 500 ? 401 : 502);
      return;
    }

    const scopes = [SCOPE_READ, ...(req.body.write === "1" ? [SCOPE_WRITE] : [])];
    try {
      const redirect = await deps.provider.completeAuthorization(pending.id, {
        userId: login.user.id,
        userEmail: login.user.email,
        scopes,
        upstreamAccessSealed: deps.sealer.seal(login.accessToken),
        upstreamRefreshSealed: deps.sealer.seal(login.refreshToken),
        upstreamAccessExpiresAt: Date.now() + login.expiresIn * 1000,
      });
      console.info(JSON.stringify({ at: new Date().toISOString(), event: "mcp.connected", userId: login.user.id, clientId: client.client_id, app: client.client_name, scopes }));
      res.redirect(302, redirect);
    } catch {
      await deps.upstream.logout(login.accessToken, login.refreshToken);
      res.status(400).type("html").send(renderMessage("This sign-in expired", "Start connecting ThreadOS again from your AI app."));
    }
  });

  return router;
}
