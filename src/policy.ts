/**
 * What the ThreadOS MCP may do, independent of who signs in.
 *
 * Three layers decide every call, and all three must agree:
 *  1. The OAuth scopes the person granted to this connection (read, or read + write drafts).
 *  2. The person's ThreadOS role and client assignments. The MCP calls the ThreadOS API with that person's own
 *     token, so the backend's permission checks and client restrictions apply exactly as in the app. The MCP
 *     also hides tools the role can't use, so the AI isn't offered actions that would only fail.
 *  3. This file: the fixed list of API calls the MCP is ever allowed to make. Approving, sending to a client,
 *     scheduling, publishing, deleting, payments, and team, role and settings changes aren't on it, so no tool,
 *     bug or prompt can reach them. Those stay with people, in ThreadOS. (Brian's brief: "drafts come back into
 *     ThreadOS for review, and it can never approve or publish.")
 */

export const SCOPE_READ = "threados:read";
export const SCOPE_WRITE = "threados:write";
export const SUPPORTED_SCOPES = [SCOPE_READ, SCOPE_WRITE];

export const SCOPE_LABELS: Record<string, string> = {
  [SCOPE_READ]: "Read the clients, strategy, knowledge and content you can already see in ThreadOS",
  [SCOPE_WRITE]: "Add notes and transcripts, propose strategy changes, and create or edit drafts for review. Nothing is approved, sent or published",
};

/** Scopes asked for in /authorize, limited to ones we know. Asking for nothing means asking for both. */
export function normalizeScopes(requested: string[] | undefined): string[] {
  const known = (requested ?? []).filter((s) => SUPPORTED_SCOPES.includes(s));
  const scopes = known.length ? known : [...SUPPORTED_SCOPES];
  // Writing always comes with reading
  if (scopes.includes(SCOPE_WRITE) && !scopes.includes(SCOPE_READ)) scopes.unshift(SCOPE_READ);
  return scopes;
}

const ID = "[0-9a-fA-F-]{36}";
type BodyCheck = (body: unknown) => string | null;

interface Route {
  method: "GET" | "POST" | "PATCH" | "PUT";
  path: RegExp;
  write: boolean;
  check?: BodyCheck;
}

const r = (method: Route["method"], path: string, write: boolean, check?: BodyCheck): Route => ({
  method, path: new RegExp(`^${path.replaceAll("{id}", ID)}$`), write, check,
});

function onlyKeys(allowed: string[]): BodyCheck {
  return (body) => {
    if (!body || typeof body !== "object") return null;
    const extra = Object.keys(body).filter((k) => !allowed.includes(k));
    return extra.length ? `fields not allowed from the MCP: ${extra.join(", ")}` : null;
  };
}

export const EPISODE_EDIT_FIELDS = ["title", "premise", "principle", "timely", "guest", "capture", "recordingDate", "showId"];
export const PIECE_EDIT_FIELDS = ["title", "body", "principle", "plannedFor", "owner", "hashtags"];

const ROUTES: Route[] = [
  // Who is signed in, and which clients they're assigned
  r("GET", "/users/me", false),
  r("GET", "/users/me/clients", false),

  // Team: reading
  r("GET", "/clients", false),
  r("GET", "/clients/{id}", false),
  r("GET", "/clients/{id}/waiting", false),
  r("GET", "/clients/{id}/brief", false),
  r("GET", "/clients/{id}/brief/changes", false),
  r("GET", "/clients/{id}/library", false),
  r("GET", "/library/{id}", false),
  r("GET", "/calls", false),
  r("GET", "/calls/{id}", false),
  r("POST", "/brain/ask", false),
  r("GET", "/clients/{id}/shows", false),
  r("GET", "/clients/{id}/episodes", false),
  r("GET", "/episodes/{id}", false),
  r("GET", "/clients/{id}/pieces", false),
  r("GET", "/pieces/{id}", false),

  // Team: writing. Each lands as a draft, a note or a proposal someone reviews in ThreadOS
  r("POST", "/clients/{id}/library/notes", true),
  r("POST", "/calls/paste", true),
  // Strategy changes are proposals (a change set) that a strategist or account manager accepts in ThreadOS.
  // Editing a section in place (PUT /brief/sections/…) isn't on this list.
  r("POST", "/clients/{id}/brief/instructions", true),
  r("POST", "/clients/{id}/brief/review", true),
  r("POST", "/clients/{id}/episodes", true),
  r("PATCH", "/episodes/{id}", true, onlyKeys(EPISODE_EDIT_FIELDS)),
  r("POST", "/episodes/{id}/brief", true, onlyKeys(["instruction", "links", "premise", "timely", "guests"])),
  r("POST", "/clients/{id}/pieces", true, onlyKeys(["channel", "title", "body", "plannedFor", "episodeId", "principle", "owner"])),
  r("PATCH", "/pieces/{id}", true, onlyKeys(PIECE_EDIT_FIELDS)),
  // Review: the MCP can hand a draft to internal review, never pass it, send it to the client or approve it
  r("POST", "/pieces/{id}/review", true, (body) =>
    (body as { action?: string } | null)?.action === "submit" ? null : "only 'submit' (send a draft to internal review) is allowed from the MCP"),
  r("POST", "/clients/{id}/content/create", true),

  // Client portal: reading their own workspace
  r("GET", "/portal/me", false),
  r("GET", "/portal/brief", false),
  r("GET", "/portal/episodes", false),
  r("GET", "/portal/calendar", false),
  r("GET", "/portal/reviews", false),
  r("GET", "/portal/approvals", false),
  // Client portal: writing. Ideas and stories to ThreadOS, comments on episode briefs. Approvals stay in the portal.
  r("POST", "/portal/assistant", true),
  r("POST", "/portal/episodes/{id}/comments", true),
];

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

/** Throws unless the call is on the list above (and, for writes, the connection has the write scope). */
export function assertCallAllowed(method: string, path: string, body: unknown, scopes: string[]): void {
  const pathname = path.split("?")[0]!;
  const route = ROUTES.find((rt) => rt.method === method.toUpperCase() && rt.path.test(pathname));
  if (!route) throw new PolicyError(`The ThreadOS MCP doesn't make this call (${method.toUpperCase()} ${pathname}). Do it in ThreadOS.`);
  if (route.write && !scopes.includes(SCOPE_WRITE)) {
    throw new PolicyError("This connection was granted read access only. Reconnect ThreadOS and allow drafts to make changes.");
  }
  if (!route.write && !scopes.includes(SCOPE_READ)) throw new PolicyError("This connection has no read access.");
  const problem = route.check?.(body);
  if (problem) throw new PolicyError(problem);
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Redirect URIs a self-registered client may use: https (limited to ALLOWED_REDIRECT_HOSTS when set), http only on
 * this machine, and the custom schemes desktop editors use. The consent page also shows where it will send you back.
 */
export function redirectUriAllowed(uri: string, opts: { extraSchemes: string[]; allowedHosts: string[] | null }): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.hash) return false;
  const scheme = url.protocol.replace(/:$/, "");
  if (scheme === "http") return LOOPBACK.has(url.hostname);
  if (scheme === "https") {
    if (!opts.allowedHosts) return true;
    return opts.allowedHosts.some((h) => url.hostname === h || url.hostname.endsWith(`.${h}`));
  }
  return opts.extraSchemes.includes(scheme);
}
