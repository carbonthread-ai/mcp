import type { FabricClient } from "./api.js";

export interface Identity {
  userId: string;
  email: string;
  name: string;
  role: { name: string; displayName: string };
  permissions: Set<string>;
  /** The role only sees clients the person is assigned to. */
  restrictedToAssigned: boolean;
  /** Client ids the person may touch; null = every client (roles not restricted to assigned clients). */
  clientIds: string[] | null;
  /** A client contact's portal login rather than a Carbon Thread team member. */
  isClientLogin: boolean;
}

const TTL_MS = 60_000;
const cache = new Map<string, { at: number; identity: Identity }>();

/**
 * Who the grant belongs to, read from Fabric (not from the token), so a role change, a removed client assignment
 * or a deactivated account takes effect within a minute, the same as it does in the app.
 */
export async function loadIdentity(grantId: string, api: FabricClient, { fresh = false } = {}): Promise<Identity> {
  const hit = cache.get(grantId);
  if (!fresh && hit && Date.now() - hit.at < TTL_MS) return hit.identity;
  const me = await api.get("/users/me");
  const permissions = new Set<string>(me.permissions ?? []);
  const restricted = Boolean(me.restrictToAssignedClients ?? me.restrict_to_assigned_clients ?? true);
  let clientIds: string[] | null = null;
  if (restricted) {
    const mine = await api.get("/users/me/clients");
    clientIds = ((mine.clientIds ?? mine.client_ids ?? []) as string[]).map(String);
  }
  const role = me.role ?? {};
  const identity: Identity = {
    userId: String(me.id),
    email: me.email,
    name: me.fullName ?? me.full_name ?? me.email,
    role: { name: role.name, displayName: role.displayName ?? role.display_name ?? role.name },
    permissions,
    restrictedToAssigned: restricted,
    clientIds,
    // Client logins hold only portal permissions; team routes never accept them
    isClientLogin: [...permissions].some((p) => p.startsWith("portal:")) && ![...permissions].some((p) => !p.startsWith("portal:")),
  };
  cache.set(grantId, { at: Date.now(), identity });
  return identity;
}

export function forgetIdentity(grantId: string): void {
  cache.delete(grantId);
}
