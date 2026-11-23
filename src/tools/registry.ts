import type { ZodRawShape } from "zod";
import { SCOPE_READ, SCOPE_WRITE } from "../policy.js";
import type { FabricClient } from "../fabric/api.js";
import type { Identity } from "../fabric/identity.js";

export interface ToolContext {
  api: FabricClient;
  identity: Identity;
  scopes: string[];
  appUrl: string;
  /** 403 before calling Fabric when the person isn't assigned this client (Fabric checks again). */
  assertClient(clientId: string): void;
  audit(action: string, details: Record<string, unknown>): void;
}

export interface ToolDef {
  name: string;
  /**
   * Old names still registered for this tool (marked deprecated), so connectors and saved setups made before the
   * ThreadOS to Fabric rename keep working. e.g. threados_whoami for fabric_whoami.
   */
  aliases?: string[];
  title: string;
  description: string;
  /** Team members (Carbon Thread) or client contacts (portal logins). Nobody sees both sets. */
  audience: "team" | "client";
  access: "read" | "write";
  /** The Fabric permission the call needs (resource:action). The tool is hidden from roles without it. */
  permission?: string;
  input: ZodRawShape;
  run(ctx: ToolContext, args: any): Promise<unknown>;
}

export function defineTool<T extends ToolDef>(def: T): T {
  return def;
}

/** The tools this person, on this connection, may use. */
export function toolsFor(all: ToolDef[], identity: Identity, scopes: string[]): ToolDef[] {
  const audience = identity.isClientLogin ? "client" : "team";
  return all.filter((tool) => {
    if (tool.audience !== audience) return false;
    if (!scopes.includes(tool.access === "write" ? SCOPE_WRITE : SCOPE_READ)) return false;
    return !tool.permission || identity.permissions.has(tool.permission);
  });
}
