import type { ZodRawShape } from "zod";
import { SCOPE_READ, SCOPE_WRITE } from "../policy.js";
import type { ThreadOSClient } from "../threados/api.js";
import type { Identity } from "../threados/identity.js";

export interface ToolContext {
  api: ThreadOSClient;
  identity: Identity;
  scopes: string[];
  appUrl: string;
  /** 403 before calling ThreadOS when the person isn't assigned this client (ThreadOS checks again). */
  assertClient(clientId: string): void;
  audit(action: string, details: Record<string, unknown>): void;
}

export interface ToolDef {
  name: string;
  title: string;
  description: string;
  /** Team members (Carbon Thread) or client contacts (portal logins). Nobody sees both sets. */
  audience: "team" | "client";
  access: "read" | "write";
  /** The ThreadOS permission the call needs (resource:action). The tool is hidden from roles without it. */
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
