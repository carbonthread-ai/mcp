import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { PolicyError, SCOPE_WRITE } from "../policy.js";
import { ConnectionLostError, ThreadOSError } from "../threados/api.js";
import { clientTools } from "./client.js";
import { toText } from "./format.js";
import { toolsFor, type ToolContext, type ToolDef } from "./registry.js";
import { teamTools } from "./team.js";

export const ALL_TOOLS: ToolDef[] = [...teamTools, ...clientTools];

const NEVER = "approve, send anything to a client, schedule, publish, delete, change payments, or change people, roles or settings";

function whoami(tools: ToolDef[]): ToolDef {
  return {
    name: "threados_whoami",
    title: "Who am I in ThreadOS",
    description: "Who this connection is signed in as, their ThreadOS role, which clients they can reach, and what this connection can and can't do.",
    audience: "team", access: "read", input: {},
    async run(ctx) {
      const { identity } = ctx;
      return {
        signedInAs: { name: identity.name, email: identity.email },
        role: identity.role.displayName,
        kind: identity.isClientLogin ? "client contact (portal)" : "Carbon Thread team",
        clients: identity.clientIds === null ? "every client" : identity.clientIds,
        permissions: [...identity.permissions].sort(),
        connection: ctx.scopes.includes(SCOPE_WRITE) ? "read and write drafts" : "read only",
        tools: tools.map((t) => t.name),
        neverFromHere: `This connection can't ${NEVER}. Those happen in ThreadOS (${ctx.appUrl}).`,
      };
    },
  };
}

function instructions(ctx: ToolContext): string {
  const who = ctx.identity.isClientLogin
    ? "You're connected to the person's own ThreadOS workspace with Carbon Thread (their client portal). You see only what the team has shared with them."
    : `You're connected to ThreadOS, Carbon Thread's operating system, as ${ctx.identity.name} (${ctx.identity.role.displayName}). You see only the clients and records their role allows.`;
  return [
    who,
    "Everything you write lands in ThreadOS as a note, a draft or a proposal that a person reviews there. Say so when you write something, and give the ThreadOS link from the result.",
    `You can't ${NEVER}. If asked, explain that it's done in ThreadOS and give the link.`,
    "Write from the client's stated strategy, voice and stories (read them first); don't invent beliefs or facts for a client.",
    "Ids come from the list tools (list_clients, list_episodes, list_content…). Don't guess them.",
  ].join("\n");
}

/** One MCP server per request, holding only the tools this person may use on this connection. */
export function buildMcpServer(ctx: ToolContext): McpServer {
  const visible = toolsFor(ALL_TOOLS, ctx.identity, ctx.scopes);
  const tools = [whoami(visible), ...visible];
  const server = new McpServer({ name: "threados", title: "ThreadOS", version: "0.1.0" }, { instructions: instructions(ctx) });

  for (const tool of tools) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.input,
        annotations: {
          title: tool.title,
          readOnlyHint: tool.access === "read",
          // Writes add or change drafts; nothing here deletes or publishes
          destructiveHint: false,
          idempotentHint: tool.access === "read",
          openWorldHint: false,
        },
      },
      async (args: Record<string, unknown>) => {
        try {
          for (const key of ["client_id"]) {
            if (typeof args?.[key] === "string") ctx.assertClient(args[key] as string);
          }
          const result = await tool.run(ctx, args ?? {});
          return { content: [{ type: "text" as const, text: toText(result ?? "Done.") }] };
        } catch (error) {
          return { isError: true, content: [{ type: "text" as const, text: describeError(error) }] };
        }
      },
    );
  }
  return server;
}

export function describeError(error: unknown): string {
  if (error instanceof PolicyError || error instanceof ConnectionLostError) return error.message;
  if (error instanceof ThreadOSError) {
    if (error.status === 403) return `ThreadOS refused: ${error.message}. Your role or client assignments don't allow this.`;
    if (error.status === 404) return `Not found in ThreadOS: ${error.message}`;
    return `ThreadOS: ${error.message}`;
  }
  console.error("tool error", error);
  return "Something went wrong talking to ThreadOS. Try again in a moment.";
}
