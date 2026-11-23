import { z } from "zod";
import { defineTool, type ToolDef } from "./registry.js";

/**
 * Tools for a client contact who connects Fabric to their own Claude or ChatGPT (Skills & AI › "Use Fabric inside
 * their AI"). They run on the portal API, so they see only their own workspace and only what the team has shared:
 * the approved strategy, episodes, the calendar and their review history. Carbon Thread's skill instructions,
 * internal notes and drafts in progress never reach them. They can send ideas, stories and comments into Fabric for
 * the team; approvals stay in the portal, where the person sees exactly what they're signing off.
 */

const clientIdArg = {
  client_id: z.string().uuid().optional().describe("Only if you're a contact on more than one Fabric workspace"),
};

const q = (a: { client_id?: string }) => ({ clientId: a.client_id });

export const clientTools: ToolDef[] = [
  defineTool({
    name: "get_my_workspace",
    title: "My Fabric workspace",
    description: "Your workspace with Carbon Thread: where onboarding stands, your proposal and what's coming up.",
    audience: "client", access: "read", permission: "portal:view",
    input: clientIdArg,
    async run(ctx, a) {
      return ctx.api.get("/portal/me", q(a));
    },
  }),
  defineTool({
    name: "get_my_strategy",
    title: "My strategy brief",
    description: "Your strategy brief as Carbon Thread last shared it: brand, voice, audience, offer and programming. Use it to keep anything you draft on-brand.",
    audience: "client", access: "read", permission: "portal:view",
    input: clientIdArg,
    async run(ctx, a) {
      return (await ctx.api.get("/portal/brief", q(a))) ?? "Your strategy brief hasn't been shared yet.";
    },
  }),
  defineTool({
    name: "list_my_episodes",
    title: "My episodes",
    description: "Your show's episodes with their premise, guest, the brief shared with you and the comments on it.",
    audience: "client", access: "read", permission: "portal:view",
    input: clientIdArg,
    async run(ctx, a) {
      return ctx.api.get("/portal/episodes", q(a));
    },
  }),
  defineTool({
    name: "get_my_calendar",
    title: "My content calendar",
    description: "Content going out between two dates, on the day it goes out.",
    audience: "client", access: "read", permission: "portal:view",
    input: { ...clientIdArg, start: z.string().date(), end: z.string().date() },
    async run(ctx, a) {
      return ctx.api.get("/portal/calendar", { ...q(a), start: a.start, end: a.end });
    },
  }),
  defineTool({
    name: "get_waiting_on_me",
    title: "What's waiting on me",
    description: "What Carbon Thread is waiting on you to review. Reviewing and approving happen in your Fabric portal; this lists them so you know what's there.",
    audience: "client", access: "read", permission: "portal:view",
    input: clientIdArg,
    async run(ctx, a) {
      const data = await ctx.api.get("/portal/approvals", q(a));
      return { ...data, note: `Approve or request changes in your portal: ${ctx.appUrl}/portal` };
    },
  }),
  defineTool({
    name: "get_my_review_history",
    title: "My review history",
    description: "Decisions your team made on pieces and email automations, newest first, with live links once published.",
    audience: "client", access: "read", permission: "portal:view",
    input: clientIdArg,
    async run(ctx, a) {
      return ctx.api.get("/portal/reviews", q(a));
    },
  }),
  defineTool({
    name: "share_with_fabric",
    aliases: ["share_with_threados"],
    title: "Share an idea or story with Fabric",
    description: "Send Fabric an idea, a story, a belief, a draft or an update (for example, something you worked out in this chat). Fabric saves what matters to your story bank and knowledge library and the Carbon Thread team reviews it before it shapes your content.",
    audience: "client", access: "write", permission: "portal:create",
    input: { ...clientIdArg, text: z.string().min(1).max(4000) },
    async run(ctx, a) {
      const reply = await ctx.api.request("POST", "/portal/assistant", { query: q(a), json: { text: a.text } });
      ctx.audit("portal.shared_with_fabric", { clientId: a.client_id ?? ctx.identity.clientIds?.[0], length: a.text.length });
      return reply;
    },
  }),
  defineTool({
    name: "comment_on_episode",
    title: "Comment on an episode brief",
    description: "Leave a comment on an episode's brief for the Carbon Thread team, e.g. notes on the guest or a point to cover.",
    audience: "client", access: "write", permission: "portal:create",
    input: { ...clientIdArg, episode_id: z.string().uuid(), text: z.string().min(1).max(2000) },
    async run(ctx, a) {
      const result = await ctx.api.request("POST", `/portal/episodes/${a.episode_id}/comments`, { query: q(a), json: { text: a.text } });
      ctx.audit("portal.episode_commented", { clientId: a.client_id ?? ctx.identity.clientIds?.[0], episodeId: a.episode_id });
      return result;
    },
  }),
];
