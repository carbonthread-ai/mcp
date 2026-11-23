import { z } from "zod";
import { FabricError } from "../fabric/api.js";
import { pickEach } from "./format.js";
import { defineTool, type ToolContext, type ToolDef } from "./registry.js";

/**
 * Tools for the Carbon Thread team. Each needs the Fabric permission it names; Fabric checks the same permission
 * and the person's client assignments again on every call. Writes create notes, drafts and proposals; approving,
 * sending to the client and publishing stay in Fabric.
 */

const clientId = z.string().uuid().describe("The client's Fabric id (from list_clients)");
const CHANNELS = ["youtube", "short", "reel", "tiktok", "linkedin", "instagram", "facebook", "x", "threads", "newsletter", "podcast", "carousel", "blog"] as const;
const CATEGORIES = ["discovery", "onboarding", "strategy", "production", "meeting", "brand", "report", "contract", "other"] as const;
const CALL_TYPES = ["discovery", "follow_up", "kickoff", "status", "other"] as const;
const DRAFT_STATUSES = new Set(["draft", "failed"]);

const link = (ctx: ToolContext, path: string) => `${ctx.appUrl}${path}`;

async function clientOf(ctx: ToolContext, path: string): Promise<any> {
  const item = await ctx.api.get(path);
  if (item?.clientId) ctx.assertClient(item.clientId);
  return item;
}

export const teamTools: ToolDef[] = [
  // ---------- Reading ----------
  defineTool({
    name: "list_clients",
    title: "List clients",
    description: "The clients you can see in Fabric (only your assigned clients if your role is limited to them), with status, tier and next step.",
    audience: "team", access: "read", permission: "client:view",
    input: {
      search: z.string().max(100).optional().describe("Part of a client's name"),
      status: z.array(z.string()).optional().describe("Only these statuses, e.g. prospect, onboarding, active"),
    },
    async run(ctx, args) {
      const rows = await ctx.api.get<any[]>("/clients", { search: args.search, status: args.status });
      return pickEach(rows, ["id", "name", "industry", "status", "tier", "nextStep", "oneLiner", "website"]);
    },
  }),
  defineTool({
    name: "get_client",
    title: "Get a client",
    description: "One client's record: contacts, offer, term, channels and current stage.",
    audience: "team", access: "read", permission: "client:view",
    input: { client_id: clientId },
    async run(ctx, { client_id }) {
      ctx.assertClient(client_id);
      return { ...(await ctx.api.get(`/clients/${client_id}`)), openInFabric: link(ctx, `/clients/${client_id}`) };
    },
  }),
  defineTool({
    name: "get_waiting_queue",
    title: "What's waiting on whom",
    description: "Everything waiting for this client: on the team (Needs us) and on the client (With client), oldest and most at-risk first.",
    audience: "team", access: "read", permission: "client:view",
    input: { client_id: clientId },
    async run(ctx, { client_id }) {
      ctx.assertClient(client_id);
      return ctx.api.get(`/clients/${client_id}/waiting`);
    },
  }),
  defineTool({
    name: "get_strategy",
    title: "Read the strategy brief",
    description: "The client's living strategy (brand, voice, ICPs, offer, programming, growth), section by section, with each section's version and how many changes are waiting on it.",
    audience: "team", access: "read", permission: "strategy:view",
    input: { client_id: clientId },
    async run(ctx, { client_id }) {
      ctx.assertClient(client_id);
      const brief = await ctx.api.get(`/clients/${client_id}/brief`);
      if (!brief) return "This client has no strategy brief yet.";
      return { ...brief, openInFabric: link(ctx, `/clients/${client_id}/brief`) };
    },
  }),
  defineTool({
    name: "list_strategy_proposals",
    title: "List proposed strategy changes",
    description: "Change sets proposed for the strategy brief (by Fabric, by the team or from this connection) and whether each is still open.",
    audience: "team", access: "read", permission: "strategy:view",
    input: { client_id: clientId, open_only: z.boolean().default(true) },
    async run(ctx, { client_id, open_only }) {
      ctx.assertClient(client_id);
      return ctx.api.get(`/clients/${client_id}/brief/changes`, { open_only });
    },
  }),
  defineTool({
    name: "search_knowledge",
    title: "Search the knowledge library",
    description: "The client's knowledge library: documents, notes, links, uploads and call transcripts, with a short excerpt of each. Search by words or filter by category.",
    audience: "team", access: "read", permission: "knowledge:view",
    input: {
      client_id: clientId,
      query: z.string().max(200).optional(),
      category: z.enum(CATEGORIES).optional(),
    },
    async run(ctx, { client_id, query, category }) {
      ctx.assertClient(client_id);
      const rows = await ctx.api.get<any[]>(`/clients/${client_id}/library`, { q: query, category });
      return pickEach(rows, ["id", "title", "category", "kind", "documentDate", "note", "excerpt", "url", "fromClient", "createdAt"]);
    },
  }),
  defineTool({
    name: "get_document",
    title: "Read a library document",
    description: "One document from a client's knowledge library, with its text and Fabric's digest of it.",
    audience: "team", access: "read", permission: "knowledge:view",
    input: { document_id: z.string().uuid() },
    async run(ctx, { document_id }) {
      return clientOf(ctx, `/library/${document_id}`);
    },
  }),
  defineTool({
    name: "list_calls",
    title: "List calls",
    description: "Recorded calls (Fathom and pasted transcripts) with their summaries, for one client or every client you can see.",
    audience: "team", access: "read", permission: "knowledge:view",
    input: { client_id: clientId.optional() },
    async run(ctx, { client_id }) {
      if (client_id) ctx.assertClient(client_id);
      const rows = await ctx.api.get<any[]>("/calls", { client_id });
      return pickEach(rows, ["id", "clientId", "type", "title", "occurredAt", "minutes", "status", "summary", "attendees"]);
    },
  }),
  defineTool({
    name: "get_call",
    title: "Read a call",
    description: "One call: summary, attendees and transcript.",
    audience: "team", access: "read", permission: "knowledge:view",
    input: { call_id: z.string().uuid() },
    async run(ctx, { call_id }) {
      return clientOf(ctx, `/calls/${call_id}`);
    },
  }),
  defineTool({
    name: "ask_brain",
    title: "Ask the Brain",
    description: "Ask Fabric's Brain a question about one client (strategy, calls, content, performance), across every client you can see, or about Fabric and the Method. It answers only from what you have access to.",
    audience: "team", access: "read", permission: "knowledge:view",
    input: {
      question: z.string().min(1).max(2000),
      client_id: clientId.optional().describe("Ask about this client only"),
    },
    async run(ctx, { question, client_id }) {
      if (client_id) ctx.assertClient(client_id);
      return ctx.api.post("/brain/ask", { question, clientId: client_id });
    },
  }),
  defineTool({
    name: "list_shows",
    title: "List shows",
    description: "The client's shows (podcast, docuseries, vlog, social show) with premise, audience, cadence and status.",
    audience: "team", access: "read", permission: "content:view",
    input: { client_id: clientId },
    async run(ctx, { client_id }) {
      ctx.assertClient(client_id);
      return ctx.api.get(`/clients/${client_id}/shows`);
    },
  }),
  defineTool({
    name: "list_episodes",
    title: "List episodes",
    description: "The client's episodes with stage (topic → brief → filming → editing → review → published), premise and guest.",
    audience: "team", access: "read", permission: "content:view",
    input: { client_id: clientId },
    async run(ctx, { client_id }) {
      ctx.assertClient(client_id);
      const rows = await ctx.api.get<any[]>(`/clients/${client_id}/episodes`);
      return pickEach(rows, ["id", "number", "title", "showName", "stage", "premise", "principle", "guest", "recordingDate", "briefStatus", "packageStatus"]);
    },
  }),
  defineTool({
    name: "get_episode",
    title: "Read an episode",
    description: "One episode: its brief and research, production details, clips and the pieces cut from it.",
    audience: "team", access: "read", permission: "content:view",
    input: { episode_id: z.string().uuid() },
    async run(ctx, { episode_id }) {
      const episode = await clientOf(ctx, `/episodes/${episode_id}`);
      return { ...episode, openInFabric: link(ctx, `/clients/${episode.clientId}/episodes/${episode_id}`) };
    },
  }),
  defineTool({
    name: "list_content",
    title: "List content pieces",
    description: "The client's content pieces (posts, shorts, newsletters, carousels…) with status (draft, internal_review, client_review, approved, scheduled, published), channel and planned date.",
    audience: "team", access: "read", permission: "content:view",
    input: {
      client_id: clientId,
      status: z.string().optional().describe("Only pieces in this status, e.g. draft"),
      channel: z.enum(CHANNELS).optional(),
    },
    async run(ctx, { client_id, status, channel }) {
      ctx.assertClient(client_id);
      const rows = (await ctx.api.get<any[]>(`/clients/${client_id}/pieces`))
        .filter((p) => (!status || p.status === status) && (!channel || p.channel === channel));
      return pickEach(rows, ["id", "channel", "form", "title", "status", "plannedFor", "episodeId", "principle", "owner", "round", "liveUrl"]);
    },
  }),
  defineTool({
    name: "get_content",
    title: "Read a content piece",
    description: "One content piece: its copy, review history and status.",
    audience: "team", access: "read", permission: "content:view",
    input: { piece_id: z.string().uuid() },
    async run(ctx, { piece_id }) {
      return clientOf(ctx, `/pieces/${piece_id}`);
    },
  }),

  // ---------- Writing: notes, transcripts, proposals and drafts ----------
  defineTool({
    name: "add_knowledge_note",
    title: "Add a note to the knowledge library",
    description: "Save a note (or a link) to the client's knowledge library, e.g. thinking worked out in this chat. Fabric reads it into the client's context; with an approved brief, the changes it suggests come back as a proposal to review.",
    audience: "team", access: "write", permission: "knowledge:create",
    input: {
      client_id: clientId,
      title: z.string().min(1).max(255),
      text: z.string().max(100_000).optional(),
      url: z.string().url().optional(),
      category: z.enum(CATEGORIES).default("other"),
    },
    async run(ctx, { client_id, title, text, url, category }) {
      ctx.assertClient(client_id);
      if (!text && !url) throw new FabricError(400, "Give the note some text or a link");
      const doc = await ctx.api.post(`/clients/${client_id}/library/notes`, { title, text, url, category });
      ctx.audit("knowledge.note_added", { clientId: client_id, documentId: doc?.id, title });
      return { saved: doc, openInFabric: link(ctx, `/clients/${client_id}/library`) };
    },
  }),
  defineTool({
    name: "add_call_transcript",
    title: "Add a call transcript",
    description: "Add a call that wasn't recorded in Fathom by pasting its transcript. Fabric summarises it and files it under the client.",
    audience: "team", access: "write", permission: "knowledge:create",
    input: {
      client_id: clientId,
      title: z.string().min(1).max(255),
      transcript: z.string().min(20),
      type: z.enum(CALL_TYPES).default("other"),
      occurred_at: z.string().datetime({ offset: true }).optional().describe("When the call happened (ISO 8601)"),
    },
    async run(ctx, { client_id, title, transcript, type, occurred_at }) {
      ctx.assertClient(client_id);
      const call = await ctx.api.post("/calls/paste", { clientId: client_id, title, transcript, type, occurredAt: occurred_at });
      ctx.audit("knowledge.call_added", { clientId: client_id, callId: call?.id, title });
      return call;
    },
  }),
  defineTool({
    name: "propose_strategy_change",
    title: "Propose a strategy change",
    description: "Describe a change to the client's strategy brief in plain words (e.g. 'Tighten the ICP to founders of 10-50 person firms'). Fabric drafts the edits as a proposal; nothing changes until someone who approves strategy accepts it in Fabric.",
    audience: "team", access: "write", permission: "strategy:edit",
    input: { client_id: clientId, instruction: z.string().min(5).max(8000) },
    async run(ctx, { client_id, instruction }) {
      ctx.assertClient(client_id);
      const set = await ctx.api.post(`/clients/${client_id}/brief/instructions`, { instruction });
      ctx.audit("strategy.change_proposed", { clientId: client_id, changeSetId: set?.id });
      return {
        proposal: set,
        note: "Proposed for review. Fabric is drafting the edits; they appear on the brief's review panel, where someone who approves strategy accepts or rejects each one.",
        openInFabric: link(ctx, `/clients/${client_id}/brief`),
      };
    },
  }),
  defineTool({
    name: "propose_strategy_from_notes",
    title: "Propose strategy changes from notes",
    description: "Hand Fabric a longer piece of material (a voice-note transcript, a working session from this chat, meeting notes). It's saved to the knowledge library, then Fabric reads it with the rest of the library and proposes brief edits for review.",
    audience: "team", access: "write", permission: "strategy:edit",
    input: { client_id: clientId, text: z.string().min(20).max(200_000) },
    async run(ctx, { client_id, text }) {
      ctx.assertClient(client_id);
      const set = await ctx.api.postForm(`/clients/${client_id}/brief/review`, { text });
      ctx.audit("strategy.review_started", { clientId: client_id, changeSetId: set?.id });
      return {
        proposal: set,
        note: "Saved to the library and sent for review. The proposed edits appear on the brief's review panel when Fabric finishes reading.",
        openInFabric: link(ctx, `/clients/${client_id}/brief`),
      };
    },
  }),
  defineTool({
    name: "create_episode",
    title: "Create an episode",
    description: "Add an episode (a topic) to the client's content plan, optionally under one of their shows.",
    audience: "team", access: "write", permission: "content:create",
    input: {
      client_id: clientId,
      title: z.string().min(1).max(255),
      show_id: z.string().uuid().optional(),
      premise: z.string().max(4000).optional(),
      principle: z.string().max(255).optional().describe("The client belief or principle the episode is about"),
      timely: z.string().max(1000).optional().describe("Why now"),
      guest: z.string().max(500).optional().describe("Guests, separated by semicolons"),
      recording_date: z.string().date().optional(),
    },
    async run(ctx, a) {
      ctx.assertClient(a.client_id);
      const episode = await ctx.api.post(`/clients/${a.client_id}/episodes`, {
        title: a.title, showId: a.show_id, premise: a.premise, principle: a.principle, timely: a.timely, guest: a.guest, recordingDate: a.recording_date,
      });
      ctx.audit("content.episode_created", { clientId: a.client_id, episodeId: episode?.id, title: a.title });
      return { episode, openInFabric: link(ctx, `/clients/${a.client_id}/episodes/${episode?.id}`) };
    },
  }),
  defineTool({
    name: "update_episode",
    title: "Edit an episode",
    description: "Change an episode's title, premise, principle, timely angle, guests or recording date. Its stage moves only in Fabric.",
    audience: "team", access: "write", permission: "content:edit",
    input: {
      episode_id: z.string().uuid(),
      title: z.string().min(1).max(255).optional(),
      premise: z.string().max(4000).optional(),
      principle: z.string().max(255).optional(),
      timely: z.string().max(1000).optional(),
      guest: z.string().max(500).optional(),
      recording_date: z.string().date().optional(),
    },
    async run(ctx, a) {
      await clientOf(ctx, `/episodes/${a.episode_id}`);
      const body = Object.fromEntries(Object.entries({
        title: a.title, premise: a.premise, principle: a.principle, timely: a.timely, guest: a.guest, recordingDate: a.recording_date,
      }).filter(([, v]) => v !== undefined));
      if (!Object.keys(body).length) throw new FabricError(400, "Nothing to change");
      const episode = await ctx.api.patch(`/episodes/${a.episode_id}`, body);
      ctx.audit("content.episode_edited", { clientId: episode?.clientId, episodeId: a.episode_id, fields: Object.keys(body) });
      return episode;
    },
  }),
  defineTool({
    name: "draft_episode_brief",
    title: "Draft an episode brief",
    description: "Start Fabric's research for an episode: it reads the strategy, calls and the links you give, and drafts the episode brief. The draft is approved and shared with the client in Fabric.",
    audience: "team", access: "write", permission: "content:create",
    input: {
      episode_id: z.string().uuid(),
      instruction: z.string().max(4000).optional().describe("What the research should focus on"),
      links: z.array(z.string().url()).max(5).optional().describe("Pages to read first (articles, the guest's profile, a video)"),
    },
    async run(ctx, { episode_id, instruction, links }) {
      const episode = await clientOf(ctx, `/episodes/${episode_id}`);
      const result = await ctx.api.post(`/episodes/${episode_id}/brief`, { instruction, links: links ?? [] });
      ctx.audit("content.episode_brief_started", { clientId: episode.clientId, episodeId: episode_id });
      return { started: result, note: "Research started. The brief appears on the episode as a draft in a few minutes.", openInFabric: link(ctx, `/clients/${episode.clientId}/episodes/${episode_id}`) };
    },
  }),
  defineTool({
    name: "create_content_draft",
    title: "Create a content draft",
    description: "Create a content piece as a draft (a LinkedIn post, a newsletter issue, a short's caption…), with copy written here. It goes through review in Fabric like any draft.",
    audience: "team", access: "write", permission: "content:create",
    input: {
      client_id: clientId,
      channel: z.enum(CHANNELS),
      title: z.string().min(1).max(300),
      body: z.string().max(50_000).optional(),
      planned_for: z.string().date().optional(),
      episode_id: z.string().uuid().optional().describe("The episode it's cut from, if any"),
      principle: z.string().max(255).optional(),
    },
    async run(ctx, a) {
      ctx.assertClient(a.client_id);
      const piece = await ctx.api.post(`/clients/${a.client_id}/pieces`, {
        channel: a.channel, title: a.title, body: a.body, plannedFor: a.planned_for, episodeId: a.episode_id, principle: a.principle,
      });
      ctx.audit("content.draft_created", { clientId: a.client_id, pieceId: piece?.id, channel: a.channel });
      return { draft: piece, openInFabric: link(ctx, `/clients/${a.client_id}/pieces`) };
    },
  }),
  defineTool({
    name: "update_content_draft",
    title: "Edit a content draft",
    description: "Change the copy of a piece that is still a draft (title, body, hashtags, planned date). Pieces already in review, approved, scheduled or published are changed in Fabric.",
    audience: "team", access: "write", permission: "content:edit",
    input: {
      piece_id: z.string().uuid(),
      title: z.string().min(1).max(300).optional(),
      body: z.string().max(50_000).optional(),
      hashtags: z.array(z.string()).max(60).optional(),
      planned_for: z.string().date().optional(),
      principle: z.string().max(255).optional(),
    },
    async run(ctx, a) {
      const piece = await clientOf(ctx, `/pieces/${a.piece_id}`);
      if (!DRAFT_STATUSES.has(piece.status)) {
        throw new FabricError(409, `This piece is in ${piece.status}, not a draft. Change it in Fabric, where its review history is.`);
      }
      const body = Object.fromEntries(Object.entries({
        title: a.title, body: a.body, hashtags: a.hashtags, plannedFor: a.planned_for, principle: a.principle,
      }).filter(([, v]) => v !== undefined));
      if (!Object.keys(body).length) throw new FabricError(400, "Nothing to change");
      const updated = await ctx.api.patch(`/pieces/${a.piece_id}`, body);
      ctx.audit("content.draft_edited", { clientId: piece.clientId, pieceId: a.piece_id, fields: Object.keys(body) });
      return updated;
    },
  }),
  defineTool({
    name: "submit_draft_for_review",
    title: "Send a draft to internal review",
    description: "Hand a finished draft to the team's internal review. Passing review, sending it to the client and approving it happen in Fabric.",
    audience: "team", access: "write", permission: "content:edit",
    input: { piece_id: z.string().uuid(), comment: z.string().max(2000).optional() },
    async run(ctx, { piece_id, comment }) {
      const piece = await clientOf(ctx, `/pieces/${piece_id}`);
      const updated = await ctx.api.post(`/pieces/${piece_id}/review`, { action: "submit", comment });
      ctx.audit("content.draft_submitted", { clientId: piece.clientId, pieceId: piece_id });
      return { piece: updated, openInFabric: link(ctx, `/clients/${piece.clientId}/pieces`) };
    },
  }),
  defineTool({
    name: "create_quick_posts",
    title: "Quick posts from a note",
    description: "Turn a note (an idea, a voice-memo transcript) and optional links into one draft per channel, written by Fabric with the client's skills and strategy. The drafts land in review.",
    audience: "team", access: "write", permission: "content:create",
    input: {
      client_id: clientId,
      note: z.string().min(1).max(20_000),
      channels: z.array(z.object({ channel: z.enum(CHANNELS), count: z.number().int().min(1).max(5).default(1) })).min(1).max(8),
      title: z.string().max(300).optional(),
      links: z.array(z.string().url()).max(10).optional(),
      planned_from: z.string().date().optional(),
    },
    async run(ctx, a) {
      ctx.assertClient(a.client_id);
      const drop = await ctx.api.postForm(`/clients/${a.client_id}/content/create`, {
        channels: JSON.stringify(a.channels), title: a.title, note: a.note, links: (a.links ?? []).join("\n"), plannedFrom: a.planned_from,
      });
      ctx.audit("content.quick_posts_started", { clientId: a.client_id, dropId: drop?.id, channels: a.channels.map((c: any) => c.channel) });
      return { drop, note: "Fabric is writing the drafts; they appear under the client's content in review.", openInFabric: link(ctx, `/clients/${a.client_id}/content`) };
    },
  }),
];
