import { loadConfig } from "./config.js";
import { createApp } from "./server.js";
import { MemoryStore } from "./store/memory.js";
import { PostgresStore } from "./store/postgres.js";
import type { Store } from "./store/types.js";

const config = loadConfig();
let store: Store;
if (config.databaseUrl) {
  store = await PostgresStore.connect(config.databaseUrl);
} else {
  if (process.env.NODE_ENV === "production") throw new Error("DATABASE_URL is required in production");
  console.warn("DATABASE_URL not set: using the in-memory store (connections are lost on restart)");
  store = new MemoryStore();
}

const { app } = createApp(config, store);
const server = app.listen(config.port, () => {
  console.info(`ThreadOS MCP on :${config.port} · connector URL ${config.mcpUrl.href} · ThreadOS API ${config.threadosApiUrl}`);
});

const sweep = setInterval(() => store.sweep(Date.now()).catch((e) => console.error("sweep failed", e)), 10 * 60_000);

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    clearInterval(sweep);
    server.close(() => store.close().finally(() => process.exit(0)));
  });
}
