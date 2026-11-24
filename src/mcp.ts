/**
 * Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0), no dependencies.
 * Lets AI assistants (Claude Code, Cursor, …) query and manage selfguard.
 *
 * Safety: no tool executes project code or package managers. Advisory text and package
 * names are third-party data; tool descriptions tell the model to treat them as such.
 */
import { createInterface } from "node:readline";
import * as api from "./api.ts";
import { GUIDE } from "./guide.ts";
import { TOOLS } from "./mcp/tools.ts";
import { presented } from "./mcp/untrusted.ts";
import { VERSION } from "./version.ts";

export { TOOLS } from "./mcp/tools.ts";

const KNOWN_PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

type Json = Record<string, unknown>;

function reply(id: unknown, result: unknown): void {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}
function replyError(id: unknown, code: number, message: string): void {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code, message } })}\n`);
}

async function handle(msg: Json): Promise<void> {
  const { id, method } = msg;
  const params = (msg.params && typeof msg.params === "object" ? msg.params : {}) as Json;
  const isRequest = id !== undefined && id !== null;

  switch (method) {
    case "initialize": {
      const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : "";
      reply(id, {
        protocolVersion: KNOWN_PROTOCOLS.includes(requested) ? requested : KNOWN_PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "selfguard", title: "selfguard", version: VERSION },
        instructions: GUIDE,
      });
      return;
    }
    case "ping":
      reply(id, {});
      return;
    case "tools/list":
      reply(id, {
        tools: TOOLS.map(({ run: _run, ...t }) => t),
      });
      return;
    case "tools/call": {
      const tool = TOOLS.find((t) => t.name === params.name);
      if (!tool) {
        replyError(id, -32602, `unknown tool: ${String(params.name)}`);
        return;
      }
      const args = (params.arguments && typeof params.arguments === "object" ? params.arguments : {}) as Json;
      try {
        const data = presented(await tool.run(args));
        reply(id, {
          content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
          structuredContent: data,
          isError: false,
        });
      } catch (e) {
        const code = e instanceof api.ApiError ? e.code : "error";
        const message = e instanceof Error ? e.message : String(e);
        reply(id, { content: [{ type: "text", text: JSON.stringify({ error: { code, message } }) }], isError: true });
      }
      return;
    }
    default:
      if (isRequest) replyError(id, -32601, `method not found: ${String(method)}`);
  }
}

export function runMcpServer(): Promise<void> {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const pending = new Set<Promise<void>>();
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      replyError(null, -32700, "parse error");
      return;
    }
    const msgs = Array.isArray(msg) ? msg : [msg];
    for (const m of msgs) {
      if (!m || typeof m !== "object") continue;
      const p = handle(m as Json).catch((e) => replyError((m as Json).id, -32603, String(e)));
      pending.add(p);
      p.finally(() => pending.delete(p));
    }
  });
  return new Promise((resolve) => rl.on("close", () => Promise.all(pending).then(() => resolve())));
}
