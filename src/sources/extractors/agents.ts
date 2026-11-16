/**
 * MCP servers of AI agents (kind "agents"): per-project configs (.mcp.json, .cursor/mcp.json…)
 * and machine-wide ones (~/.claude.json, Claude Desktop…). The agents and their paths are data
 * in sources/agents/configs.ts (see docs/ci-and-agent-tools.md). sources/builtin.ts registers
 * every entry.
 */
import { homedir } from "node:os";
import { join } from "node:path";
import { configsFor, type AgentConfig } from "../agents/configs.ts";
import { extractAgentConfig } from "../agents/extract.ts";
import { readNpxCache, type NpxCache } from "../agents/npx-cache.ts";
import type { SourceExtractor, SourceTarget } from "../types.ts";

const pathOf = (target: SourceTarget, cfg: AgentConfig): string => join(target.root, ...cfg.path.split("/"));

const candidates = (target: SourceTarget): string[] => [...new Set(configsFor(target.scope).map((c) => pathOf(target, c)))];

export const MCP_SERVERS: SourceExtractor = {
  id: "mcp-servers",
  kind: "agents",
  files: candidates,
  // Fixed paths, no walk: a config appearing or changing changes its own mtime.
  markers: candidates,
  probe: candidates,
  extract(file, text, target) {
    const cfg = configsFor(target.scope).find((c) => pathOf(target, c) === file);
    if (!cfg) return { refs: [], warnings: [], skipped: 0 };
    let cache: NpxCache | undefined;
    return extractAgentConfig(cfg, text, { npxCache: () => (cache ??= readNpxCache()), home: homedir() });
  },
};

export const AGENT_EXTRACTORS: SourceExtractor[] = [MCP_SERVERS];
