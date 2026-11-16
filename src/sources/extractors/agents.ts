/**
 * MCP servers of AI agents (kind "agents"): per-project configs (.mcp.json, .cursor/mcp.json…)
 * and machine-wide ones (~/.claude.json, Claude Desktop…). Not implemented yet: the list stays
 * empty until the extractor lands (see docs/ci-and-agent-tools.md). sources/builtin.ts
 * registers every entry.
 */
import type { SourceExtractor } from "../types.ts";

export const AGENT_EXTRACTORS: SourceExtractor[] = [];
