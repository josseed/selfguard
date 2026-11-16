/**
 * Where each AI agent keeps its MCP servers. Data, so adding an agent or fixing a path is one
 * entry. Paths are relative to the target root: the home folder (scope "machine") or the git
 * root (scope "repo"). Missing files are ignored, so platform-specific paths are all listed.
 */
import type { SourceScope } from "../types.ts";

export interface AgentConfig {
  agent: string;
  scope: SourceScope;
  /** Relative to the target root, "/"-separated. */
  path: string;
  format: "json" | "toml";
  /** Key holding the server table: "mcpServers", "servers" (VS Code), "mcp_servers" (Codex). */
  key: string;
  /** ~/.claude.json: also `projects[<path>].mcpServers`. */
  perProject?: boolean;
}

const MAC_SUPPORT = "Library/Application Support";

export const AGENT_CONFIGS: readonly AgentConfig[] = [
  // Machine-wide.
  { agent: "Claude Code", scope: "machine", path: ".claude.json", format: "json", key: "mcpServers", perProject: true },
  { agent: "Claude Desktop", scope: "machine", path: `${MAC_SUPPORT}/Claude/claude_desktop_config.json`, format: "json", key: "mcpServers" },
  { agent: "Claude Desktop", scope: "machine", path: ".config/Claude/claude_desktop_config.json", format: "json", key: "mcpServers" },
  { agent: "Cursor", scope: "machine", path: ".cursor/mcp.json", format: "json", key: "mcpServers" },
  { agent: "VS Code", scope: "machine", path: `${MAC_SUPPORT}/Code/User/mcp.json`, format: "json", key: "servers" },
  { agent: "VS Code", scope: "machine", path: ".config/Code/User/mcp.json", format: "json", key: "servers" },
  { agent: "VS Code Insiders", scope: "machine", path: `${MAC_SUPPORT}/Code - Insiders/User/mcp.json`, format: "json", key: "servers" },
  { agent: "VS Code Insiders", scope: "machine", path: ".config/Code - Insiders/User/mcp.json", format: "json", key: "servers" },
  { agent: "Windsurf", scope: "machine", path: ".codeium/windsurf/mcp_config.json", format: "json", key: "mcpServers" },
  { agent: "Codex", scope: "machine", path: ".codex/config.toml", format: "toml", key: "mcp_servers" },
  { agent: "Gemini CLI", scope: "machine", path: ".gemini/settings.json", format: "json", key: "mcpServers" },
  // Per project (git root).
  { agent: "Claude Code", scope: "repo", path: ".mcp.json", format: "json", key: "mcpServers" },
  { agent: "Cursor", scope: "repo", path: ".cursor/mcp.json", format: "json", key: "mcpServers" },
  { agent: "VS Code", scope: "repo", path: ".vscode/mcp.json", format: "json", key: "servers" },
  { agent: "Gemini CLI", scope: "repo", path: ".gemini/settings.json", format: "json", key: "mcpServers" },
];

export const configsFor = (scope: SourceScope): AgentConfig[] => AGENT_CONFIGS.filter((c) => c.scope === scope);
