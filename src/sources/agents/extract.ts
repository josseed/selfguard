/**
 * One agent config file -> references to the packages its MCP servers run. Reads only the
 * server tables, and of each server only `command`, `args` (parsed for package specs) and
 * whether it is remote. Env, headers, URLs and other arguments are never copied anywhere:
 * remote servers yield at most their host, in a low warning.
 */
import { parseToml } from "../../lockfile/toml.ts";
import type { ExtractResult } from "../types.ts";
import type { AgentConfig } from "./configs.ts";
import { parseJsonc, stripJsonc } from "./jsonc.ts";
import { parseLaunch } from "./launchers.ts";
import { cachedVersion, type NpxCache } from "./npx-cache.ts";
import { jsonKeyOffset, lineAt, members, rootObject, specLine, tomlHeaderOffset, valueAt } from "./lines.ts";

const MAX_SERVERS = 500;
const MAX_PROJECTS = 2000;
const REMOTE_TYPES = new Set(["http", "sse", "streamable-http", "streamablehttp", "ws", "websocket"]);

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Obj) : null);

interface ServerTable {
  servers: Obj;
  /** Offset of the table's key in the text, to look for server lines after it. */
  from: number;
  /** JSON: offset of each server's key in the table (depth-aware). */
  keys: Map<string, number>;
  /** ~/.claude.json per-project entry: the project folder ("~/code/app"). */
  project?: string;
}

/** The host of a remote server's URL, nothing else (no credentials, path or query). */
function hostOf(def: Obj): string | null {
  for (const k of ["url", "httpUrl", "serverUrl"]) {
    const v = def[k];
    if (typeof v !== "string") continue;
    try {
      const host = new URL(v).hostname;
      return /^[A-Za-z0-9.:[\]-]{1,253}$/.test(host) ? host : null;
    } catch {
      return null;
    }
  }
  return null;
}

function isRemote(def: Obj): boolean {
  if (typeof def.command === "string" && def.command.trim()) return false;
  if (["url", "httpUrl", "serverUrl"].some((k) => typeof def[k] === "string")) return true;
  return typeof def.type === "string" && REMOTE_TYPES.has(def.type.toLowerCase());
}

/**
 * The server tables of a config, each with the offsets of its server keys. JSON offsets come
 * from a depth-aware walk of the text (comments blanked): the top-level `mcpServers`, and each
 * project's own `mcpServers` inside its entry, never a same-named key elsewhere.
 */
function tables(cfg: AgentConfig, data: Obj, text: string, home: string): ServerTable[] {
  const out: ServerTable[] = [];
  const json = cfg.format === "json" ? stripJsonc(text) : "";
  const root = json ? members(json, rootObject(json)) : new Map<string, number>();
  const keysOf = (keyOffset: number | undefined): Map<string, number> => members(json, valueAt(json, keyOffset));
  const top = obj(data[cfg.key]);
  if (top) out.push({ servers: top, from: Math.max(0, root.get(cfg.key) ?? 0), keys: keysOf(root.get(cfg.key)) });
  const projects = cfg.perProject ? obj(data.projects) : null;
  if (projects) {
    let byPath: Map<string, number> | null = null;
    for (const [path, p] of Object.entries(projects).slice(0, MAX_PROJECTS)) {
      const servers = obj(obj(p)?.mcpServers);
      if (!servers || Object.keys(servers).length === 0) continue;
      byPath ??= json ? keysOf(root.get("projects")) : new Map();
      const own = members(json, valueAt(json, byPath.get(path))).get("mcpServers");
      const project = path === home ? "~" : path.startsWith(`${home}/`) ? `~/${path.slice(home.length + 1)}` : path;
      out.push({ servers, from: Math.max(0, own ?? byPath.get(path) ?? 0), keys: keysOf(own), project });
    }
  }
  return out;
}

export interface ExtractDeps {
  /** The npx cache, read on first use (only for unpinned npx packages). */
  npxCache: () => NpxCache;
  /** The home folder, to shorten project paths. */
  home: string;
}

export function extractAgentConfig(cfg: AgentConfig, text: string, deps: ExtractDeps): ExtractResult {
  const res: ExtractResult = { refs: [], warnings: [], skipped: 0 };
  let data: Obj | null;
  try {
    data = obj(cfg.format === "toml" ? parseToml(text) : parseJsonc(text));
  } catch {
    data = null; // parser messages may quote the file: never pass them on
  }
  if (!data) {
    res.warnings.push({ rule: "unreadable-agent-config", message: `Could not parse this ${cfg.agent} config: its MCP servers were not checked.`, line: 0, severity: "low" });
    return res;
  }
  let count = 0;
  for (const table of tables(cfg, data, text, deps.home)) {
    for (const [name, raw] of Object.entries(table.servers)) {
      if (++count > MAX_SERVERS) return res;
      const server = table.project ? `${name} (project ${table.project})` : name;
      const at = cfg.format === "toml" ? tomlHeaderOffset(text, cfg.key, name) : (table.keys.get(name) ?? jsonKeyOffset(text, name, table.from));
      const line = lineAt(text, at);
      const def = obj(raw);
      if (!def) {
        res.skipped++;
        continue;
      }
      if (isRemote(def)) {
        res.skipped++;
        const host = hostOf(def);
        res.warnings.push({ rule: "remote-mcp-server", message: `Remote MCP server "${server}"${host ? ` (${host})` : ""} not checked.`, line, severity: "low" });
        continue;
      }
      const launch = parseLaunch(def.command, def.args);
      if (!launch || launch.ambiguous) {
        res.skipped++;
        // A package hidden behind an unknown option must not come out clean.
        if (launch) res.warnings.push({ rule: "unparsed-mcp-server", message: `MCP server "${server}" (${launch.launcher}): an option before the package makes it unclear what runs, so it was not checked.`, line, severity: "low" });
        continue;
      }
      for (const pkg of launch.packages) {
        // The npx cache tells what ran last time, not what runs next: the reference stays
        // unpinned (name-only query, so malicious advisories always apply).
        const lastRun = pkg.version === null && launch.launcher === "npx" && pkg.raw ? cachedVersion(deps.npxCache(), pkg.name, pkg.raw) : null;
        const ref: ExtractResult["refs"][number] = {
          ecosystem: pkg.ecosystem,
          name: pkg.name,
          version: pkg.version,
          versionKind: pkg.version ? "exact" : "unknown",
          line: (pkg.raw && specLine(text, pkg.raw, at)) || line,
          agent: cfg.agent,
          server,
          launcher: launch.launcher,
        };
        if (!pkg.version) ref.unknownKind = "tracks-latest";
        if (lastRun) ref.lastRun = lastRun;
        if (pkg.pin) ref.pin = pkg.pin;
        res.refs.push(ref);
        if (pkg.version !== null) continue;
        const as = pkg.pin ? `${pkg.name}${pkg.ecosystem === "PyPI" && /^[<>=!~]/.test(pkg.pin) ? "" : "@"}${pkg.pin}` : pkg.name;
        res.warnings.push({
          rule: "unpinned-mcp-server",
          message:
            `MCP server "${server}" runs ${as} (${launch.launcher}) unpinned: whatever is latest at start-up.` +
            `${lastRun ? ` Last run: ${lastRun}.` : ""} Pin an exact version.`,
          line: ref.line,
          severity: "moderate",
        });
      }
    }
  }
  return res;
}
