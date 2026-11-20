import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { before, test } from "node:test";
import type { SourceRecord } from "../src/sources/types.ts";

const FIXTURES = fileURLToPath(new URL("./fixtures/agents/", import.meta.url));
let home: string;
let sources: typeof import("../src/sources.ts");

before(async () => {
  home = realpathSync(mkdtempSync(join(tmpdir(), "sg-agents-user-")));
  process.env.HOME = home; // never the real home
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-agents-state-"));
  delete process.env.npm_config_cache; // npm sets it for scripts: it would point at the real cache
  sources = await import("../src/sources.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

function put(root: string, rel: string, fixture: string, replace: Record<string, string> = {}): void {
  let text = readFileSync(join(FIXTURES, fixture), "utf8");
  for (const [k, v] of Object.entries(replace)) text = text.replaceAll(k, v);
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), text);
}

function extract(scope: "machine" | "repo", root: string): SourceRecord {
  const { inventories } = sources.prepareSources([{ kind: "agents", target: scope === "machine" ? sources.machineTarget() : sources.repoTarget(root) }]);
  return inventories[0]!.record;
}

const summary = (rec: SourceRecord, base: string) =>
  rec.refs.map((r) => `${r.agent}|${r.server}|${r.launcher}|${r.ecosystem}:${r.name}@${r.version ?? `?${r.pin ?? ""}`}|${r.file.slice(base.length + 1)}:${r.line}`);

test("machine scope: every agent's file format, launchers, remote and local servers skipped", () => {
  put(home, ".claude.json", "claude-code.fixture.json", { "HOME/": `${home}/` });
  put(home, "Library/Application Support/Claude/claude_desktop_config.json", "claude-desktop.fixture.json");
  put(home, ".cursor/mcp.json", "cursor.fixture.json");
  put(home, ".config/Code/User/mcp.json", "vscode.fixture.json");
  put(home, ".codeium/windsurf/mcp_config.json", "windsurf.fixture.json");
  put(home, ".codex/config.toml", "codex.fixture.toml");
  put(home, ".gemini/settings.json", "gemini.fixture.json");
  const rec = extract("machine", home);
  assert.equal(rec.scope, "machine");
  assert.equal(rec.path, home);
  assert.deepEqual(summary(rec, home), [
    "Claude Code|filesystem|npx|npm:@modelcontextprotocol/server-filesystem@0.5.0|.claude.json:8",
    "Claude Code|fetch (project ~/code/app)|uvx|PyPI:mcp-server-fetch@2025.4.7|.claude.json:16",
    "Claude Desktop|memory|npx|npm:@modelcontextprotocol/server-memory@?|Library/Application Support/Claude/claude_desktop_config.json:3",
    "Cursor|context7|bunx|npm:@upstash/context7-mcp@1.0.14|.cursor/mcp.json:5",
    "Cursor|puppeteer|pnpm dlx|npm:@modelcontextprotocol/server-puppeteer@?latest|.cursor/mcp.json:6",
    "VS Code|yarn-one|yarn dlx|npm:mcp-yarn-tool@2.0.0|.config/Code/User/mcp.json:5",
    "VS Code|npm-exec|npm exec|npm:mcp-npm-exec@?^3.1.0|.config/Code/User/mcp.json:6",
    "Windsurf|abs-npx|npx|npm:mcp-abs@1.2.3|.codeium/windsurf/mcp_config.json:3",
    "Windsurf|pipx|pipx run|PyPI:mcp-pipx@0.3.1|.codeium/windsurf/mcp_config.json:4",
    "Codex|docs|npx|npm:mcp-docs-server@4.5.6|.codex/config.toml:5",
    "Codex|uv.tool|uvx|PyPI:mcp-uv-tool@1.0.0|.codex/config.toml:12",
    "Gemini CLI|uv-at|uvx|PyPI:mcp-gem@1.2.3|.gemini/settings.json:4",
    "Gemini CLI|pkg-eq|npx|npm:mcp-gem-npm@0.0.9|.gemini/settings.json:5",
  ]);
  // Remote: linear, cursor, vscode, windsurf, codex, gemini. Local: docker, node, python.
  assert.equal(rec.skipped, 9);
  const remote = rec.warnings.filter((w) => w.rule === "remote-mcp-server").map((w) => w.message);
  assert.deepEqual(remote, [
    'Remote MCP server "linear" (mcp.linear.app) not checked.',
    'Remote MCP server "remote" (mcp.example.com) not checked.',
    'Remote MCP server "remote" (api.example.com) not checked.',
    'Remote MCP server "remote" (windsurf.example.com) not checked.',
    'Remote MCP server "remote" (codex.example.com) not checked.',
    'Remote MCP server "remote" (gemini.example.com) not checked.',
  ]);
  const unpinned = rec.warnings.filter((w) => w.rule === "unpinned-mcp-server");
  assert.deepEqual(unpinned.map((w) => [w.severity, w.line, w.file.slice(home.length + 1)]), [
    ["moderate", 3, "Library/Application Support/Claude/claude_desktop_config.json"],
    ["moderate", 6, ".cursor/mcp.json"],
    ["moderate", 6, ".config/Code/User/mcp.json"],
  ]);
  assert.match(unpinned[0]!.message, /"memory" runs @modelcontextprotocol\/server-memory \(npx\) unpinned: whatever is latest at start-up\. Pin an exact version\./);
  assert.match(unpinned[1]!.message, /server-puppeteer@latest \(pnpm dlx\)/);
  // Unrelated data of ~/.claude.json never shows up.
  assert.doesNotMatch(JSON.stringify(rec), /someone@example\.com|numStartups|\/Users\/someone/);
});

test("repo scope: .mcp.json, .cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json only", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-agents-repo-")));
  put(root, ".mcp.json", "repo-mcp.fixture.json");
  put(root, ".cursor/mcp.json", "cursor.fixture.json");
  put(root, ".vscode/mcp.json", "vscode.fixture.json");
  put(root, ".gemini/settings.json", "gemini.fixture.json");
  put(root, ".codex/config.toml", "codex.fixture.toml"); // machine-wide only: not read here
  put(root, ".claude.json", "claude-code.fixture.json");
  const rec = extract("repo", root);
  // The agent guard reads .codex/config.toml in a repo for its settings, not for MCP servers.
  const mcpFiles = rec.files.filter((f) => f.by?.includes("mcp-servers"));
  assert.deepEqual([...new Set(mcpFiles.map((f) => f.path.slice(root.length + 1)))], [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json"]);
  assert.deepEqual(summary(rec, root).slice(0, 1), ["Claude Code|team-docs|npx|npm:team-docs-mcp@?|.mcp.json:3"]);
  assert.equal(rec.refs.length, 7);
  assert.equal(rec.skipped, 1 + 1 + 1 + 1, "github: spec, and one remote server in each of the three others");
  assert.doesNotMatch(JSON.stringify(rec), /acme\/private-mcp/);
});

test("malformed and odd files: a warning, never a crash or a quote of the file", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-agents-bad-")));
  put(root, ".mcp.json", "malformed.fixture.json");
  mkdirSync(join(root, ".cursor"));
  writeFileSync(join(root, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { a: "npx", b: null, c: { command: ["npx"] }, d: { command: "npx", args: "-y x" } } }));
  mkdirSync(join(root, ".vscode"));
  writeFileSync(join(root, ".vscode", "mcp.json"), "[1, 2]");
  mkdirSync(join(root, ".gemini"));
  writeFileSync(join(root, ".gemini", "settings.json"), JSON.stringify({ mcpServers: [1, 2] }));
  const rec = extract("repo", root);
  assert.deepEqual(rec.refs, []);
  assert.equal(rec.skipped, 4);
  assert.deepEqual(rec.warnings.map((w) => [w.rule, w.file.slice(root.length + 1)]), [
    ["unreadable-agent-config", ".mcp.json"],
    ["unreadable-agent-config", ".vscode/mcp.json"],
  ]);
  assert.doesNotMatch(JSON.stringify(rec), /MALFORMED_SECRET/);
  // Codex: malformed TOML.
  const h = realpathSync(mkdtempSync(join(tmpdir(), "sg-agents-toml-")));
  process.env.HOME = h;
  try {
    mkdirSync(join(h, ".codex"));
    writeFileSync(join(h, ".codex", "config.toml"), '[mcp_servers.x]\ncommand = "npx\nargs = ["TOML_SECRET"]\n');
    const t = extract("machine", h);
    assert.deepEqual(t.warnings.map((w) => w.rule), ["unreadable-agent-config"]);
    assert.doesNotMatch(JSON.stringify(t), /TOML_SECRET/);
  } finally {
    process.env.HOME = home;
  }
});

function npxEntry(cache: string, hash: string, specs: string[], name: string, version: string, lock = true): void {
  const dir = join(cache, "_npx", hash);
  mkdirSync(join(dir, "node_modules", ...name.split("/")), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { [name]: `^${version}` }, _npx: { packages: specs } }));
  if (lock) writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, [`node_modules/${name}`]: { version } } }));
  else writeFileSync(join(dir, "node_modules", ...name.split("/"), "package.json"), JSON.stringify({ name, version }));
}

test("npx cache: the version last run is kept apart, the reference stays unpinned (name-only query)", () => {
  const h = realpathSync(mkdtempSync(join(tmpdir(), "sg-agents-npx-")));
  process.env.HOME = h;
  try {
    const cache = join(h, ".npm");
    npxEntry(cache, "aaaa", ["@modelcontextprotocol/server-memory"], "@modelcontextprotocol/server-memory", "0.6.2");
    npxEntry(cache, "bbbb", ["@modelcontextprotocol/server-memory@0.1.0"], "@modelcontextprotocol/server-memory", "0.1.0");
    npxEntry(cache, "cccc", ["mcp-latest@latest"], "mcp-latest", "3.0.0", false);
    npxEntry(cache, "dddd", ["mcp-other@2"], "mcp-other", "2.5.0");
    mkdirSync(join(cache, "_npx", "junk"), { recursive: true });
    writeFileSync(join(cache, "_npx", "junk", "package.json"), "{not json");
    mkdirSync(join(h, ".cursor"));
    const servers = {
      memory: { command: "npx", args: ["-y", "@modelcontextprotocol/server-memory"] },
      latest: { command: "npx", args: ["-y", "mcp-latest@latest"] },
      other: { command: "npx", args: ["-y", "mcp-other"] }, // cached only as "mcp-other@2": another spec
      bunx: { command: "bunx", args: ["@modelcontextprotocol/server-memory"] }, // bunx has its own cache
    };
    writeFileSync(join(h, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: servers }, null, 2));
    const rec = extract("machine", h);
    assert.deepEqual(rec.refs.map((r) => [r.server, r.version, r.versionKind, r.unknownKind, r.lastRun ?? null]), [
      ["memory", null, "unknown", "tracks-latest", "0.6.2"],
      ["latest", null, "unknown", "tracks-latest", "3.0.0"],
      ["other", null, "unknown", "tracks-latest", null],
      ["bunx", null, "unknown", "tracks-latest", null],
    ]);
    const w = rec.warnings.filter((x) => x.rule === "unpinned-mcp-server");
    assert.equal(w.length, 4);
    assert.match(w[0]!.message, /Last run: 0\.6\.2\./);
    assert.match(w[1]!.message, /mcp-latest@latest .* Last run: 3\.0\.0\./);
    assert.doesNotMatch(w[2]!.message, /Last run/);
    assert.deepEqual(sources.queryFor(rec.refs[0]!), { name: "@modelcontextprotocol/server-memory", ecosystem: "npm" });
  } finally {
    process.env.HOME = home;
  }
});
