// where (version-aware), forget (sources of the git root), line numbers in ~/.claude.json,
// and the file list handed from sourceInputs to the scan.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { startOsv } from "./sources-helpers.ts";

let server: Server;
let sources: typeof import("../src/sources.ts");
let api: typeof import("../src/api.ts");
let extract: typeof import("../src/sources/agents/extract.ts");
let configs: typeof import("../src/sources/agents/configs.ts");

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-user-")));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  sources = await import("../src/sources.ts");
  api = await import("../src/api.ts");
  extract = await import("../src/sources/agents/extract.ts");
  configs = await import("../src/sources/agents/configs.ts");
  sources.registerBuiltinExtractors(); // already done by the API's import
});
after(() => server.close());

function put(root: string, rel: string, text: string): string {
  const file = join(root, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text);
  return file;
}

function gitRepo(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-fix-")));
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
  return root;
}

function npmProject(dir: string): void {
  put(dir, "package.json", JSON.stringify({ name: "app", dependencies: { lodash: "4.17.21" } }));
  put(dir, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { lodash: "4.17.21" } }, "node_modules/lodash": { version: "4.17.21" } } }));
}

const WORKFLOW = "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v45.0.7\n      - uses: TJ-Actions/changed-files@v46.0.1\n";

test("where: a reference is vulnerable only when a finding matches its name and version", async () => {
  const root = gitRepo();
  put(root, ".github/workflows/ci.yml", WORKFLOW);
  const [o] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
  sources.saveSource(o!.record);
  const hit = api.whereUsed("tj-actions/changed-files").usedIn.find((u) => u.path === root)!;
  assert.deepEqual(
    hit.versions.map((v) => [v.version, v.vulnerable]),
    [["45.0.7", true], ["46.0.1", false]],
  );
});

test("forget: a repo's sources go with its last tracked project; --exclude too", async () => {
  const root = gitRepo();
  put(root, ".github/workflows/ci.yml", WORKFLOW);
  const a = join(root, "a");
  const b = join(root, "b");
  npmProject(a);
  npmProject(b);
  await api.scanPath(a);
  await api.scanPath(b);
  assert.ok(sources.loadSource("ci", "repo", root));

  api.forget(a, { exclude: false });
  assert.ok(sources.loadSource("ci", "repo", root), "b still lives in that git root");
  api.forget(b, { exclude: false });
  assert.equal(sources.loadSource("ci", "repo", root), null);

  const other = gitRepo();
  put(other, ".github/workflows/ci.yml", WORKFLOW);
  npmProject(join(other, "app"));
  await api.scanPath(join(other, "app"));
  assert.ok(sources.loadSource("ci", "repo", other));
  const r = api.forget(other); // exclude: drops the projects below and their sources
  assert.deepEqual(r.alsoForgotten, [join(other, "app")]);
  assert.equal(sources.loadSource("ci", "repo", other), null);
});

test("~/.claude.json: top-level servers get their own line, per-project ones theirs", () => {
  const home = process.env.HOME!;
  const text = [
    "{",
    '  "note": "\\"mcpServers\\": {\\"docs\\": 1}",', // 2: in a string
    '  "projects": {', // 3
    `    "${home}/app": {`, // 4
    '      "mcpServers": {', // 5
    '        "docs": { "command": "npx", "args": ["-y", "@acme/docs@1.0.0"] }', // 6
    "      }",
    "    }",
    "  },",
    '  "mcpServers": {', // 10
    '    "docs": {', // 11
    '      "command": "npx",',
    '      "args": ["-y", "@acme/docs@1.0.0"]', // 13
    "    }",
    "  }",
    "}",
  ].join("\n");
  const cfg = configs.AGENT_CONFIGS.find((c) => c.agent === "Claude Code" && c.scope === "machine")!;
  const res = extract.extractAgentConfig(cfg, text, { npxCache: () => new Map(), home });
  assert.deepEqual(res.refs.map((r) => [r.server, r.line]), [["docs", 13], ["docs (project ~/app)", 6]]);
});

test("the scan reads the files sourceInputs found, without walking again", async () => {
  const root = gitRepo();
  put(root, ".github/workflows/ci.yml", WORKFLOW);
  const [input] = sources.sourceInputs([root]).filter((i) => i.kind === "ci");
  assert.deepEqual([...input!.files!.keys()], [join(root, ".github", "workflows", "ci.yml")]);
  // An extractor whose files() would now fail: the list handed over is used.
  const [ex] = input!.files!.values().next().value!;
  const blind = { ...ex!, files: () => assert.fail("walked again") };
  const { inventories } = sources.prepareSources([{ ...input!, files: new Map([[join(root, ".github", "workflows", "ci.yml"), [blind]]]) }]);
  assert.equal(inventories[0]!.record.refs.length, 2);
});
