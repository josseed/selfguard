import assert from "node:assert/strict";
import { test } from "node:test";
import { parseJsonc, stripJsonc } from "../src/sources/agents/jsonc.ts";
import { parseLaunch } from "../src/sources/agents/launchers.ts";
import { parseNpmSpec, parsePySpec } from "../src/sources/agents/specs.ts";

/** "launcher ecosystem:name@version|pin" per package, or null. */
function launch(command: string, args: string[] = []): string[] | null {
  const l = parseLaunch(command, args);
  return l && l.packages.map((p) => `${l.launcher} ${p.ecosystem}:${p.name}@${p.version ?? `?${p.pin ?? ""}`}`);
}

test("npx: -y, --yes, -p/--package, --package=, --, absolute paths, one-string commands", () => {
  assert.deepEqual(launch("npx", ["-y", "@modelcontextprotocol/server-filesystem@0.5.0", "/tmp"]), ["npx npm:@modelcontextprotocol/server-filesystem@0.5.0"]);
  assert.deepEqual(launch("npx", ["--yes", "mcp-x@v1.2.3"]), ["npx npm:mcp-x@1.2.3"]);
  assert.deepEqual(launch("npx", ["-p", "a@1.0.0", "-p", "@s/b@2.0.0", "bin", "--flag"]), ["npx npm:a@1.0.0", "npx npm:@s/b@2.0.0"]);
  assert.deepEqual(launch("npx", ["--package", "a@1.0.0", "bin"]), ["npx npm:a@1.0.0"]);
  assert.deepEqual(launch("npx", ["--package=a@latest", "bin"]), ["npx npm:a@?latest"]);
  assert.deepEqual(launch("npx", ["--registry", "https://r.example", "-y", "a"]), ["npx npm:a@?"]);
  assert.deepEqual(launch("/opt/homebrew/bin/npx", ["-y", "a@1.0.0"]), ["npx npm:a@1.0.0"]);
  assert.deepEqual(launch("C:\\Program Files\\nodejs\\npx.cmd", ["-y", "a@1.0.0"]), ["npx npm:a@1.0.0"]);
  assert.deepEqual(launch("cmd", ["/c", "npx", "-y", "a@1.0.0"]), ["npx npm:a@1.0.0"]);
  assert.deepEqual(launch("npx -y a@1.0.0 --port 3"), ["npx npm:a@1.0.0"]);
  assert.deepEqual(launch("npx", ["-y", "--", "a@1.0.0"]), ["npx npm:a@1.0.0"]);
  // Flags after the package belong to the server and are ignored.
  assert.deepEqual(launch("npx", ["-y", "a@1.0.0", "-p", "b@9.9.9"]), ["npx npm:a@1.0.0"]);
  assert.equal(launch("npx", ["-c", "echo hi"]), null);
  assert.equal(launch("npx", ["-y"]), null);
});

test("bunx, bun x, pnpm dlx, pnpx, yarn dlx, npm exec / npm x", () => {
  assert.deepEqual(launch("bunx", ["@upstash/context7-mcp@1.0.14"]), ["bunx npm:@upstash/context7-mcp@1.0.14"]);
  assert.deepEqual(launch("bunx", ["--bun", "a"]), ["bunx npm:a@?"]);
  assert.deepEqual(launch("bun", ["x", "a@1.0.0"]), ["bunx npm:a@1.0.0"]);
  assert.deepEqual(launch("pnpm", ["dlx", "a@^1.0.0"]), ["pnpm dlx npm:a@?^1.0.0"]);
  assert.deepEqual(launch("pnpm", ["--silent", "dlx", "--package=b@2.0.0", "b-bin"]), ["pnpm dlx npm:b@2.0.0"]);
  assert.deepEqual(launch("pnpx", ["a@1.0.0"]), ["pnpm dlx npm:a@1.0.0"]);
  assert.deepEqual(launch("yarn", ["dlx", "-q", "-p", "a@1.0.0", "a"]), ["yarn dlx npm:a@1.0.0"]);
  assert.deepEqual(launch("npm", ["exec", "--yes", "--", "a@1.0.0"]), ["npm exec npm:a@1.0.0"]);
  assert.deepEqual(launch("npm", ["x", "--package=@s/a@3.0.0", "--", "a"]), ["npm exec npm:@s/a@3.0.0"]);
  assert.equal(launch("pnpm", ["exec", "a"]), null);
  assert.equal(launch("npm", ["run", "start"]), null);
  assert.equal(launch("yarn", ["start"]), null);
});

test("uvx, uv tool run, pipx run -> PyPI", () => {
  assert.deepEqual(launch("uvx", ["mcp-server-fetch"]), ["uvx PyPI:mcp-server-fetch@?"]);
  assert.deepEqual(launch("uvx", ["mcp-server-fetch==2025.4.7"]), ["uvx PyPI:mcp-server-fetch@2025.4.7"]);
  assert.deepEqual(launch("uvx", ["mcp-server-fetch@2025.4.7"]), ["uvx PyPI:mcp-server-fetch@2025.4.7"]);
  assert.deepEqual(launch("uvx", ["pkg@latest"]), ["uvx PyPI:pkg@?latest"]);
  assert.deepEqual(launch("uvx", ["--python", "3.12", "--from", "pkg[cli]==1.0.0", "pkg-cli"]), ["uvx PyPI:pkg@1.0.0"]);
  assert.deepEqual(launch("uvx", ["--from=pkg>=1.0", "pkg"]), ["uvx PyPI:pkg@?>=1.0"]);
  assert.deepEqual(launch("/Users/me/.local/bin/uvx", ["pkg==1.0.0"]), ["uvx PyPI:pkg@1.0.0"]);
  assert.deepEqual(launch("uv", ["tool", "run", "pkg==1.0.0"]), ["uvx PyPI:pkg@1.0.0"]);
  assert.deepEqual(launch("pipx", ["run", "--spec", "pkg==0.3.1", "pkg"]), ["pipx run PyPI:pkg@0.3.1"]);
  assert.deepEqual(launch("pipx", ["run", "pkg"]), ["pipx run PyPI:pkg@?"]);
  assert.equal(launch("uvx", ["--from", "git+https://github.com/acme/x", "x"]), null);
  assert.equal(launch("uv", ["run", "server.py"]), null);
});

test("docker, node, python, local binaries and junk are not launchers", () => {
  assert.equal(launch("docker", ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"]), null);
  assert.equal(launch("node", ["/Users/me/server/index.js"]), null);
  assert.equal(launch("python", ["/Users/me/server.py"]), null);
  assert.equal(launch("/usr/local/bin/my-mcp", ["--stdio"]), null);
  assert.equal(parseLaunch(undefined, ["-y", "a"]), null);
  assert.equal(parseLaunch(42, null), null);
  assert.deepEqual(parseLaunch("npx", ["-y", 7, "a@1.0.0"])?.packages.map((p) => p.name), ["a"]);
});

test("npm and PyPI specs: scoped names, exact versions, tags and ranges, non-registry specs rejected", () => {
  assert.deepEqual(parseNpmSpec("@scope/name@1.2.3-beta.1"), { ecosystem: "npm", name: "@scope/name", version: "1.2.3-beta.1", raw: "@scope/name@1.2.3-beta.1" });
  assert.equal(parseNpmSpec("@scope/name")?.version, null);
  assert.equal(parseNpmSpec("@scope/name@next")?.pin, "next");
  assert.equal(parseNpmSpec("name@1.2")?.pin, "1.2");
  assert.equal(parseNpmSpec("name@~1.2.3")?.version, null);
  for (const s of ["github:acme/x", "acme/x", "git+https://t@github.com/x.git", "https://x.example/a.tgz", "./local", "/abs/path", "file:../x", "npm:alias@1", "a@https://x", "@scope"]) {
    assert.equal(parseNpmSpec(s), null, s);
  }
  assert.deepEqual(parsePySpec("pkg[extra]==1.0.0")?.version, "1.0.0");
  assert.equal(parsePySpec("pkg==1.*")?.version, null);
  assert.equal(parsePySpec("pkg==1.*")?.pin, "==1.*");
  assert.equal(parsePySpec("pkg~=1.0")?.pin, "~=1.0");
  assert.equal(parsePySpec("pkg @ https://x.example/p.whl"), null);
  assert.equal(parsePySpec("./dist/pkg.whl"), null);
});

test("JSONC: comments and trailing commas, strings left alone, offsets kept", () => {
  const text = '{\n  // c\n  "a": "x // not a comment, ]", /* b */\n  "b": [1, 2,],\n}\n';
  assert.deepEqual(parseJsonc(text), { a: "x // not a comment, ]", b: [1, 2] });
  assert.equal(stripJsonc(text).length, text.length);
  assert.equal(stripJsonc(text).split("\n").length, text.split("\n").length);
  assert.deepEqual(parseJsonc('\uFEFF{"a":1}'), { a: 1 });
  assert.throws(() => parseJsonc('{"a": '));
  const proto = parseJsonc('{"__proto__": {"polluted": true}}') as Record<string, unknown>;
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.ok(Object.hasOwn(proto, "__proto__"));
});
