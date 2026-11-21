// Editor extensions: denylist, sideloaded, one low entry per extension, hidden Unicode in entry points.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";
import { freshHome, put, scanHost, summary } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");
let deny: typeof import("../src/sources/host/extensions-editor-denylist.ts");

before(async () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  deny = await import("../src/sources/host/extensions-editor-denylist.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

/** One extensions.json entry the way VS Code writes it. */
const entry = (id: string, version: string, source = "gallery", extra: Record<string, unknown> = {}) => ({
  identifier: { id },
  version,
  relativeLocation: `${id}-${version}`,
  metadata: { source, isBuiltin: false },
  ...extra,
});

/** A GlassWorm-style payload: bytes as variation selectors. */
const payload = (s: string) => [...Buffer.from(s)].map((b) => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)).join("");

function install(home: string, editor: string, list: unknown[], code: Record<string, string> = {}) {
  put(home, `${editor}/extensions/extensions.json`, JSON.stringify(list));
  for (const [folder, js] of Object.entries(code)) {
    put(home, `${editor}/extensions/${folder}/package.json`, JSON.stringify({ main: "./out/ext.js" }));
    put(home, `${editor}/extensions/${folder}/out/ext.js`, js);
  }
}

test("denylist: ids are lower-case with a version list or null; matching ignores case", () => {
  assert.ok(deny.DENYLIST.size >= 40);
  for (const [id, e] of deny.DENYLIST) {
    assert.match(id, /^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$/);
    assert.ok(e.versions === null || e.versions.length > 0);
  }
  assert.ok(deny.deniedExtension("NRWL.angular-console", "18.95.0"));
  assert.ok(!deny.deniedExtension("nrwl.angular-console", "18.100.0"));
  assert.ok(deny.deniedExtension("SmartContractAI.solaibot", "0.0.1"));
});

test("every extension is a low N warning; malicious ones high and urgent; sideloaded moderate", () => {
  const { home } = freshHome();
  install(home, ".vscode", [
    entry("esbenp.prettier-vscode", "11.0.0"),
    entry("SmartContractAI.solaibot", "1.0.0"),
    entry("nrwl.angular-console", "18.95.0"),
    entry("me.local-tool", "0.1.0", "vsix"),
    entry("ms.builtin", "1.0.0", "gallery", { metadata: { isBuiltin: true, source: "gallery" } }),
  ]);
  install(home, ".cursor", [entry("esbenp.prettier-vscode", "11.0.0"), entry("nrwl.angular-console", "18.100.0")]);
  const rec = scanHost(sources, sources.machineTarget());
  const got = summary(rec).filter((s) => /extension|prettier|solaibot|angular|local-tool/.test(s));
  assert.deepEqual(
    got.sort(),
    [
      "high malicious-extension nrwl.angular-console @extensions.json:0 N",
      "high malicious-extension smartcontractai.solaibot @extensions.json:0 N",
      "low editor-extension esbenp.prettier-vscode @extensions.json:0 N",
      "low editor-extension esbenp.prettier-vscode @extensions.json:0 N",
      "low editor-extension me.local-tool @extensions.json:0 N",
      "low editor-extension nrwl.angular-console @extensions.json:0 N",
      "low editor-extension nrwl.angular-console @extensions.json:0 N",
      "low editor-extension smartcontractai.solaibot @extensions.json:0 N",
      "moderate sideloaded-extension me.local-tool @extensions.json:0 N",
    ].sort(),
  );
  const bad = rec.warnings.filter((w) => w.rule === "malicious-extension");
  assert.ok(bad.length === 2 && bad.every((w) => w.urgent === true));
  assert.match(bad[0]!.message, /in (VS Code|Cursor)\b/);
  assert.ok(rec.markers!.some((m) => m.path === join(home, ".vscode", "extensions") && m.mtimeMs !== null));
});

test("a new extension after the baseline is news; the first scan is silent", () => {
  const { home } = freshHome();
  install(home, ".vscode", [entry("a.one", "1.0.0")]);
  const first = scanHost(sources, sources.machineTarget());
  assert.equal(sources.diffWarnings(first, null, "2026-01-01T00:00:00Z", "x").newWarnings.length, 0);
  install(home, ".vscode", [entry("a.one", "2.0.0"), entry("b.two", "1.0.0")]);
  const second = scanHost(sources, sources.machineTarget());
  const previous = { ...first, scannedAt: "2026-01-01T00:00:00Z", warningsBy: "x" };
  const diff = sources.diffWarnings(second, previous, "2026-01-02T00:00:00Z", "x");
  assert.deepEqual(diff.newWarnings.map((w) => w.key), ["b.two"]);
});

test("hidden Unicode in the entry point is high and urgent; ordinary code and emoji are clean", () => {
  const { home } = freshHome();
  const evil = `const s = '${payload("eval(atob('AAAA'))")}';\neval(s);`;
  install(home, ".vscode", [entry("bad.glass", "1.0.0"), entry("good.emoji", "1.0.0"), entry("good.plain", "1.0.0")], {
    "bad.glass-1.0.0": evil,
    "good.emoji-1.0.0": "const a = '❤️ \u{1f468}‍\u{1f4bb}';",
    "good.plain-1.0.0": "module.exports = {};",
  });
  const rec = scanHost(sources, sources.machineTarget());
  const hidden = rec.warnings.filter((w) => w.rule === "hidden-unicode");
  assert.equal(hidden.length, 1);
  assert.equal(hidden[0]!.key, "bad.glass");
  assert.equal(hidden[0]!.severity, "high");
  assert.equal(hidden[0]!.urgent, true);
  assert.doesNotMatch(JSON.stringify(rec), /atob|eval/);
});

test("entry points are read only inside the extension folder, as regular files", () => {
  const { home } = freshHome();
  const outside = mkdtempSync(join(tmpdir(), "sg-ext-out-"));
  const evil = `x='${payload("eval(atob('AAAA'))")}'`;
  writeFileSync(join(outside, "secret.js"), evil);
  const ext = join(home, ".vscode", "extensions");
  install(home, ".vscode", ["t.trav", "t.link", "t.abs", "t.dir", "t.big"].map((id) => entry(id, "1.0.0")));
  put(home, ".vscode/extensions/t.trav-1.0.0/package.json", JSON.stringify({ main: `../../../../../..${outside}/secret.js` }));
  mkdirSync(join(ext, "t.link-1.0.0"), { recursive: true });
  writeFileSync(join(ext, "t.link-1.0.0", "package.json"), JSON.stringify({ main: "./ext.js" }));
  symlinkSync(join(outside, "secret.js"), join(ext, "t.link-1.0.0", "ext.js"));
  put(home, ".vscode/extensions/t.abs-1.0.0/package.json", JSON.stringify({ main: join(outside, "secret.js") }));
  put(home, ".vscode/extensions/t.dir-1.0.0/package.json", JSON.stringify({ main: "./sub" }));
  mkdirSync(join(ext, "t.dir-1.0.0", "sub"));
  put(home, ".vscode/extensions/t.big-1.0.0/package.json", JSON.stringify({ main: "./b.js" }));
  put(home, ".vscode/extensions/t.big-1.0.0/b.js", evil + " ".repeat(5 * 1024 * 1024));
  const rec = scanHost(sources, sources.machineTarget());
  // t.big is padded past 5 MB after the payload: the first 5 MB are still read (see host-hardening).
  assert.deepEqual(rec.warnings.filter((w) => w.rule === "hidden-unicode").map((w) => w.key), ["t.big"]);
  assert.equal(rec.warnings.filter((w) => w.rule === "editor-extension").length, 5);
});

test("hostile ids, versions, folders and malformed files never throw or reach messages", () => {
  const { home } = freshHome();
  install(home, ".vscode", [
    entry("evil\u001b]8;;http://x.example\u0007.ext", "1.0.0"),
    entry("ok.name", "1.0.0\u001b[31m"),
    { identifier: { id: "ok.folder" }, version: "1.0.0", relativeLocation: "../../etc", metadata: null },
    { identifier: "nope" },
    null,
    7,
    entry(`${"x".repeat(500)}.y`, "1"),
  ]);
  put(home, ".cursor/extensions/extensions.json", "{not json");
  put(home, ".windsurf/extensions/extensions.json", '{"a":1}');
  put(home, ".vscode-oss/extensions/extensions.json", "");
  const rec = scanHost(sources, sources.machineTarget());
  const exts = rec.warnings.filter((w) => w.rule === "editor-extension");
  assert.deepEqual(exts.map((w) => w.key).sort(), ["ok.folder", "ok.name"]);
  assert.doesNotMatch(JSON.stringify(rec.warnings), /u001b|x\.example/);
  assert.match(exts.find((w) => w.key === "ok.name")!.message, /"ok\.name" unknown in VS Code/);
});

test("repo scope: editor extensions are machine-wide only", () => {
  const { home } = freshHome();
  install(home, ".vscode", [entry("a.one", "1.0.0")]);
  assert.equal(sources.filesFor("host", sources.repoTarget(home)).has(join(home, ".vscode", "extensions", "extensions.json")), false);
});

test("a long list is capped and the messages never show paths", () => {
  const { home } = freshHome();
  install(home, ".vscode", Array.from({ length: 600 }, (_, i) => entry(`pub.ext${i}`, "1.0.0")));
  const rec = scanHost(sources, sources.machineTarget());
  assert.equal(rec.warnings.filter((w) => w.rule === "editor-extension").length, 400);
  assert.doesNotMatch(rec.warnings.map((w) => w.message).join("\n"), /\/extensions|tmp|\.vscode/);
});
