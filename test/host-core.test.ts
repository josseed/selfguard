// The "host" kind in the core: warning key/notify, store, labels and grouping keys, the API.
import assert from "node:assert/strict";
import { before, test } from "node:test";
import { freshHome, put } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");
let api: typeof import("../src/api.ts");
let news: typeof import("../src/sources/news.ts");

before(async () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  process.env.SELFGUARD_NO_NOTIFY = "1";
  sources = await import("../src/sources.ts");
  api = await import("../src/api.ts");
  news = await import("../src/sources/news.ts");
});

test("warnings keep a cleaned, short key and notify only when it is exactly true", () => {
  const { home } = freshHome();
  sources.resetSourceExtractors();
  sources.registerSourceExtractor({
    id: "fake-host",
    kind: "host",
    files: (t) => (t.scope === "machine" ? [`${t.root}/fake-host.json`] : []),
    markers: (t) => [`${t.root}/fake-host.json`],
    extract: (_f, text) => JSON.parse(text),
  });
  put(home, "fake-host.json", JSON.stringify({
    refs: [],
    skipped: 0,
    warnings: [
      { rule: "a", message: "m", severity: "low", key: `lab\u001b[31mel${"x".repeat(300)}`, notify: true },
      { rule: "b", message: "m", severity: "high", key: "  ", notify: "yes" },
      { rule: "c", message: "m", severity: "moderate", key: 42 },
    ],
  }));
  const { inventories } = sources.prepareSources([{ kind: "host", target: sources.machineTarget() }]);
  const [a, b, c] = inventories[0]!.record.warnings;
  assert.equal(a!.notify, true);
  assert.ok(a!.key!.startsWith("lab[31mel") && a!.key!.length <= 120, "control characters stripped, length capped");
  assert.deepEqual([b!.key, b!.notify, c!.key, c!.notify], [undefined, undefined, undefined, undefined]);
  sources.resetSourceExtractors();
});

test("host records: stored and listed, per-kind machine keys and labels, in the API's machine list", () => {
  const { home } = freshHome();
  const rec = {
    schema: 1 as const, kind: "host" as const, scope: "machine" as const, path: home, registeredAt: "2026-01-01T00:00:00Z",
    scannedAt: "2026-01-01T00:00:00Z", files: [], refs: [], findings: [], skipped: 0,
    warnings: [{ rule: "launch-item", message: "Starts at login", file: `${home}/Library/LaunchAgents/x.plist`, line: 0, severity: "low" as const, key: "x", notify: true }],
  };
  sources.saveSource(rec);
  sources.saveSource({ ...rec, kind: "agents", warnings: [] });
  assert.equal(sources.loadSource("host", "machine", home)?.warnings[0]!.key, "x");
  assert.deepEqual(sources.listSources({ kind: "host" }).map((r) => r.kind), ["host"]);
  const label = news.sourceLabel(rec);
  assert.deepEqual([label.key, label.label, label.branch], ["sources:host:machine", "This machine", null]);
  assert.equal(news.sourceLabel({ ...rec, kind: "agents" }).key, news.MACHINE_AGENTS_KEY);
  assert.equal(news.MACHINE_AGENTS_KEY, "sources:agents:machine", "unchanged for existing state");
  assert.equal(news.KIND_LABEL.host, "this machine");
  const all = api.getSources();
  const host = all.machine.find((s) => s.kind === "host")!;
  assert.deepEqual([host.label, host.repoKey, host.warnings[0]!.notify], ["This machine", null, true]);
  assert.ok(all.machine.some((s) => s.kind === "agents"));
});
