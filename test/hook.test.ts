import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { ZSH_HOOK } from "../src/hook.ts";
import { groupByPackage } from "../src/report.ts";
import type { Finding } from "../src/store.ts";

test("zsh hook is valid zsh syntax", { skip: !existsSync("/bin/zsh") }, () => {
  execFileSync("/bin/zsh", ["-n", "-c", ZSH_HOOK]);
  assert.ok(!ZSH_HOOK.includes("\\$"), "no stray escaped dollars");
});

test("groups advisories per package with a single upgrade target", () => {
  const base = { aliases: [], summary: "", direct: true, dev: false, firstSeen: "" };
  const f = (id: string, severity: Finding["severity"], fixedIn?: string): Finding => ({
    ...base, id, severity, name: "axios", version: "0.21.0", ...(fixedIn ? { fixedIn } : {}),
  });
  const [g] = groupByPackage([f("A", "moderate", "0.21.2"), f("B", "high", "0.30.0"), f("C", "low")]);
  assert.equal(g!.worst, "high");
  assert.equal(g!.upgradeTo, "0.30.0");
  assert.equal(g!.unfixed, 1);
});
