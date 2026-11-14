import assert from "node:assert/strict";
import { test } from "node:test";
import { compare, isValid, parse } from "../src/semver.ts";

test("parses valid versions and rejects ranges/tags", () => {
  assert.deepEqual(parse("1.2.3-beta.1+build.5"), { major: 1, minor: 2, patch: 3, pre: ["beta", 1] });
  for (const bad of ["latest", "^1.2.3", "1.2", "01.2.3", "1.2.3.4", "", "x".repeat(300)]) {
    assert.equal(isValid(bad), false, bad);
  }
});

test("orders versions per SemVer 2.0 precedence", () => {
  const sorted = [
    "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
    "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0",
  ];
  for (let i = 0; i < sorted.length - 1; i++) {
    assert.equal(compare(sorted[i]!, sorted[i + 1]!), -1, `${sorted[i]} < ${sorted[i + 1]}`);
    assert.equal(compare(sorted[i + 1]!, sorted[i]!), 1);
  }
  assert.equal(compare("1.0.0+a", "1.0.0+b"), 0);
});
