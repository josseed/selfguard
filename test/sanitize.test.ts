import assert from "node:assert/strict";
import { test } from "node:test";
import { clean } from "../src/sanitize.ts";

test("strips terminal escapes and bidi overrides", () => {
  assert.equal(clean("evil\u001b]8;;http://x\u0007pkg\u001b[2J"), "evil]8;;http://xpkg[2J");
  assert.equal(clean("a‮b⁦c"), "abc");
  assert.equal(clean("line1\n  line2"), "line1 line2");
  assert.equal(clean("x".repeat(10), 5), "xxxx…");
});
