// Property-based fuzzing with fast-check (complements the mutation fuzzer in fuzz.test.ts):
// arbitrary text never makes a parser throw anything but a parse error, and text shown to the
// user never carries control or bidi characters.
import assert from "node:assert/strict";
import { test } from "node:test";
import fc from "fast-check";
import { parseGoMod } from "../src/lockfile/gomod.ts";
import { parseToml } from "../src/lockfile/toml.ts";
import { clean } from "../src/sanitize.ts";

const RUNS = Number(process.env.SELFGUARD_FUZZ_ITERATIONS ?? 300);
const text = fc.string({ unit: "binary", maxLength: 2000 });

/** Parse errors are expected; anything else (TypeError, RangeError, stack overflow) is a bug. */
function onlyParseErrors(parse: (s: string) => unknown): (s: string) => void {
  return (s) => {
    try {
      parse(s);
    } catch (e) {
      assert.ok(e instanceof Error && !(e instanceof TypeError) && !(e instanceof RangeError), String(e));
    }
  };
}

test("property: go.mod and TOML parsers only ever throw parse errors", () => {
  fc.assert(fc.property(text, onlyParseErrors(parseGoMod)), { numRuns: RUNS });
  fc.assert(fc.property(text, onlyParseErrors(parseToml)), { numRuns: RUNS });
});

test("property: clean() output is bounded and free of control and bidi characters", () => {
  const bad = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩]/;
  fc.assert(
    fc.property(text, fc.integer({ min: 1, max: 500 }), fc.boolean(), (s, max, multiline) => {
      const out = clean(s, max, { multiline });
      assert.ok(out.length <= max + 1, `${out.length} > ${max}`);
      assert.doesNotMatch(out, bad);
      if (!multiline) assert.doesNotMatch(out, /\n/);
    }),
    { numRuns: RUNS },
  );
});
