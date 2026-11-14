import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate, severityOf } from "../src/match.ts";
import type { OsvVuln } from "../src/osv.ts";

const vuln: OsvVuln = {
  id: "GHSA-test",
  database_specific: { severity: "HIGH" },
  affected: [
    {
      package: { ecosystem: "npm", name: "lodash" },
      ranges: [
        { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] },
        { type: "SEMVER", events: [{ introduced: "5.0.0-alpha" }, { last_affected: "5.0.0-beta.3" }] },
      ],
    },
  ],
};

test("evaluates introduced/fixed ranges and finds the fix", () => {
  assert.deepEqual(evaluate(vuln, "lodash", "4.17.20"), { affected: true, fixedIn: "4.17.21" });
  assert.deepEqual(evaluate(vuln, "lodash", "0.0.1-pre"), { affected: true, fixedIn: "4.17.21" });
  assert.deepEqual(evaluate(vuln, "lodash", "4.17.21"), { affected: false });
});

test("last_affected is inclusive", () => {
  assert.equal(evaluate(vuln, "lodash", "5.0.0-beta.3").affected, true);
  assert.equal(evaluate(vuln, "lodash", "5.0.0-beta.4").affected, false);
  assert.equal(evaluate(vuln, "lodash", "5.0.0").affected, false);
});

test("ignores other packages and ecosystems", () => {
  assert.equal(evaluate(vuln, "lodash-es", "4.0.0").affected, false);
  const pypi: OsvVuln = { id: "X", affected: [{ package: { ecosystem: "PyPI", name: "lodash" }, versions: ["1.0.0"] }] };
  assert.equal(evaluate(pypi, "lodash", "1.0.0").affected, false);
});

test("explicit versions list and malicious classification", () => {
  const mal: OsvVuln = {
    id: "MAL-2025-1",
    affected: [{ package: { ecosystem: "npm", name: "evil" }, versions: ["1.0.1"] }],
  };
  assert.equal(evaluate(mal, "evil", "1.0.1").affected, true);
  assert.equal(evaluate(mal, "evil", "1.0.0").affected, false);
  assert.equal(severityOf(mal), "malicious");
  assert.equal(severityOf(vuln), "high");
  assert.equal(severityOf({ id: "GHSA-x" }), "unknown");
});
