import assert from "node:assert/strict";
import { test } from "node:test";
import { agentsManaged } from "../src/schedule/launchd.ts";

// Only the pure guard is tested: calling the updaters here would touch this machine's real agents
// if the guard ever broke.
test("background agents are left alone on a custom SELFGUARD_HOME or with SELFGUARD_NO_LAUNCHD", () => {
  const saved = { home: process.env.SELFGUARD_HOME, off: process.env.SELFGUARD_NO_LAUNCHD };
  try {
    delete process.env.SELFGUARD_NO_LAUNCHD;
    delete process.env.SELFGUARD_HOME;
    assert.equal(agentsManaged(), true);
    process.env.SELFGUARD_HOME = "/tmp/scratch-state";
    assert.equal(agentsManaged(), false, "a dev build on scratch state must not repoint the real agents");
    process.env.SELFGUARD_HOME = "  ";
    assert.equal(agentsManaged(), true, "a blank SELFGUARD_HOME means the default state");
    delete process.env.SELFGUARD_HOME;
    process.env.SELFGUARD_NO_LAUNCHD = "1";
    assert.equal(agentsManaged(), false);
  } finally {
    for (const [k, v] of [["SELFGUARD_HOME", saved.home], ["SELFGUARD_NO_LAUNCHD", saved.off]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});
