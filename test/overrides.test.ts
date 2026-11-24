import assert from "node:assert/strict";
import { test } from "node:test";
import { pathOverride, urlOverride } from "../src/overrides.ts";

test("URL overrides: https or local http only, never in the app", () => {
  const k = "SELFGUARD_TEST_URL";
  const fb = "https://default.example";
  try {
    process.env[k] = "https://mirror.example/v1";
    assert.equal(urlOverride(k, fb), "https://mirror.example/v1");
    process.env[k] = "http://127.0.0.1:8080/v1";
    assert.equal(urlOverride(k, fb), "http://127.0.0.1:8080/v1");
    process.env[k] = "http://evil.example";
    assert.equal(urlOverride(k, fb), fb);
    process.env[k] = "not a url";
    assert.equal(urlOverride(k, fb), fb);
    process.env[k] = "https://mirror.example";
    process.env.SELFGUARD_RUNTIME = "app";
    assert.equal(urlOverride(k, fb), fb);
    process.env.SELFGUARD_TEST_PATH = "/tmp/x";
    assert.equal(pathOverride("SELFGUARD_TEST_PATH"), undefined);
  } finally {
    delete process.env[k];
    delete process.env.SELFGUARD_TEST_PATH;
    delete process.env.SELFGUARD_RUNTIME;
  }
});
