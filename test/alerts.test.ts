import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAlert } from "../src/alerts.ts";
import { clean } from "../src/sanitize.ts";
import type { Finding } from "../src/store.ts";

const f = (name: string, version: string, id: string, severity: Finding["severity"], fixedIn?: string): Finding => ({
  id, name, version, severity, aliases: [], summary: "", direct: true, dev: false, firstSeen: "",
  ...(fixedIn ? { fixedIn } : {}),
});

test("no news, no alert", () => {
  assert.deepEqual(buildAlert([{ path: "/x/app", newFindings: [] }]), { kind: "none" });
});

test("one project: package count, worst severity and upgrade targets", () => {
  const a = buildAlert([{
    path: "/code/tienda-web",
    newFindings: [
      f("axios", "0.21.0", "GHSA-1", "moderate", "0.21.2"),
      f("axios", "0.21.0", "GHSA-2", "high", "0.33.0"),
      f("lodash", "4.17.20", "GHSA-3", "high", "4.18.0"),
      f("left-pad", "1.0.0", "GHSA-4", "low"),
      f("qs", "6.5.1", "GHSA-5", "moderate", "6.5.3"),
    ],
  }]);
  assert.equal(a.kind, "banner");
  if (a.kind !== "banner") return;
  assert.equal(a.title, "selfguard: tienda-web");
  assert.equal(a.subtitle, "4 vulnerable packages · worst: HIGH");
  assert.equal(a.body, "axios → 0.33.0, lodash → 4.18.0, qs → 6.5.3, +1 more");
});

test("several projects are summarized", () => {
  const a = buildAlert([
    { path: "/c/a", newFindings: [f("x", "1.0.0", "G1", "critical", "1.0.1")] },
    { path: "/c/b", newFindings: [f("y", "1.0.0", "G2", "low", "2.0.0")] },
  ]);
  assert.equal(a.kind === "banner" && a.title, "selfguard: 2 projects affected");
  assert.equal(a.kind === "banner" && a.subtitle, "2 vulnerable packages · worst: CRITICAL");
});

test("a malicious package escalates to a critical dialog that wins over everything", () => {
  const a = buildAlert([
    { path: "/c/web", newFindings: [f("lodash", "4.17.20", "GHSA-3", "critical", "4.18.0")] },
    { path: "/c/api-pagos", newFindings: [f("color-utils-pro", "2.4.1", "MAL-2026-9999", "malicious")] },
  ]);
  assert.equal(a.kind, "critical");
  if (a.kind !== "critical") return;
  assert.equal(a.subtitle, "color-utils-pro@2.4.1 · MAL-2026-9999");
  assert.equal(a.url, "https://osv.dev/vulnerability/MAL-2026-9999");
  assert.match(a.dialogMessage, /Rotate credentials/);
  assert.match(a.dialogMessage, /\/c\/api-pagos/);
});

test("multiline cleaning keeps line breaks but still strips escapes", () => {
  assert.equal(clean("a\n\n\n\nb\u001b[2J", 100, { multiline: true }), "a\n\nb[2J");
  assert.equal(clean("a\nb"), "a b");
});
