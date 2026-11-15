import assert from "node:assert/strict";
import { test } from "node:test";
import { buildAlert, buildReminder, buildResolvedAlert, needsAttention } from "../src/alerts.ts";
import { reminderDue } from "../src/announce.ts";
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
    path: "/code/shop-web",
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
  assert.equal(a.title, "selfguard: shop-web");
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
    { path: "/c/payments-api", newFindings: [f("color-utils-pro", "2.4.1", "MAL-2026-9999", "malicious")] },
  ]);
  assert.equal(a.kind, "critical");
  if (a.kind !== "critical") return;
  assert.equal(a.subtitle, "color-utils-pro@2.4.1 · MAL-2026-9999");
  assert.equal(a.url, "https://osv.dev/vulnerability/MAL-2026-9999");
  assert.match(a.dialogMessage, /Rotate credentials/);
  assert.match(a.dialogMessage, /\/c\/payments-api/);
});

test("multiline cleaning keeps line breaks but still strips escapes", () => {
  assert.equal(clean("a\n\n\n\nb\u001b[2J", 100, { multiline: true }), "a\n\nb[2J");
  assert.equal(clean("a\nb"), "a b");
});

test("checkouts of the same repo are reported once, findings de-duplicated", () => {
  const repo = { key: "github.com/acme/web", label: "acme/web" };
  const lodash = f("lodash", "4.17.20", "GHSA-3", "high", "4.18.0");
  const a = buildAlert([
    { path: "/c/web", newFindings: [lodash], repo },
    { path: "/c/web-feat-x", newFindings: [lodash, f("qs", "6.5.1", "GHSA-5", "moderate", "6.5.3")], repo },
    { path: "/c/web-hotfix", newFindings: [lodash], repo },
  ]);
  assert.equal(a.kind, "banner");
  if (a.kind !== "banner") return;
  assert.equal(a.title, "selfguard: acme/web (3 checkouts)");
  assert.equal(a.subtitle, "2 vulnerable packages · worst: HIGH");
});

test("inactive checkouts stay quiet, except for malicious packages", () => {
  const vuln = f("lodash", "4.17.20", "GHSA-3", "critical", "4.18.0");
  assert.deepEqual(buildAlert([{ path: "/c/old", newFindings: [vuln], active: false }]), { kind: "none" });
  const mal = f("evil", "1.0.0", "MAL-1", "malicious");
  assert.equal(buildAlert([{ path: "/c/old", newFindings: [vuln, mal], active: false }]).kind, "critical");
});

test("fixes are announced per repo, counting only packages that are no longer vulnerable", () => {
  const repo = { key: "github.com/acme/web", label: "acme/web" };
  const a1 = f("axios", "0.21.0", "GHSA-1", "high", "0.21.2");
  const a2 = f("axios", "0.21.0", "GHSA-2", "moderate", "0.21.2");
  const qs = f("qs", "6.5.1", "GHSA-5", "moderate", "6.5.3");
  const lodash = f("lodash", "4.17.20", "GHSA-3", "critical", "4.18.0");
  const a = buildResolvedAlert([
    // axios lost one advisory but is still vulnerable: not "fixed"
    { path: "/c/web", newFindings: [], resolvedFindings: [a1, qs, lodash], findings: [a2], repo },
  ]);
  assert.equal(a.kind, "banner");
  if (a.kind !== "banner") return;
  assert.equal(a.title, "selfguard: acme/web ✓");
  assert.equal(a.subtitle, "2 vulnerable packages fixed");
  assert.equal(a.body, "1 still vulnerable · worst: MODERATE");

  const clean = buildResolvedAlert([{ path: "/c/web", newFindings: [], resolvedFindings: [qs], findings: [], repo }]);
  assert.equal(clean.kind === "banner" && clean.body, "No known vulnerabilities left.");
  assert.deepEqual(buildResolvedAlert([{ path: "/c/web", newFindings: [], resolvedFindings: [qs], findings: [], active: false }]), { kind: "none" });
});

test("reminders cover malicious, critical (non-dev) and high direct findings only", () => {
  const dev = { ...f("tinypool", "1.1.1", "G-dev", "critical", "2.1.2"), dev: true };
  const transitiveHigh = { ...f("brace-expansion", "1.1.12", "G-t", "high", "1.1.20"), direct: false };
  const moderate = f("qs", "6.5.1", "G-m", "moderate", "6.5.3");
  assert.equal(needsAttention(dev), false);
  assert.equal(needsAttention(transitiveHigh), false);
  assert.deepEqual(buildReminder([{ label: "acme/web", findings: [dev, transitiveHigh, moderate] }]), { kind: "none" });

  const one = buildReminder([{ label: "acme/web", findings: [dev, f("mongoose", "9.7.2", "G-h", "high", "9.11.4")] }]);
  assert.equal(one.kind === "banner" && one.title, "selfguard: acme/web needs attention");
  assert.equal(one.kind === "banner" && one.subtitle, "1 high · open: selfguard ui");
  assert.equal(one.kind === "banner" && one.body, "mongoose → 9.11.4");

  const many = buildReminder([
    { label: "low-risk", findings: [f("a", "1.0.0", "G1", "high", "1.0.1")] },
    { label: "worst", findings: [f("b", "1.0.0", "G2", "critical", "1.0.1"), f("c", "1.0.0", "G3", "high", "2.0.0")] },
  ]);
  assert.equal(many.kind === "banner" && many.title, "selfguard: 2 repos need attention");
  assert.equal(many.kind === "banner" && many.body, "worst (1 critical, 1 high), low-risk (1 high)");
});

test("reminders are due once per period, in the daytime", () => {
  const at = (h: number, day = 15) => new Date(2026, 10, day, h, 0, 0);
  assert.equal(reminderDue("off", undefined, at(12)), false);
  assert.equal(reminderDue("daily", undefined, at(12)), true);
  assert.equal(reminderDue("daily", undefined, at(7)), false, "not before 9:00");
  assert.equal(reminderDue("daily", undefined, at(22)), false, "not after 21:00");
  assert.equal(reminderDue("daily", at(10).toISOString(), at(18)), false, "already sent today");
  assert.equal(reminderDue("daily", at(10, 14).toISOString(), at(10)), true);
  assert.equal(reminderDue("weekly", at(10, 10).toISOString(), at(10)), false);
  assert.equal(reminderDue("weekly", at(10, 8).toISOString(), at(10)), true);
});
