// Browser extensions: Chromium profiles and Firefox, fixtures in temp folders only.
import assert from "node:assert/strict";
import { before, test } from "node:test";
import { freshHome, put, scanHost, summary } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");
let data: typeof import("../src/sources/host/extensions-browser-data.ts");

before(async () => {
  freshHome();
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  data = await import("../src/sources/host/extensions-browser-data.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

const id = (c: string) => c.repeat(32);
const CHROME = "Library/Application Support/Google/Chrome";
const SECRET = "SECRET_BROWSING_DATA";

interface Entry {
  location?: number;
  from_webstore?: boolean;
  state?: number;
  name?: string;
  version?: string;
  api?: string[];
  hosts?: string[];
  path?: string;
}

function prefs(entries: Record<string, Entry>, extra: object = {}): string {
  const settings: Record<string, unknown> = {};
  for (const [k, e] of Object.entries(entries)) {
    settings[k] = {
      location: e.location,
      from_webstore: e.from_webstore,
      state: e.state,
      path: e.path,
      manifest: { name: e.name, version: e.version ?? "1.0", permissions: ["storage"] },
      active_permissions: { api: e.api ?? [], explicit_host: e.hosts ?? [] },
    };
  }
  return JSON.stringify({ extensions: { settings }, homepage: SECRET, session: { startup_urls: [`https://${SECRET}.example`] }, ...extra });
}

test("Chromium: the four rules, keyed by browser, profile and id; components and leftovers skipped", () => {
  const { home } = freshHome();
  const [a, b, c, d, e, f, g, h] = ["a", "b", "c", "d", "e", "f", "g", "h"].map(id);
  put(
    home,
    `${CHROME}/Default/Secure Preferences`,
    prefs({
      [a!]: { location: 1, from_webstore: true, name: "Plain Tool", version: "2.0" },
      [b!]: { location: 4, name: "My Dev Ext" },
      [c!]: { location: 1, from_webstore: true, name: "Power", api: ["debugger", "cookies", "storage"], hosts: ["<all_urls>"] },
      [d!]: { location: 5, name: "Built in" },
      [e!]: { name: "Leftover" },
      [f!]: { location: 1, from_webstore: true, name: "Cookies narrow", api: ["cookies", "webRequestBlocking"], hosts: ["https://example.com/*"] },
      [g!]: { location: 1, from_webstore: false, name: "Sideloaded" },
      [h!]: { location: 1, from_webstore: true, state: 0, name: "Off", api: ["proxy", "nativeMessaging"] },
      "not-an-id": { location: 1, name: "Bad id" },
    }),
  );
  put(home, `${CHROME}/Profile 2/Secure Preferences`, prefs({ [a!]: { location: 1, from_webstore: true, name: "Plain Tool" } }));
  put(home, `${CHROME}/Profile 99x/Secure Preferences`, prefs({ [a!]: { location: 1, name: "ignored profile" } }));
  const rec = scanHost(sources, sources.machineTarget());
  const s = summary(rec).map((x) => x.replace(/ @.*?( N)?$/, "$1"));
  assert.deepEqual(s, [
    `low browser-extension Chrome|Default|${a} N`,
    `moderate unpacked-browser-extension Chrome|Default|${b} N`,
    `low browser-extension Chrome|Default|${b} N`,
    `moderate powerful-browser-extension Chrome|Default|${c}`,
    `low browser-extension Chrome|Default|${c} N`,
    `low browser-extension Chrome|Default|${f} N`,
    `moderate unpacked-browser-extension Chrome|Default|${g} N`,
    `low browser-extension Chrome|Default|${g} N`,
    `low browser-extension Chrome|Default|${h} N`,
    `low browser-extension Chrome|Profile 2|${a} N`,
  ]);
  const power = rec.warnings.find((w) => w.rule === "powerful-browser-extension")!;
  assert.match(power.message, /"Power" \(c{32}\) in Chrome profile "Default".*debugger.*cookies on all sites/);
  assert.match(rec.warnings.find((w) => w.key?.endsWith(h!))!.message, /\(disabled\)$/);
  assert.doesNotMatch(JSON.stringify(rec), new RegExp(SECRET));
  // Markers: the Extensions folder, not the constantly rewritten preferences.
  const m = rec.markers!.map((x) => x.path);
  assert.ok(m.includes(`${home}/${CHROME}/Default/Extensions`));
  assert.ok(!m.some((p) => p.endsWith("Preferences")));
});

test("malicious ids: whole-extension and version-specific entries, urgent and high", () => {
  const { home } = freshHome();
  const whole = "fjmlhlkccegopebcllcmafahkmeejpph";
  const hijacked = "pajkjnmeojmbapicmbpliphjmcekeaac";
  const trust = "egjidjbpglichdcondbcbdnbeeppgdph";
  put(
    home,
    `${CHROME}/Default/Secure Preferences`,
    prefs({
      [whole]: { location: 1, from_webstore: true, name: "SEO Pulse‮ Pro\x1b[31m", version: "1.0" },
      [hijacked]: { location: 1, from_webstore: true, name: "Cyberhaven", version: "24.10.4" },
      [trust]: { location: 1, from_webstore: true, name: "Trust Wallet", version: "2.69" },
    }),
  );
  const rec = scanHost(sources, sources.machineTarget());
  const bad = rec.warnings.filter((w) => w.rule === "malicious-browser-extension");
  assert.deepEqual(bad.map((w) => w.key), [`Chrome|Default|${whole}`, `Chrome|Default|${hijacked}`]);
  for (const w of bad) assert.ok(w.severity === "high" && w.urgent === true && w.notify === true);
  assert.match(bad[1]!.message, /version 24\.10\.4 was published by attackers/);
  assert.doesNotMatch(bad[0]!.message, /[‮\x1b]/);
  assert.equal(rec.warnings.filter((w) => w.rule === "browser-extension").length, 3);
});

test("denylist data: valid ids, a public https source for each entry, no duplicates", () => {
  const ids = Object.keys(data.DENYLIST);
  assert.ok(ids.length >= 50);
  for (const k of ids) {
    assert.match(k, /^[a-p]{32}$/, k);
    const e = data.DENYLIST[k]!;
    assert.match(data.SOURCES[e.src], /^https:\/\//);
    assert.ok(e.name.length > 0);
  }
});

test("names: __MSG_ is resolved from the extension's locale files; unpacked fall back to the id", () => {
  const { home } = freshHome();
  const a = id("a");
  put(home, `${CHROME}/Default/Secure Preferences`, prefs({ [a]: { location: 1, from_webstore: true, name: "__MSG_appName__", path: `${a}/1.0_0` } }));
  put(home, `${CHROME}/Default/Extensions/${a}/1.0_0/manifest.json`, JSON.stringify({ default_locale: "en" }));
  put(home, `${CHROME}/Default/Extensions/${a}/1.0_0/_locales/en/messages.json`, JSON.stringify({ AppName: { message: "Resolved Name" } }));
  const b = id("b");
  put(home, `${CHROME}/Profile 2/Secure Preferences`, prefs({ [b]: { location: 4, name: "__MSG_x__", path: "/abs/path" } }));
  const rec = scanHost(sources, sources.machineTarget());
  assert.match(rec.warnings.find((w) => w.key === `Chrome|Default|${a}`)!.message, /"Resolved Name"/);
  assert.match(rec.warnings.find((w) => w.key === `Chrome|Profile 2|${b}`)!.message, new RegExp(`"${b}"`));
});

test("Edge and old Chromium: Preferences is used when Secure Preferences is missing; Edge isn't 'not from the store'", () => {
  const { home } = freshHome();
  const a = id("a");
  put(home, "Library/Application Support/Microsoft Edge/Default/Preferences", prefs({ [a]: { location: 1, from_webstore: false, name: "Edge Addon" } }));
  put(home, `.config/google-chrome/Default/Preferences`, prefs({ [a]: { location: 4, name: "Linux Dev" } }));
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec).map((x) => x.replace(/ @.*?( N)?$/, "$1")), [
    `low browser-extension Edge|Default|${a} N`,
    `moderate unpacked-browser-extension Chrome|Default|${a} N`,
    `low browser-extension Chrome|Default|${a} N`,
  ]);
});

test("Firefox: temporary and unsigned add-ons, built-ins and themes skipped, powers from userPermissions", () => {
  const { home } = freshHome();
  const addon = (o: object) => ({ type: "extension", version: "1.0", active: true, defaultLocale: { name: "N" }, ...o });
  put(
    home,
    "Library/Application Support/Firefox/Profiles/abcd1234.default-release/extensions.json",
    JSON.stringify({
      addons: [
        addon({ id: "ok@example.com", location: "app-profile", signedState: 2, userPermissions: { permissions: ["storage"], origins: [] } }),
        addon({ id: "temp@example.com", location: "app-temporary" }),
        addon({ id: "unsigned@example.com", location: "app-profile", signedState: 0 }),
        addon({ id: "power@example.com", location: "app-profile", signedState: 2, userPermissions: { permissions: ["proxy", "cookies", "nativeMessaging"], origins: ["<all_urls>"] } }),
        addon({ id: "builtin@mozilla.org", location: "app-builtin" }),
        addon({ id: "theme@example.com", type: "theme", location: "app-profile" }),
        addon({ id: "bad id with spaces", location: "app-profile" }),
        "junk",
      ],
    }),
  );
  const rec = scanHost(sources, sources.machineTarget());
  const keys = rec.warnings.map((w) => `${w.rule} ${w.key}`);
  assert.deepEqual(keys, [
    "browser-extension Firefox|default-release|ok@example.com",
    "unpacked-browser-extension Firefox|default-release|temp@example.com",
    "browser-extension Firefox|default-release|temp@example.com",
    "unpacked-browser-extension Firefox|default-release|unsigned@example.com",
    "browser-extension Firefox|default-release|unsigned@example.com",
    "powerful-browser-extension Firefox|default-release|power@example.com",
    "browser-extension Firefox|default-release|power@example.com",
  ]);
  assert.match(rec.warnings[5]!.message, /nativeMessaging.*proxy.*cookies on all sites/s);
});

test("malformed, huge-looking and hostile files never throw; repo scope reads nothing", () => {
  const { home } = freshHome();
  put(home, `${CHROME}/Default/Secure Preferences`, "{ not json");
  put(home, `${CHROME}/Profile 2/Secure Preferences`, JSON.stringify({ extensions: { settings: { [id("a")]: "x", [id("b")]: { location: "4", manifest: 5, active_permissions: [] }, __proto__: { a: 1 } } } }));
  put(home, `${CHROME}/Profile 3/Secure Preferences`, JSON.stringify({ extensions: { settings: [] } }));
  put(home, "Library/Application Support/Firefox/Profiles/abcd1234.x/extensions.json", JSON.stringify({ addons: "nope" }));
  const rec = scanHost(sources, sources.machineTarget());
  assert.equal(rec.warnings.length, 0);
  assert.equal(sources.filesFor("host", sources.repoTarget(home)).size, 0);
  // A symlinked or directory "Secure Preferences" is not a regular file: skipped.
  put(home, `${CHROME}/Profile 4/Secure Preferences/x`, "dir");
  assert.doesNotThrow(() => scanHost(sources, sources.machineTarget()));
});
