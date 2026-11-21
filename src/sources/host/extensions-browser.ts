/**
 * Browser extensions (docs/host.md): Chromium-family profiles and Firefox, read as data. From
 * each profile only extension ids, names, versions, install kind and permissions are taken;
 * nothing else in those files (history-related settings, accounts, URLs) is kept or shown.
 */
import { join } from "node:path";
import { readRegularFile } from "../../fsutil.ts";
import { clean } from "../../sanitize.ts";
import type { ExtractResult, SourceExtractor } from "../types.ts";
import { NONE } from "./fs.ts";
import { files, locate, markers, watch, type Profile } from "./extensions-browser-paths.ts";
import { type BrowserExtension, extensionWarnings, type Warning } from "./extensions-browser-rules.ts";

/** Extensions fully handled per profile (all of them are checked against the denylist first). */
const MAX_EXTENSIONS = 150;
const MAX_SMALL = 512 * 1024;

const CHROMIUM_ID = /^[a-p]{32}$/;
const CHROMIUM_PATH = /^[a-p]{32}\/[\w.-]{1,64}$/;
const LOCALE = /^[A-Za-z]{2,3}([_-][A-Za-z0-9]{2,8})?$/;
const FIREFOX_ID = /^(\{[0-9a-fA-F-]{36}\}|[\w.+-]{1,80}@[\w.+-]{1,80}|[\w.+-]{1,80})$/;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, 500) : []);
const str = (v: unknown, max = 200): string => (typeof v === "string" ? clean(v, max) : "");

function parse(text: string): Obj | null {
  try {
    const v = JSON.parse(text) as unknown;
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

function readJson(file: string): Obj | null {
  const raw = readRegularFile(file, MAX_SMALL, { nofollow: true });
  return raw ? parse(raw.data.toString("utf8")) : null;
}

/** "__MSG_appName__" → the extension's own locale string (a bounded read of two small files). */
function localized(profile: Profile, entry: Obj, raw: string): string {
  const token = /^__MSG_(\w{1,80})__$/.exec(raw)?.[1]?.toLowerCase();
  const path = typeof entry.path === "string" && CHROMIUM_PATH.test(entry.path) ? entry.path : null;
  if (!token || !path) return "";
  const dir = join(profile.path, "Extensions", ...path.split("/"));
  const locale = str(readJson(join(dir, "manifest.json"))?.default_locale, 20);
  for (const loc of [locale, "en", "en_US"]) {
    if (!loc || !LOCALE.test(loc)) continue;
    const messages = readJson(join(dir, "_locales", loc, "messages.json"));
    if (!messages) continue;
    for (const [k, v] of Object.entries(messages)) if (k.toLowerCase() === token && isObj(v)) return str(v.message, 100);
  }
  return "";
}

/** Chromium location values: 4 unpacked, 8 command line. 5 and 10 are built-in components. */
const COMPONENT = new Set([5, 10]);

export function chromiumExtensions(profile: Profile, prefs: Obj): BrowserExtension[] {
  const settings = isObj(prefs.extensions) && isObj(prefs.extensions.settings) ? prefs.extensions.settings : {};
  const out: BrowserExtension[] = [];
  let resolved = 0;
  for (const [id, raw] of Object.entries(settings)) {
    if (!CHROMIUM_ID.test(id) || !isObj(raw)) continue;
    const location = typeof raw.location === "number" ? raw.location : null;
    // No location: a leftover record of a removed extension. Components ship with the browser.
    if (location === null || COMPONENT.has(location)) continue;
    const manifest = isObj(raw.manifest) ? raw.manifest : {};
    let name = str(manifest.name, 100);
    if (name.startsWith("__MSG_")) name = resolved++ < 40 ? localized(profile, raw, name) : "";
    const active = isObj(raw.active_permissions) ? raw.active_permissions : {};
    const apis = Array.isArray(active.api) ? strings(active.api) : strings(manifest.permissions).filter((p) => !p.includes("/") && p !== "<all_urls>");
    const hosts = [
      ...strings(active.explicit_host),
      ...strings(active.scriptable_host),
      ...strings(manifest.host_permissions),
      ...strings(manifest.permissions).filter((p) => p.includes("/") || p === "<all_urls>"),
    ];
    const reasons = raw.disable_reasons;
    const disabled = raw.state === 0 || (Array.isArray(reasons) && reasons.length > 0) || (typeof reasons === "number" && reasons > 0);
    let unpacked: string | null = null;
    if (location === 4) unpacked = "was loaded unpacked (developer mode)";
    else if (location === 8) unpacked = "was loaded from the command line";
    // Edge's own store doesn't set from_webstore; the others install from the Chrome Web Store.
    else if (location === 1 && raw.from_webstore === false && profile.browser !== "Edge") unpacked = "did not come from the Chrome Web Store";
    out.push({ id, name: name || id, version: str(manifest.version, 40) || null, unpacked, disabled, apis, hosts });
  }
  return out;
}

/** Firefox locations of add-ons that ship with the browser. */
const FIREFOX_BUILTIN = /^app-(builtin|system)/;

export function firefoxExtensions(doc: Obj): BrowserExtension[] {
  const out: BrowserExtension[] = [];
  for (const raw of Array.isArray(doc.addons) ? doc.addons : []) {
    if (!isObj(raw) || raw.type !== "extension" || typeof raw.id !== "string" || !FIREFOX_ID.test(raw.id)) continue;
    const location = str(raw.location, 40);
    if (FIREFOX_BUILTIN.test(location) || raw.hidden === true || raw.builtin === true) continue;
    const perms = isObj(raw.userPermissions) ? raw.userPermissions : {};
    const locale = isObj(raw.defaultLocale) ? raw.defaultLocale : {};
    let unpacked: string | null = null;
    if (location === "app-temporary") unpacked = "was loaded temporarily (about:debugging)";
    else if (typeof raw.signedState === "number" && raw.signedState <= 0) unpacked = "is not signed by Mozilla";
    out.push({
      id: raw.id,
      name: str(locale.name, 100) || raw.id,
      version: str(raw.version, 40) || null,
      unpacked,
      disabled: raw.active === false || raw.userDisabled === true || raw.softDisabled === true,
      apis: strings(perms.permissions),
      hosts: strings(perms.origins),
    });
  }
  return out;
}

export function extractBrowserExtensions(file: string, text: string): ExtractResult {
  const profile = locate(file);
  const doc = profile ? parse(text) : null;
  if (!profile || !doc) return NONE;
  const list = profile.family === "firefox" ? firefoxExtensions(doc) : chromiumExtensions(profile, doc);
  const warnings: Warning[] = [];
  const label = profile.family === "firefox" ? profile.dir.replace(/^[^.]+\./, "") : profile.dir;
  for (const [n, ext] of list.entries()) {
    const found = extensionWarnings(profile.browser, clean(label, 60), ext);
    // Past the limit only the denylist applies: a long list can't push a malicious one out.
    warnings.push(...(n < MAX_EXTENSIONS ? found : found.filter((w) => w.rule === "malicious-browser-extension")));
  }
  return { refs: [], warnings, skipped: 0 };
}

export const BROWSER_EXTENSIONS: SourceExtractor = {
  id: "host-browser-extensions",
  kind: "host",
  files,
  markers,
  watch,
  extract: (file, text, target) => (target.scope === "machine" ? extractBrowserExtensions(file, text) : NONE),
};
