/**
 * Where browser profiles live, and which files of them are read: bounded (profiles per
 * browser, files overall), one level, no walks. Never writes into a profile.
 */
import { join, sep } from "node:path";
import type { SourceTarget } from "../types.ts";
import { exists, home, isDir, names } from "./fs.ts";

export type Family = "chromium" | "firefox";

export interface BrowserRoot {
  browser: string;
  family: Family;
  /** Path under the home folder. */
  rel: string[];
}

const mac = (...p: string[]) => ["Library", "Application Support", ...p];
const cfg = (...p: string[]) => [".config", ...p];

export const ROOTS: BrowserRoot[] = [
  { browser: "Chrome", family: "chromium", rel: mac("Google", "Chrome") },
  { browser: "Brave", family: "chromium", rel: mac("BraveSoftware", "Brave-Browser") },
  { browser: "Edge", family: "chromium", rel: mac("Microsoft Edge") },
  { browser: "Arc", family: "chromium", rel: mac("Arc", "User Data") },
  { browser: "Chromium", family: "chromium", rel: mac("Chromium") },
  { browser: "Vivaldi", family: "chromium", rel: mac("Vivaldi") },
  { browser: "Chrome", family: "chromium", rel: cfg("google-chrome") },
  { browser: "Chromium", family: "chromium", rel: cfg("chromium") },
  { browser: "Brave", family: "chromium", rel: cfg("BraveSoftware", "Brave-Browser") },
  { browser: "Edge", family: "chromium", rel: cfg("microsoft-edge") },
  { browser: "Firefox", family: "firefox", rel: mac("Firefox", "Profiles") },
  { browser: "Firefox", family: "firefox", rel: [".mozilla", "firefox"] },
  { browser: "Firefox", family: "firefox", rel: ["snap", "firefox", "common", ".mozilla", "firefox"] },
  { browser: "Firefox", family: "firefox", rel: [".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"] },
];

/** Profiles read per browser, and files overall (the core caps a record at 200 files). */
export const MAX_PROFILES = 12;
const MAX_FILES = 80;

const CHROMIUM_PROFILE = /^(Default|Profile \d{1,3})$/;
/** Firefox profile folders: "<8 random chars>.<name>". */
const FIREFOX_PROFILE = /^[A-Za-z0-9]{8}\.[\w .-]{1,60}$/;

export const rootPath = (r: BrowserRoot): string => join(home(), ...r.rel);

export interface Profile {
  browser: string;
  family: Family;
  /** Folder name ("Default", "Profile 2", "abcd1234.default-release"). */
  dir: string;
  path: string;
}

/** The profiles of every browser root that exists (Default first, then by name). */
export function profiles(): Profile[] {
  const out: Profile[] = [];
  for (const r of ROOTS) {
    const root = rootPath(r);
    if (!isDir(root)) continue;
    const re = r.family === "chromium" ? CHROMIUM_PROFILE : FIREFOX_PROFILE;
    const found = names(root, 200)
      .filter((n) => re.test(n))
      .sort((a, b) => (a === "Default" ? -1 : b === "Default" ? 1 : a.localeCompare(b)))
      .slice(0, MAX_PROFILES);
    for (const dir of found) {
      const path = join(root, dir);
      if (isDir(path)) out.push({ browser: r.browser, family: r.family, dir, path });
    }
  }
  return out;
}

/**
 * The file with a profile's extension data. Chromium: `Secure Preferences` (where Chrome keeps
 * extensions.settings), or `Preferences` in builds that don't have it. Firefox: extensions.json.
 */
export function dataFile(p: Profile): string {
  if (p.family === "firefox") return join(p.path, "extensions.json");
  const secure = join(p.path, "Secure Preferences");
  return exists(secure) ? secure : join(p.path, "Preferences");
}

const machine = (t: SourceTarget): boolean => t.scope === "machine";

export function files(target: SourceTarget): string[] {
  if (!machine(target)) return [];
  return profiles().map(dataFile).filter(exists).slice(0, MAX_FILES);
}

/**
 * Cheap, no walks. The browser roots (a new profile folder changes them), each Chromium
 * profile's Extensions folder (changes on install, update and removal only) and, for a profile
 * that has no data file yet, the profile folder. Profile folders and Preferences files are
 * deliberately not markers otherwise: browsers rewrite them constantly. Listing is cheap; the
 * point is to not re-list because of that churn.
 */
export function markers(target: SourceTarget): string[] {
  if (!machine(target)) return [];
  const out = ROOTS.map(rootPath);
  for (const p of profiles()) {
    if (p.family === "chromium") out.push(join(p.path, "Extensions"));
    if (!exists(dataFile(p))) out.push(p.path);
  }
  return out;
}

/** What wakes the watcher: Extensions folders and Firefox's extensions.json, never Preferences. */
export function watch(target: SourceTarget): string[] {
  if (!machine(target)) return [];
  return profiles()
    .map((p) => (p.family === "chromium" ? join(p.path, "Extensions") : join(p.path, "extensions.json")))
    .filter(exists)
    .slice(0, 40);
}

/** Which browser and profile a data file belongs to (null: not one of ours). */
export function locate(file: string): Profile | null {
  for (const r of ROOTS) {
    const prefix = rootPath(r) + sep;
    if (!file.startsWith(prefix)) continue;
    const [dir, leaf, ...more] = file.slice(prefix.length).split(sep);
    if (!dir || more.length || !leaf) continue;
    const okName = r.family === "chromium" ? CHROMIUM_PROFILE.test(dir) : FIREFOX_PROFILE.test(dir);
    const okLeaf = r.family === "chromium" ? leaf === "Secure Preferences" || leaf === "Preferences" : leaf === "extensions.json";
    if (okName && okLeaf) return { browser: r.browser, family: r.family, dir, path: join(rootPath(r), dir) };
  }
  return null;
}
