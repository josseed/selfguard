/**
 * The version npx last installed for an unpinned package, from its cache: each
 * `~/.npm/_npx/<hash>/` holds a package.json whose `_npx.packages` lists the specs as given
 * to npx, and a package-lock.json (or node_modules/<name>/package.json) with what was
 * installed. Read-only and bounded; nothing is run.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { parseNpmSpec } from "./specs.ts";

const MAX_DIRS = 1000;
const MAX_MANIFEST = 256 * 1024;
const MAX_LOCK = 8 * 1024 * 1024;
const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

interface Entry {
  dir: string;
  /** Specs as given to npx ("pkg", "pkg@latest"). */
  specs: string[];
  mtimeMs: number;
}

export type NpxCache = Map<string, Entry[]>;

/** npm's cache folder: $npm_config_cache when absolute, else ~/.npm. */
export function npxCacheDir(): string {
  const env = process.env.npm_config_cache;
  return join(env && isAbsolute(env) ? env : join(homedir(), ".npm"), "_npx");
}

function readJson(path: string, max: number): unknown {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > max) return null;
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
}

const obj = (v: unknown): Record<string, unknown> | null => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null);

/** Package name -> cache entries that installed it. Empty when there is no cache. */
export function readNpxCache(dir = npxCacheDir()): NpxCache {
  const out: NpxCache = new Map();
  let names: string[];
  try {
    names = readdirSync(dir).slice(0, MAX_DIRS);
  } catch {
    return out;
  }
  for (const n of names) {
    const d = join(dir, n);
    let mtimeMs: number;
    try {
      mtimeMs = statSync(join(d, "package.json")).mtimeMs;
    } catch {
      continue;
    }
    const specs = obj(obj(readJson(join(d, "package.json"), MAX_MANIFEST))?._npx)?.packages;
    if (!Array.isArray(specs)) continue;
    const written = specs.filter((s): s is string => typeof s === "string").slice(0, 50);
    for (const s of written) {
      const name = parseNpmSpec(s)?.name;
      if (!name) continue;
      out.set(name, [...(out.get(name) ?? []), { dir: d, specs: written, mtimeMs }]);
    }
  }
  return out;
}

function installedVersion(dir: string, name: string): string | null {
  const lock = obj(obj(readJson(join(dir, "package-lock.json"), MAX_LOCK))?.packages);
  const fromLock = obj(lock?.[`node_modules/${name}`])?.version;
  const v = typeof fromLock === "string" ? fromLock : obj(readJson(join(dir, "node_modules", ...name.split("/"), "package.json"), MAX_MANIFEST))?.version;
  return typeof v === "string" && EXACT.test(v) ? v : null;
}

/**
 * The installed version of `name` run with this exact spec (npx keys its cache by the specs
 * as given): the entry with this spec alone first, then the most recently used one.
 */
export function cachedVersion(cache: NpxCache, name: string, spec: string): string | null {
  const entries = (cache.get(name) ?? []).filter((e) => e.specs.includes(spec));
  entries.sort((a, b) => Number(a.specs.length !== 1) - Number(b.specs.length !== 1) || b.mtimeMs - a.mtimeMs);
  for (const e of entries) {
    const v = installedVersion(e.dir, name);
    if (v) return v;
  }
  return null;
}
