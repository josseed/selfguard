import { existsSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { atomicWrite, isObject, readJsonFile } from "./fsutil.ts";
import { stateRoot } from "./paths.ts";

export interface Root {
  path: string;
  /** How many directory levels below `path` to look for projects. */
  depth: number;
}

export type RemindEvery = "daily" | "weekly" | "off";

export interface Config {
  schema: 1;
  roots: Root[];
  /** Absolute paths never tracked or discovered (and everything below them). */
  exclude: string[];
  /** How often to remind about unresolved malicious/critical/high findings. */
  remind: RemindEvery;
  /** Checkouts without git activity for this many days are "inactive" (no alerts). */
  activeDays: number;
}

export const DEFAULT_DEPTH = 5;
export const MAX_DEPTH = 10;
export const DEFAULT_ACTIVE_DAYS = 30;
export const REMIND_VALUES: readonly RemindEvery[] = ["daily", "weekly", "off"];

const configFile = (): string => join(stateRoot(), "config.json");

export function loadConfig(): Config {
  const raw = readJsonFile<Config>(configFile());
  const roots: Root[] = [];
  if (raw && isObject(raw) && Array.isArray(raw.roots)) {
    for (const r of raw.roots) {
      if (isObject(r) && typeof r.path === "string") {
        const depth = typeof r.depth === "number" ? clampDepth(r.depth) : DEFAULT_DEPTH;
        roots.push({ path: r.path, depth });
      }
    }
  }
  const exclude =
    raw && isObject(raw) && Array.isArray(raw.exclude) ? raw.exclude.filter((e): e is string => typeof e === "string") : [];
  const remind = raw && isObject(raw) && REMIND_VALUES.includes(raw.remind as RemindEvery) ? (raw.remind as RemindEvery) : "daily";
  const activeDays =
    raw && isObject(raw) && typeof raw.activeDays === "number" && raw.activeDays >= 1
      ? Math.min(365, Math.trunc(raw.activeDays))
      : DEFAULT_ACTIVE_DAYS;
  return { schema: 1, roots, exclude, remind, activeDays };
}

export function isExcluded(path: string, exclude: readonly string[]): boolean {
  return exclude.some((e) => path === e || path.startsWith(e.endsWith("/") ? e : `${e}/`));
}

export function saveConfig(cfg: Config): void {
  atomicWrite(configFile(), `${JSON.stringify(cfg, null, 2)}\n`);
}

export function clampDepth(n: number): number {
  return Math.max(1, Math.min(MAX_DEPTH, Math.trunc(n)));
}

export function expandHome(p: string): string {
  const t = p.trim();
  if (t === "~") return homedir();
  if (t.startsWith("~/")) return join(homedir(), t.slice(2));
  return t;
}

/** Absolute, symlink-resolved directory path, or null if it isn't a directory. */
export function normalizeDir(p: string): string | null {
  try {
    const abs = resolve(expandHome(p));
    if (!existsSync(abs) || !statSync(abs).isDirectory()) return null;
    return realpathSync(abs);
  } catch {
    return null;
  }
}

/** Common places people keep code, shown as suggestions in `selfguard setup`. */
const CANDIDATES = [
  "repository", "repositories", "repos", "code", "Code", "dev", "Developer", "development",
  "projects", "Projects", "src", "workspace", "work", "git", "github", "GitHub",
  "Documents/GitHub", "Documents/code", "Documents/projects", "Sites",
];

export function candidateRoots(): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const c of CANDIDATES) {
    const dir = normalizeDir(join(homedir(), c));
    // macOS is case-insensitive: ~/code and ~/Code are the same folder
    if (dir && !seen.has(dir.toLowerCase())) {
      seen.add(dir.toLowerCase());
      out.push(dir);
    }
  }
  return out;
}
