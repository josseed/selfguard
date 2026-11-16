import { homedir } from "node:os";
import { join } from "node:path";
import { clampDepth, loadConfig, normalizeDir, saveConfig, type Root } from "../config.ts";
import { liveDismissals, trackedActivity } from "../dismiss.ts";
import { ApiError } from "../errors.ts";
import { appendEvents } from "../events.ts";
import { discoverEverywhere, groupPlaces, PROTECTED, type EverywhereProgress, type Place } from "../everywhere.ts";
import { tryLock } from "../fsutil.ts";
import { notify } from "../notify.ts";
import { tildify } from "../report.ts";
import { loadState, updateState } from "../state.ts";
import { addRoot, discoverNew, type DiscoverResult } from "./roots.ts";

// ---------- find my projects (whole home folder) ----------

export interface EverywhereScan {
  home: string;
  places: Place[];
  projects: number;
  visited: number;
  ms: number;
  /** Zones cut short (too many folders, no project). */
  heavy: string[];
  /** Folders we couldn't read (permissions / macOS privacy). */
  denied: string[];
  /** Protected folders skipped on purpose. */
  skipped: string[];
}

/** Search the whole home folder and group what's found into places. Read-only. */
export async function findEverywhere(
  opts: { skipProtected?: boolean; onProgress?: (p: EverywhereProgress) => void; isCancelled?: () => boolean } = {},
): Promise<EverywhereScan> {
  const cfg = loadConfig();
  const r = await discoverEverywhere({ exclude: cfg.exclude, skipProtected: opts.skipProtected, onProgress: opts.onProgress, isCancelled: opts.isCancelled });
  updateState({ lastEverywhere: new Date().toISOString() });
  return {
    home: r.home,
    places: groupPlaces(r.projects, r.home, cfg.roots, cfg.activeDays, Date.now(), cfg.dismissed.length ? liveDismissals(cfg.dismissed, trackedActivity(cfg)) : new Map()),
    projects: r.projects.length,
    visited: r.visited,
    ms: r.ms,
    heavy: r.heavy,
    denied: r.denied,
    skipped: r.skipped,
  };
}

export interface ApplyPlacesResult {
  watching: Root[];
  excluded: string[];
  discovered: DiscoverResult | null;
}

/**
 * Watch the chosen places (folders + depth) and exclude the rejected ones, then register and
 * scan the new projects. Paths must be existing folders.
 */
export async function applyPlaces(watch: Array<{ path: string; depth: number }>, ignore: string[] = []): Promise<ApplyPlacesResult> {
  const watching: Root[] = [];
  for (const w of watch) {
    const dir = normalizeDir(w.path);
    if (!dir) throw new ApiError("not_found", `not a directory: ${w.path}`);
    if (!Number.isInteger(w.depth)) throw new ApiError("invalid", "depth must be an integer");
    const cfg = loadConfig();
    const existing = cfg.roots.find((r) => r.path === dir);
    const depth = Math.max(clampDepth(w.depth), existing?.depth ?? 0);
    addRoot(dir, depth);
    watching.push({ path: dir, depth });
  }
  const excluded: string[] = [];
  if (ignore.length) {
    const cfg = loadConfig();
    for (const path of ignore) {
      const dir = normalizeDir(path);
      if (!dir || cfg.exclude.includes(dir) || cfg.roots.some((r) => r.path === dir)) continue;
      cfg.exclude.push(dir);
      excluded.push(dir);
    }
    saveConfig(cfg);
  }
  const discovered = loadConfig().roots.length ? await discoverNew() : null;
  return { watching, excluded, discovered };
}

export interface AutoDiscoverResult {
  ran: boolean;
  reason: string | null;
  added: Array<{ path: string; depth: number; active: number; projects: number }>;
  scan: EverywhereScan | null;
}

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * The weekly background pass: search the home folder and start watching new places that
 * have repos with recent git activity (unless excluded or removed by the user before),
 * with a notification. Their current findings are the baseline: logged, not alerted.
 * Protected macOS folders are only searched if a watched folder already lives there.
 */
export async function autoDiscover(opts: { force?: boolean; notify?: boolean } = {}): Promise<AutoDiscoverResult> {
  const cfg = loadConfig();
  if (!cfg.autoDiscover && !opts.force) return { ran: false, reason: "automatic discovery is off", added: [], scan: null };
  const last = loadState().lastEverywhere;
  if (!opts.force && last && Date.now() - Date.parse(last) < WEEK_MS - 12 * 60 * 60 * 1000) {
    return { ran: false, reason: "ran less than a week ago", added: [], scan: null };
  }
  const release = tryLock("everywhere");
  if (!release) throw new ApiError("busy", "a search is already running");
  try {
    const home = homedir();
    const protectedAllowed = cfg.roots.some((r) => PROTECTED.some((p) => r.path === join(home, p) || r.path.startsWith(join(home, p) + "/")));
    const scan = await findEverywhere({ skipProtected: process.platform === "darwin" && !protectedAllowed });
    const dismissed = loadState().dismissedPlaces ?? [];
    const fresh = scan.places.filter((p) => p.recommended && !dismissed.some((d) => p.path === d || p.path.startsWith(d + "/")));
    if (fresh.length === 0) return { ran: true, reason: null, added: [], scan };
    const res = await applyPlaces(fresh.map((p) => ({ path: p.path, depth: p.depth })));
    const added = fresh.map((p) => ({ path: p.path, depth: p.depth, active: p.active, projects: p.projects }));
    const at = new Date().toISOString();
    appendEvents(added.map((a) => ({
      at, kind: "watching" as const, repo: tildify(a.path), repoKey: `place:${a.path}`, path: a.path, branch: null, active: true, total: a.projects, packages: [],
    })));
    if (opts.notify !== false) {
      const title = added.length === 1 ? `selfguard: now watching ${tildify(added[0]!.path)}` : `selfguard: now watching ${added.length} new folders`;
      const body = added.length === 1
        ? `${added[0]!.active} active repo(s) found there${res.discovered?.withVulnerabilities ? `, ${res.discovered.withVulnerabilities} with vulnerabilities` : ""}. Remove it in Folders if you don't want it.`
        : added.map((a) => tildify(a.path)).join(", ");
      await notify(title, body, "Find my projects");
    }
    return { ran: true, reason: null, added, scan };
  } finally {
    release();
  }
}
