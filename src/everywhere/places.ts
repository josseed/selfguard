import { dirname, join, relative, sep } from "node:path";
import { activityOf } from "../activity.ts";
import { MAX_DEPTH, type Root } from "../config.ts";
import { repoIdentity } from "../repoid.ts";
import type { FoundProject } from "./walk.ts";

export interface Place {
  /** Folder to watch. */
  path: string;
  /** Depth that covers all its projects. */
  depth: number;
  projects: number;
  /** Projects with git activity in the active window. */
  active: number;
  secondary: number;
  noGit: number;
  lastActivity: string | null;
  /** Already covered by a watched folder. */
  watched: boolean;
  /** Suggested default: has active, non-secondary projects. */
  recommended: boolean;
  /** A few project paths, for the UI. */
  examples: string[];
}

/**
 * Group projects into a few folders to watch: the folder right below the home that holds
 * them (~/Desktop, ~/repository), or for projects sitting directly in the home or found
 * through a worktree pointer, their parent folder. Depth is what covers the deepest one.
 */
export function groupPlaces(
  projects: FoundProject[],
  home: string,
  watched: readonly Root[],
  activeDays: number,
  now = Date.now(),
  /** Repo key → when the user dismissed it (see dismiss.ts): such repos don't count as active. */
  dismissed: ReadonlyMap<string, string> = new Map(),
): Place[] {
  const segs = (from: string, to: string): string[] => relative(from, to).split(sep).filter(Boolean);
  // Worth watching: in git and not a sample/dump. Depth and recommendations follow these.
  const primary = (p: FoundProject): boolean => Boolean(p.gitRoot) && !p.secondary;
  const placeOf = (p: FoundProject): string => {
    // Worktrees found through their repo: the tool folder that holds them. Up to the last
    // hidden folder (~/repo/.worktrees), plus a following "worktrees" (~/.t3/worktrees);
    // otherwise the worktree's parent folder.
    if (p.worktreeRoot) {
      const parts = p.worktreeRoot.split(sep);
      const hidden = parts.findLastIndex((x, i) => i < parts.length - 1 && x.startsWith("."));
      if (hidden < 0) return dirname(p.worktreeRoot);
      const end = /^(worktrees?|workspaces?|wt)$/i.test(parts[hidden + 1] ?? "") && hidden + 1 < parts.length - 1 ? hidden + 2 : hidden + 1;
      return parts.slice(0, end).join(sep) || sep;
    }
    const parts = segs(home, p.root);
    if (parts.length === 0 || parts[0] === "..") return p.root;
    if (parts.length === 1) return p.root; // a project directly in the home is its own place
    return join(home, parts[0]!);
  };
  const depthIn = (path: string, list: FoundProject[]): number => {
    const ref = list.some(primary) ? list.filter(primary) : list;
    return Math.min(MAX_DEPTH, Math.max(1, ...ref.map((p) => segs(path, p.root).length)));
  };

  const rawDepth = (path: string, list: FoundProject[]): number => {
    const ref = list.some(primary) ? list.filter(primary) : list;
    return Math.max(1, ...ref.map((p) => segs(path, p.root).length));
  };

  // 1. Group. A worth-watching project deeper than MAX_DEPTH below its place moves to the
  //    shallowest folder that fits it; deep junk stays put (outside the depth, so unwatched).
  const initial = new Map<string, FoundProject[]>();
  for (const p of projects) {
    let key = placeOf(p);
    const rel = segs(key, p.root);
    if (rel.length > MAX_DEPTH && primary(p)) key = join(key, ...rel.slice(0, rel.length - MAX_DEPTH));
    initial.set(key, [...(initial.get(key) ?? []), p]);
  }
  // 2. Fold a place into an enclosing one when it fits in MAX_DEPTH and no hidden folder sits
  //    between them (regular discovery doesn't enter hidden folders).
  const groups = new Map<string, FoundProject[]>();
  for (const key of [...initial.keys()].sort((a, b) => a.length - b.length || a.localeCompare(b))) {
    const list = initial.get(key)!;
    const host = [...groups.keys()]
      .filter((g) => key.startsWith(g.endsWith(sep) ? g : g + sep) && !segs(g, key).some((x) => x.startsWith(".")))
      .sort((a, b) => b.length - a.length)
      .find((g) => rawDepth(g, [...groups.get(g)!, ...list]) <= MAX_DEPTH);
    if (host) groups.set(host, [...groups.get(host)!, ...list]);
    else groups.set(key, list);
  }

  const identity = new Map<string, ReturnType<typeof repoIdentity>>();
  const places = [...groups].map(([path, list]) => {
    let active = 0;
    let last = 0;
    for (const p of list) {
      if (!primary(p)) continue;
      const key = p.root;
      if (!identity.has(key)) identity.set(key, repoIdentity(p.root));
      const id = identity.get(key) ?? null;
      const act = activityOf(id, activeDays, now, (id && dismissed.get(id.key)) ?? null);
      if (act.active) active++;
      if (act.lastActivity) last = Math.max(last, Date.parse(act.lastActivity));
    }
    const depth = Math.min(MAX_DEPTH, depthIn(path, list));
    // Covered when a watched folder reaches it; regular discovery never enters hidden folders.
    const covered = watched.some((r) => {
      if (path === r.path) return r.depth >= depth;
      if (!path.startsWith(r.path.endsWith(sep) ? r.path : r.path + sep)) return false;
      const between = segs(r.path, path);
      return !between.some((x) => x.startsWith(".")) && r.depth >= depth + between.length;
    });
    const place: Place = {
      path,
      depth,
      projects: list.length,
      active,
      secondary: list.filter((p) => p.secondary).length,
      noGit: list.filter((p) => !p.gitRoot).length,
      lastActivity: last ? new Date(last).toISOString() : null,
      watched: covered,
      recommended: !covered && active > 0,
      examples: list.filter(primary).slice(0, 3).map((p) => p.root),
    };
    return place;
  });
  return places.sort(
    (a, b) => Number(b.recommended) - Number(a.recommended) || b.active - a.active || b.projects - a.projects || a.path.localeCompare(b.path),
  );
}
