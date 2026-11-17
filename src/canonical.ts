/**
 * Which checkout speaks for each repo. Worktrees, clones and copies of a repo share its
 * vulnerabilities, and the fix is made once, on the default branch, so only that checkout
 * counts: in repo status, reminders, the menu bar and alerts. The others are listed with
 * the repo and only alert for malicious packages.
 *
 * - Git checkouts are grouped by repo identity (remote + subfolder, see repoid.ts). The one
 *   on the default branch represents the repo; without one, the main clone if it is active,
 *   else the most recently active checkout.
 * - A folder without git is a copy of a tracked project when it has the same manifest name
 *   and mostly the same dependencies (agents' snapshots, unpacked archives, "evidence"
 *   folders). It joins that project's repo and never represents it.
 */
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { activityOf } from "./activity.ts";
import type { RepoIdentity } from "./repoid.ts";
import { checkoutId, repoKeyOf, type RepoRecord } from "./store.ts";

/** default-branch / branch: git checkouts; folder: no git; copy: a folder copying a project. */
export type CheckoutRole = "default-branch" | "branch" | "folder" | "copy";

export interface Placement {
  /** Repo group key (a copy gets the key of the repo it copies). */
  key: string;
  /** Label of that repo (for copies, the original's). */
  label: string | null;
  role: CheckoutRole;
  /** This checkout's findings are the repo's. */
  representative: boolean;
  /** Has recent git activity (a copy: the original's activity decides). */
  active: boolean;
}

export interface Checkout {
  rec: RepoRecord;
  repo: RepoIdentity | null;
}

/** A copy shares the original's name and at least this share of its dependencies. */
export const COPY_SIMILARITY = 0.6;

const nameCache = new Map<string, { mtimeMs: number; name: string | null }>();

function readName(file: string, parse: (text: string) => string | null): string | null {
  try {
    const st = statSync(file);
    const hit = nameCache.get(file);
    if (hit && hit.mtimeMs === st.mtimeMs) return hit.name;
    const name = st.size > 1024 * 1024 ? null : parse(readFileSync(file, "utf8"));
    nameCache.set(file, { mtimeMs: st.mtimeMs, name });
    return name;
  } catch {
    return null;
  }
}

const tomlName = (section: RegExp) => (text: string): string | null => {
  const at = text.search(section);
  if (at < 0) return null;
  const rest = text.slice(at).split(/\r?\n/).slice(1);
  for (const line of rest) {
    if (/^\s*\[/.test(line)) break;
    const m = /^\s*name\s*=\s*["']([^"']+)["']/.exec(line);
    if (m) return m[1]!;
  }
  return null;
};

/** The project's own name from its manifest (local checkouts only). */
export function manifestName(rec: RepoRecord): string | null {
  if (rec.machine) return null;
  switch (rec.lockType) {
    case "npm":
    case "pnpm":
    case "yarn":
    case "bun":
      return readName(join(rec.path, "package.json"), (t) => {
        const n = (JSON.parse(t) as { name?: unknown }).name;
        return typeof n === "string" && n.trim() ? n : null;
      });
    case "uv":
    case "poetry":
      return readName(join(rec.path, "pyproject.toml"), (t) => tomlName(/^\[project\]\s*$/m)(t) ?? tomlName(/^\[tool\.poetry\]\s*$/m)(t));
    case "cargo":
      return readName(join(rec.path, "Cargo.toml"), tomlName(/^\[package\]\s*$/m));
    case "gomod":
      return readName(join(rec.path, "go.mod"), (t) => /^\s*module\s+(\S+)/m.exec(t)?.[1] ?? null);
    default:
      return null;
  }
}

/** Share of dependency names two projects have in common (Jaccard). */
const depNames = new WeakMap<RepoRecord, Set<string>>();
function namesOf(r: RepoRecord): Set<string> {
  let set = depNames.get(r);
  if (!set) {
    set = new Set(r.deps.map((d) => `${d.ecosystem ?? "npm"}:${d.name}`));
    depNames.set(r, set);
  }
  return set;
}

export function similarity(a: RepoRecord, b: RepoRecord): number {
  const x = namesOf(a);
  const y = namesOf(b);
  if (x.size === 0 && y.size === 0) return 1;
  let common = 0;
  for (const n of x) if (y.has(n)) common++;
  return common / (x.size + y.size - common);
}

const depth = (p: string): number => p.split("/").length;
const at = (repo: RepoIdentity | null): number => (repo?.lastActivity ? Date.parse(repo.lastActivity) : 0);

/**
 * Place every checkout in its repo and pick each repo's representative. `dismissed`: repo key
 * → dismissal still in effect (see dismiss.ts).
 */
export function placeCheckouts(checkouts: Checkout[], activeDays: number, dismissed: Map<string, string> = new Map(), now = Date.now()): Map<string, Placement> {
  const out = new Map<string, Placement>();
  const groups = new Map<string, Checkout[]>();
  const copyOf = new Map<string, string>();
  const labels = new Map<string, string | null>();

  // Originals by machine and name: git checkouts first, then folders without git from the
  // shallowest path down, so a snapshot nested in a project is found to be its copy.
  const pool = new Map<string, Array<{ key: string; rec: RepoRecord }>>();
  const poolKey = (c: Checkout, name: string) => `${c.rec.machine ?? ""}\u0000${name}`;
  const ordered = [...checkouts].sort((a, b) => Number(!a.repo) - Number(!b.repo) || depth(a.rec.path) - depth(b.rec.path) || a.rec.path.localeCompare(b.rec.path));
  for (const c of ordered) {
    let key = repoKeyOf(c.rec, c.repo);
    const name = manifestName(c.rec);
    if (!c.repo && name) {
      const match = (pool.get(poolKey(c, name)) ?? [])
        .map((o) => ({ key: o.key, score: similarity(c.rec, o.rec) }))
        .filter((o) => o.score >= COPY_SIMILARITY)
        .sort((a, b) => b.score - a.score)[0];
      if (match) {
        copyOf.set(checkoutId(c.rec), match.key);
        key = match.key;
      }
    }
    if (name && !copyOf.has(checkoutId(c.rec))) {
      // One original per repo is enough to compare against (its worktrees are alike).
      const list = pool.get(poolKey(c, name)) ?? [];
      if (!list.some((o) => o.key === key)) list.push({ key, rec: c.rec });
      pool.set(poolKey(c, name), list);
    }
    if (c.repo && !labels.has(key)) labels.set(key, c.repo.label);
    const g = groups.get(key) ?? [];
    g.push(c);
    groups.set(key, g);
  }

  for (const [key, members] of groups) {
    const dismissedAt = dismissed.get(key) ?? null;
    const own = members.filter((c) => !copyOf.has(checkoutId(c.rec)));
    const activity = new Map(members.map((c) => [checkoutId(c.rec), activityOf(c.repo, activeDays, now, dismissedAt).active]));
    const anyActive = own.some((c) => activity.get(checkoutId(c.rec)));
    const onDefault = (c: Checkout) => !!c.repo?.defaultBranch && c.repo.branch === c.repo.defaultBranch;
    const rank = (c: Checkout): number[] => [
      Number(!onDefault(c)),
      Number(!(activity.get(checkoutId(c.rec)) && !c.repo?.worktree)),
      Number(!activity.get(checkoutId(c.rec))),
      Number(c.repo?.worktree ?? false),
      -at(c.repo),
    ];
    const cmp = (a: Checkout, b: Checkout): number => {
      const ra = rank(a);
      const rb = rank(b);
      for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i]! - rb[i]!;
      return a.rec.path.localeCompare(b.rec.path);
    };
    const rep = [...own].sort(cmp)[0] ?? null;
    for (const c of members) {
      const id = checkoutId(c.rec);
      const copy = copyOf.has(id);
      out.set(id, {
        key,
        label: labels.get(key) ?? null,
        role: copy ? "copy" : !c.repo ? "folder" : onDefault(c) ? "default-branch" : "branch",
        representative: c === rep,
        active: copy ? anyActive : (activity.get(id) ?? false),
      });
    }
  }
  return out;
}
