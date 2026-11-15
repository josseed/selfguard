/**
 * Which checkouts you are actually working on. Alerts and reminders only cover active
 * checkouts, so old clones and abandoned worktrees don't drown out what matters.
 */
import type { RepoIdentity } from "./repoid.ts";

const DAY_MS = 24 * 60 * 60 * 1000;

export interface Activity {
  active: boolean;
  /** Last local git activity (ISO), when known. */
  lastActivity: string | null;
  /** Turned off by the user and no git activity since (see dismiss.ts). */
  dismissed: boolean;
}

/**
 * `dismissedAt`: when the user turned this checkout's repo off (null: not dismissed, or it
 * already came back). Dismissed checkouts are inactive until git activity after that moment.
 */
export function activityOf(repo: RepoIdentity | null, activeDays: number, now = Date.now(), dismissedAt: string | null = null): Activity {
  const base = baseActivity(repo, activeDays, now);
  if (dismissedAt && !activeSince(repo?.lastActivity ?? null, dismissedAt)) return { active: false, lastActivity: base.lastActivity, dismissed: true };
  return { ...base, dismissed: false };
}

/** Git activity strictly after `since` (both ISO). */
export function activeSince(lastActivity: string | null, since: string): boolean {
  return lastActivity !== null && Date.parse(lastActivity) > Date.parse(since);
}

function baseActivity(repo: RepoIdentity | null, activeDays: number, now: number): Omit<Activity, "dismissed"> {
  // Not a git checkout: we can't tell, so it counts (you added it on purpose).
  if (!repo) return { active: true, lastActivity: null };
  if (repo.orphaned) return { active: false, lastActivity: null };
  if (!repo.lastActivity) return { active: true, lastActivity: null };
  const age = now - Date.parse(repo.lastActivity);
  return { active: age <= activeDays * DAY_MS, lastActivity: repo.lastActivity };
}
