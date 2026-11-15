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
}

export function activityOf(repo: RepoIdentity | null, activeDays: number, now = Date.now()): Activity {
  // Not a git checkout: we can't tell, so it counts (you added it on purpose).
  if (!repo) return { active: true, lastActivity: null };
  if (repo.orphaned) return { active: false, lastActivity: null };
  if (!repo.lastActivity) return { active: true, lastActivity: null };
  const age = now - Date.parse(repo.lastActivity);
  return { active: age <= activeDays * DAY_MS, lastActivity: repo.lastActivity };
}
