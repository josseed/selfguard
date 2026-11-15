/**
 * "Turn off" a repo you don't care about right now (an old experiment, a repo you only
 * cloned to read). It stays tracked and scanned, but counts as inactive: no reminders and
 * no alerts except malicious packages, like any inactive checkout. It comes back on its own
 * as soon as any of its checkouts shows git activity after the dismissal.
 */
import { activeSince } from "./activity.ts";
import type { Config, Dismissal } from "./config.ts";
import { identityOf, listAllRepos, repoKeyOf } from "./store.ts";

export interface CheckoutActivity {
  key: string;
  lastActivity: string | null;
}

/** Repo key → dismissed at, for dismissals none of whose checkouts has had activity since. */
export function liveDismissals(dismissed: readonly Dismissal[], checkouts: Iterable<CheckoutActivity>): Map<string, string> {
  const live = new Map(dismissed.map((d) => [d.key, d.at]));
  if (live.size === 0) return live;
  for (const c of checkouts) {
    const at = live.get(c.key);
    if (at !== undefined && activeSince(c.lastActivity, at)) live.delete(c.key);
  }
  return live;
}

/** Activity of every tracked checkout (local and remote), keyed by repo group. */
export function trackedActivity(cfg: Config): CheckoutActivity[] {
  return listAllRepos(cfg.machines.map((m) => m.name)).map((rec) => {
    const identity = identityOf(rec);
    return { key: repoKeyOf(rec, identity), lastActivity: identity?.lastActivity ?? null };
  });
}

/**
 * Dismissals that came back (activity since) are dropped. Returns the keys dropped, so the
 * caller can save the config. Unknown keys (repo not tracked right now) are kept.
 */
export function pruneDismissals(cfg: Config, checkouts: Iterable<CheckoutActivity>): string[] {
  if (cfg.dismissed.length === 0) return [];
  const live = liveDismissals(cfg.dismissed, checkouts);
  const dropped = cfg.dismissed.filter((d) => !live.has(d.key)).map((d) => d.key);
  if (dropped.length) cfg.dismissed = cfg.dismissed.filter((d) => live.has(d.key));
  return dropped;
}
