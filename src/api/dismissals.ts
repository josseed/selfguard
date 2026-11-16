import { writeMenuBar } from "../menubar.ts";
import { resolve } from "node:path";
import { loadConfig, normalizeDir, saveConfig } from "../config.ts";
import { liveDismissals, pruneDismissals, trackedActivity } from "../dismiss.ts";
import { ApiError } from "../errors.ts";
import { getStatus } from "./status.ts";

// ---------- dismissed repos ----------

export interface DismissedRepo {
  key: string;
  label: string;
  dismissedAt: string;
}

/** Repos the user turned off that haven't come back yet. */
export function listDismissed(): DismissedRepo[] {
  const cfg = loadConfig();
  const live = liveDismissals(cfg.dismissed, trackedActivity(cfg));
  return cfg.dismissed.filter((d) => live.has(d.key)).map((d) => ({ key: d.key, label: d.label, dismissedAt: d.at }));
}

/**
 * Turn a repo off (all its checkouts): it keeps being scanned but counts as inactive (no
 * reminders, alerts only for malicious packages) until any of its checkouts has git
 * activity again (a commit, checkout, pull...). Dismissing again restarts the clock.
 */
export function dismissRepo(key: string): DismissedRepo {
  const group = getStatus().repos.find((g) => g.key === key);
  if (!group) throw new ApiError("not_found", "unknown repo");
  const cfg = loadConfig();
  // The label names the machine like everywhere else ("devbox · acme/api").
  const label = group.machine ? `${group.machine} · ${group.label}` : group.label;
  const at = new Date().toISOString();
  cfg.dismissed = [...cfg.dismissed.filter((d) => d.key !== key), { key, label, at }];
  saveConfig(cfg);
  writeMenuBar();
  return { key, label, dismissedAt: at };
}

/**
 * Repo group key from what a user types: a key as listed by status/dismissed, or the path
 * of (or inside) a local checkout.
 */
export function resolveRepoKey(target: string): string {
  const repos = getStatus().repos;
  if (repos.some((g) => g.key === target) || loadConfig().dismissed.some((d) => d.key === target)) return target;
  const abs = normalizeDir(target) ?? resolve(target);
  const inside = (dir: string): boolean => abs === dir || abs.startsWith(`${dir}/`);
  const hit = repos
    .flatMap((g) => g.checkouts.filter((k) => !k.machine && inside(k.path)).map((k) => ({ key: g.key, len: k.path.length })))
    .sort((x, y) => y.len - x.len)[0];
  if (!hit) throw new ApiError("not_found", `no tracked repo at ${abs}`);
  return hit.key;
}

/** Turn a dismissed repo back on right away. */
export function undismissRepo(key: string): { key: string; removed: boolean } {
  const cfg = loadConfig();
  const before = cfg.dismissed.length;
  cfg.dismissed = cfg.dismissed.filter((d) => d.key !== key);
  if (cfg.dismissed.length < before) {
    saveConfig(cfg);
    writeMenuBar();
  }
  return { key, removed: cfg.dismissed.length < before };
}

/** Forget dismissals of repos that came back (git activity since). Never fails a scan. */
export function pruneDismissed(cfg: ReturnType<typeof loadConfig>): void {
  try {
    if (cfg.dismissed.length && pruneDismissals(cfg, trackedActivity(cfg)).length) saveConfig(cfg);
  } catch {
    /* best effort */
  }
}
