/**
 * GET /api/menubar: the small summary the macOS app shows in its menu bar icon and menu.
 * Built from the overview, so the menu and the dashboard never disagree.
 */
import { severityRank, type Severity } from "../match.ts";
import { loadState } from "../state.ts";
import { getOverview, updateStatus } from "./overview.ts";

/** Icon state, worst first: a malicious package, serious findings, a service down, all good. */
export type MenuBarState = "malicious" | "attention" | "degraded" | "clean";

export interface MenuBar {
  version: string;
  state: MenuBarState;
  totals: Record<Severity, number>;
  /** Repos with serious findings, worst first (at most 10). */
  repos: Array<{ key: string; label: string; machine: string | null; worstSeverity: Severity | null; serious: number }>;
  moreRepos: number;
  trackedProjects: number;
  /** null: not macOS, or the schedule couldn't be read. */
  services: { sync: boolean; watcher: boolean } | null;
  lastSync: string | null;
  lastCheck: string | null;
  update: { available: boolean; latest: string | null };
}

const MAX_REPOS = 10;

export function menuBarState(totals: Record<Severity, number>, attention: number, services: MenuBar["services"]): MenuBarState {
  if (totals.malicious > 0) return "malicious";
  if (attention > 0) return "attention";
  if (services && (!services.sync || !services.watcher)) return "degraded";
  return "clean";
}

export function getMenuBar(): MenuBar {
  const o = getOverview();
  const byKey = new Map(o.repos.map((r) => [r.key, r]));
  const repos = o.needsAttention
    .map((key) => {
      const r = byKey.get(key);
      return { key, label: r?.label ?? key, machine: r?.machine ?? null, worstSeverity: r?.worstSeverity ?? null, serious: o.seriousByRepo[key] ?? 0 };
    })
    .sort((a, b) => severityRank(a.worstSeverity ?? "unknown") - severityRank(b.worstSeverity ?? "unknown") || b.serious - a.serious || a.label.localeCompare(b.label));
  const services = o.schedule ? { sync: o.schedule.enabled, watcher: o.schedule.watcher } : null;
  const state = loadState();
  const update = updateStatus() as { available?: unknown; latest?: unknown };
  return {
    version: o.version,
    state: menuBarState(o.totals, repos.length, services),
    totals: o.totals,
    repos: repos.slice(0, MAX_REPOS),
    moreRepos: Math.max(0, repos.length - MAX_REPOS),
    trackedProjects: o.trackedProjects,
    services,
    lastSync: state.lastSync ?? null,
    lastCheck: state.lastCheck ?? null,
    update: { available: update.available === true, latest: typeof update.latest === "string" ? update.latest : null },
  };
}
