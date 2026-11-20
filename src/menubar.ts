/**
 * The summary the macOS app shows in its menu bar: ~/.selfguard/menubar.json, rewritten after
 * every scan that brought news, every dismissal or forget, and by `selfguard menubar`. The app
 * only reads this file, so it needs no dashboard server running (also GET /api/menubar).
 */
import { readdirSync } from "node:fs";
import { needsAttention } from "./alerts.ts";
import { riskCounts } from "./api/risks.ts";
import { getAttention } from "./api/status.ts";
import { loadConfig } from "./config.ts";
import { readEvents } from "./events.ts";
import { atomicWrite, ensureDir } from "./fsutil.ts";
import { packageKey } from "./lockfile/types.ts";
import { severityRank, type Severity } from "./match.ts";
import { machineReposDir, menuBarFile, reposDir, stateRoot } from "./paths.ts";
import { recordFiles } from "./store.ts";
import { groupByPackage, worstSeverity } from "./report.ts";
import { scheduleStatus } from "./schedule.ts";
import { loadState } from "./state.ts";
import { cachedUpdate } from "./update.ts";
import { VERSION } from "./version.ts";

/** Backlog state, worst first: a malicious package, serious findings, a service down, all good. */
export type MenuBarState = "malicious" | "attention" | "degraded" | "clean";

export interface MenuBarEvent {
  at: string;
  /** "risk" / "risk-resolved": source warnings (total = number of risks, severity = worst). */
  kind: "new" | "resolved" | "risk" | "risk-resolved";
  repo: string;
  repoKey: string;
  machine: string | null;
  severity: Severity | null;
  total: number;
}

export interface MenuBar {
  version: string;
  generatedAt: string;
  state: MenuBarState;
  /** Distinct vulnerable packages in the repos' representative checkouts, by worst severity. */
  totals: Record<Severity, number>;
  /** Repos with serious findings, worst first (at most 10 of `attentionRepos`). */
  repos: Array<{ key: string; label: string; machine: string | null; branch: string | null; worstSeverity: Severity | null; serious: number }>;
  attentionRepos: number;
  moreRepos: number;
  /** Open source warnings that alert (high, or their rule asks), not dismissed, in active repos and this machine. */
  risks: { open: number; high: number; sources: number };
  trackedProjects: number;
  /** null: not macOS, or the schedule couldn't be read. */
  services: { sync: boolean; watcher: boolean; owner: "app" | "cli" | null } | null;
  lastSync: string | null;
  lastCheck: string | null;
  update: { available: boolean; latest: string | null };
  /** Latest findings and fixes of the repos (newest first), for "new since you looked". */
  events: MenuBarEvent[];
}

const MAX_REPOS = 10;
const MAX_EVENTS = 30;

export function menuBarState(totals: Record<Severity, number>, attention: number, services: MenuBar["services"]): MenuBarState {
  if (totals.malicious > 0) return "malicious";
  if (attention > 0) return "attention";
  if (services && (!services.sync || !services.watcher)) return "degraded";
  return "clean";
}

const worstOf = (list: Severity[]): Severity | null => list.sort((a, b) => severityRank(a) - severityRank(b))[0] ?? null;

function countRecords(): number {
  const count = (dir: string): number => {
    try {
      return recordFiles(readdirSync(dir)).length;
    } catch {
      return 0;
    }
  };
  return count(reposDir()) + loadConfig().machines.reduce((n, m) => n + count(machineReposDir(m.name)), 0);
}

export function getMenuBar(): MenuBar {
  const attention = getAttention();
  const totals: Record<Severity, number> = { malicious: 0, critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  const worst = new Map<string, Severity>();
  for (const r of attention) {
    for (const g of groupByPackage(r.findings)) {
      const k = packageKey(g);
      const prev = worst.get(k);
      if (!prev || severityRank(g.worst) < severityRank(prev)) worst.set(k, g.worst);
    }
  }
  for (const s of worst.values()) totals[s]++;
  const repos = attention
    .map((r) => ({ r, serious: r.findings.filter(needsAttention) }))
    .filter(({ serious }) => serious.length > 0)
    .map(({ r, serious }) => ({ key: r.key, label: r.label, machine: r.machine, branch: r.branch, worstSeverity: worstSeverity(serious), serious: groupByPackage(serious).length }))
    .sort((a, b) => severityRank(a.worstSeverity ?? "unknown") - severityRank(b.worstSeverity ?? "unknown") || b.serious - a.serious || a.label.localeCompare(b.label));
  let services: MenuBar["services"] = null;
  if (process.platform === "darwin") {
    try {
      const s = scheduleStatus();
      services = { sync: s.loaded, watcher: s.watcher.loaded, owner: s.owner };
    } catch {
      services = null;
    }
  }
  const state = loadState();
  const update = cachedUpdate();
  const risks = riskCounts();
  const events: MenuBarEvent[] = readEvents(300)
    .filter((e) => (e.kind === "new" || e.kind === "resolved" || e.kind === "risk" || e.kind === "risk-resolved") && e.active && !e.firstScan)
    .slice(0, MAX_EVENTS)
    .map((e) => ({
      at: e.at,
      kind: e.kind as MenuBarEvent["kind"],
      repo: e.repo,
      repoKey: e.repoKey,
      machine: e.machine ?? null,
      severity: worstOf([...e.packages.map((p) => p.severity), ...(e.risks ?? []).map((r) => r.severity)]),
      total: e.total,
    }));
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    // An open high risk needs attention like a serious vulnerability.
    state: menuBarState(totals, repos.length + (risks.high > 0 ? 1 : 0), services),
    totals,
    repos: repos.slice(0, MAX_REPOS),
    attentionRepos: repos.length,
    moreRepos: Math.max(0, repos.length - MAX_REPOS),
    risks,
    trackedProjects: countRecords(),
    services,
    lastSync: state.lastSync ?? null,
    lastCheck: state.lastCheck ?? null,
    update: { available: update.available, latest: update.latest },
    events,
  };
}

/** Rewrite ~/.selfguard/menubar.json. Never throws: the summary is a convenience. */
export function writeMenuBar(): MenuBar | null {
  try {
    const m = getMenuBar();
    ensureDir(stateRoot());
    atomicWrite(menuBarFile(), JSON.stringify(m));
    return m;
  } catch {
    return null;
  }
}
