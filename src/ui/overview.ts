/** What the dashboard shows at a glance (GET /api/overview) and the update status. */
import { needsAttention } from "../alerts.ts";
import * as api from "../api.ts";
import { readEvents } from "../events.ts";
import { loadConfig } from "../config.ts";
import { severityRank, type Severity } from "../match.ts";
import { groupByPackage } from "../report.ts";
import { scheduleStatus } from "../schedule.ts";
import { cachedUpdate, checkForUpdate, installedVersion } from "../update.ts";
import { VERSION } from "../version.ts";
import { packageKey } from "../lockfile/types.ts";

export interface Overview {
  version: string;
  generatedAt: string;
  settings: api.Settings;
  schedule: { enabled: boolean; watcher: boolean; watchedPaths: number; remote: boolean } | null;
  /** Newer version available (the Mac app updates itself; see update.ts). */
  update: unknown;
  /** Sharing on this machine, and pairing requests waiting for approval. */
  share: { enabled: boolean; requests: number };
  /** Other machines and how their last sync went. */
  machines: Array<{ name: string; host: string; os: string | null; lastSync: string | null; error: string | null; trackedProjects: number; roots: number }>;
  roots: number;
  /** Distinct vulnerable packages in active checkouts, by worst severity. */
  totals: Record<Severity, number>;
  /** Repos with serious findings (see alerts.needsAttention) on their representative checkout. */
  needsAttention: string[];
  /** Repo key → number of serious vulnerable packages. */
  seriousByRepo: Record<string, number>;
  trackedProjects: number;
  activeCheckouts: number;
  repos: api.RepoGroup[];
  events: ReturnType<typeof readEvents>;
}

export function getOverview(): Overview {
  const status = api.getStatus();
  const attention = api.getAttention();
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
  let schedule: Overview["schedule"] = null;
  if (process.platform === "darwin") {
    try {
      const s = scheduleStatus();
      schedule = { enabled: s.loaded, watcher: s.watcher.loaded, watchedPaths: s.watcher.paths, remote: s.remote.loaded };
    } catch {
      schedule = null;
    }
  }
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    settings: api.getSettings(),
    schedule,
    roots: api.listRoots().roots.length,
    update: updateStatus(),
    share: (() => {
      const cfg = loadConfig();
      return { enabled: cfg.share.enabled, requests: cfg.share.enabled ? api.listShareRequests().length : 0 };
    })(),
    machines: api.listMachines().map((m) => ({
      name: m.name,
      host: m.host,
      os: m.status.os,
      lastSync: m.status.lastSync,
      error: m.status.error,
      trackedProjects: m.trackedProjects,
      roots: m.roots.length,
    })),
    totals,
    needsAttention: attention.filter((r) => r.findings.some(needsAttention)).map((r) => r.key),
    seriousByRepo: Object.fromEntries(
      attention.map((r) => [r.key, groupByPackage(r.findings.filter(needsAttention)).length]).filter(([, n]) => (n as number) > 0),
    ),
    trackedProjects: status.projects.length,
    activeCheckouts: status.projects.filter((p) => p.active && p.exists).length,
    repos: status.repos,
    events: readEvents(80),
  };
}

/** What the page needs to keep the user up to date (no network; a stale check runs in the background). */
let updateCheckRunning = false;
export function updateStatus(): unknown {
  const info = cachedUpdate();
  const installed = installedVersion();
  if (info.enabled && !updateCheckRunning && (!info.checkedAt || Date.now() - Date.parse(info.checkedAt) > 24 * 60 * 60 * 1000)) {
    updateCheckRunning = true;
    void checkForUpdate().finally(() => {
      updateCheckRunning = false;
    });
  }
  return { ...info, installed, available: info.available && !(info.latest && installed === info.latest) };
}
