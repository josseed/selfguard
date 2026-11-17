/** Internal helpers shared by the api/* modules (not part of the public api surface, except toReport). */
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { activityOf } from "../activity.ts";
import { loadConfig } from "../config.ts";
import { ApiError } from "../errors.ts";
import { findProject, type Project } from "../lockfile/detect.ts";
import { liveDismissals } from "../dismiss.ts";
import { countBySeverity, groupByPackage, worstSeverity } from "../report.ts";
import type { RepoIdentity } from "../repoid.ts";
import { identityOf, packagesOf, repoKeyOf, type RepoRecord } from "../store.ts";
import type { ProjectReport, ProjectSummary } from "./shapes.ts";

export const advisoryUrl = (id: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;

// ---------- helpers ----------

export const machineNames = (): string[] => loadConfig().machines.map((m) => m.name);

/** Dismissals still in effect (no git activity since), from the given checkouts' activity. */
export function dismissalsFor(cfg: ReturnType<typeof loadConfig>, checkouts: Array<{ rec: RepoRecord; repo: RepoIdentity | null }>): Map<string, string> {
  if (cfg.dismissed.length === 0) return new Map();
  return liveDismissals(cfg.dismissed, checkouts.map(({ rec, repo }) => ({ key: repoKeyOf(rec, repo), lastActivity: repo?.lastActivity ?? null })));
}

export function summarize(rec: RepoRecord, activeDays = loadConfig().activeDays, dismissed: Map<string, string> = new Map(), repoIn?: RepoIdentity | null): ProjectSummary {
  // Remote checkouts exist as long as the last sync of their machine found them.
  const exists = rec.machine ? true : existsSync(rec.path);
  const repo = exists ? (repoIn !== undefined ? repoIn : identityOf(rec)) : null;
  const activity = exists
    ? activityOf(repo, activeDays, Date.now(), dismissed.get(repoKeyOf(rec, repo)) ?? null)
    : { active: false, lastActivity: null, dismissed: false };
  return {
    path: rec.path,
    machine: rec.machine ?? null,
    exists,
    lockfile: rec.lockfile,
    lockType: rec.lockType,
    packages: packagesOf(rec),
    skippedEntries: rec.skipped,
    scannedAt: rec.scannedAt,
    error: rec.error ?? null,
    worstSeverity: worstSeverity(rec.findings),
    vulnerablePackages: groupByPackage(rec.findings).length,
    advisories: rec.findings.length,
    bySeverity: countBySeverity(rec.findings),
    repo,
    active: activity.active,
    lastActivity: activity.lastActivity,
    dismissed: activity.dismissed,
  };
}

export function toReport(rec: RepoRecord): ProjectReport {
  return {
    ...summarize(rec),
    vulnerable: groupByPackage(rec.findings).map((g) => ({
      name: g.name,
      version: g.version,
      ecosystem: g.ecosystem,
      direct: g.direct,
      dev: g.dev,
      worstSeverity: g.worst,
      upgradeTo: g.worst === "malicious" ? null : (g.upgradeTo ?? null),
      advisoriesWithoutFix: g.unfixed,
      advisories: g.findings.map((f) => ({
        id: f.id,
        aliases: f.aliases,
        severity: f.severity,
        summary: f.summary,
        fixedIn: f.fixedIn ?? null,
        firstSeen: f.firstSeen,
        url: advisoryUrl(f.id),
      })),
    })),
  };
}

export function resolveProject(path: string): Project {
  const abs = resolve(path);
  if (!existsSync(abs)) throw new ApiError("not_found", `no such directory: ${abs}`);
  const project = findProject(abs);
  if (!project) throw new ApiError("no_project", `no lockfile or package.json found in ${abs} or its parents`);
  return project;
}
