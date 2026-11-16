import { loadConfig } from "../config.ts";
import { ApiError } from "../errors.ts";
import { packageKey } from "../lockfile/types.ts";
import { renderMarkdown, type MarkdownCheckout } from "../markdown.ts";
import { severityRank } from "../match.ts";
import { loadRepo } from "../store.ts";
import { resolveProject, toReport } from "./common.ts";
import type { ProjectReport, RepoGroup, VulnerablePackage } from "./shapes.ts";
import { getStatus } from "./status.ts";

export interface RepoPackage extends VulnerablePackage {
  /** Checkouts where this exact version is installed. */
  checkouts: Array<{ path: string; machine: string | null; branch: string | null; active: boolean }>;
}

export interface RepoDetail {
  key: string;
  label: string;
  machine: string | null;
  dismissedAt: string | null;
  checkouts: RepoGroup["checkouts"];
  packages: RepoPackage[];
}

/** All vulnerable packages of one repo group, merged across its checkouts (no network). */
export function getRepoDetail(key: string): RepoDetail {
  const group = getStatus().repos.find((g) => g.key === key);
  if (!group) throw new ApiError("not_found", "unknown repo");
  const byPkg = new Map<string, RepoPackage>();
  for (const k of group.checkouts) {
    const rec = loadRepo(k.path, k.machine);
    if (!rec) continue;
    for (const p of toReport(rec).vulnerable) {
      const id = packageKey(p);
      let entry = byPkg.get(id);
      if (!entry) {
        entry = { ...p, checkouts: [] };
        byPkg.set(id, entry);
      }
      entry.checkouts.push({ path: k.path, machine: k.machine, branch: k.branch, active: k.active });
    }
  }
  const rank = (p: RepoPackage): number => (p.checkouts.some((c) => c.active) ? 0 : 1);
  const packages = [...byPkg.values()].sort(
    (a, b) =>
      rank(a) - rank(b) ||
      severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
      Number(a.dev) - Number(b.dev) ||
      Number(b.direct) - Number(a.direct) ||
      a.name.localeCompare(b.name),
  );
  return { key: group.key, label: group.label, machine: group.machine, dismissedAt: group.dismissedAt, checkouts: group.checkouts, packages };
}

/**
 * Markdown report (see markdown.ts). With `path`, only that checkout of
 * the repo; otherwise every checkout, merged.
 */
export function getRepoMarkdown(key: string, opts: { path?: string } = {}): { markdown: string; packages: number } {
  const detail = getRepoDetail(key);
  const scoped = opts.path === undefined ? detail.checkouts : detail.checkouts.filter((k) => k.path === opts.path);
  if (scoped.length === 0) throw new ApiError("not_found", "unknown checkout");
  const paths = new Set(scoped.map((k) => k.path));
  const checkouts: MarkdownCheckout[] = scoped.map((k) => {
    const rec = loadRepo(k.path, k.machine);
    return { path: k.path, machine: k.machine, host: k.machine ? machineHost(k.machine) : null, branch: k.branch, lockfile: rec?.lockfile ?? null, lockType: rec?.lockType ?? null, scannedAt: rec?.scannedAt ?? null };
  });
  const packages = detail.packages
    .map((p) => ({ ...p, checkouts: p.checkouts.map((c) => c.path).filter((c) => paths.has(c)) }))
    .filter((p) => p.checkouts.length > 0);
  return { markdown: renderMarkdown({ label: detail.label, checkouts, packages }), packages: packages.length };
}

function machineHost(name: string): string | null {
  return loadConfig().machines.find((m) => m.name === name)?.host ?? null;
}

/** Same report for a single project path (CLI `report --markdown`). */
export function getReportMarkdown(path: string): { markdown: string; packages: number } {
  const report = getReport(path);
  const markdown = renderMarkdown({
    label: report.repo?.label ?? (report.path.split("/").pop() || report.path),
    checkouts: [{ path: report.path, machine: null, host: null, branch: report.repo?.branch ?? null, lockfile: report.lockfile, lockType: report.lockType, scannedAt: report.scannedAt }],
    packages: report.vulnerable,
  });
  return { markdown, packages: report.vulnerable.length };
}

/** Last stored report for a project (no network). */
export function getReport(path: string): ProjectReport {
  const project = resolveProject(path);
  const rec = loadRepo(project.root);
  if (!rec) throw new ApiError("not_tracked", `${project.root} is not tracked yet; scan it first`);
  return toReport(rec);
}
