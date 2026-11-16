import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { activityOf } from "../activity.ts";
import type { AttentionRepo } from "../alerts.ts";
import { loadConfig } from "../config.ts";
import { packageKey } from "../lockfile/types.ts";
import { expandRemote, loadMachineStatus } from "../machines.ts";
import { severityRank, type Severity } from "../match.ts";
import { worstSeverity } from "../report.ts";
import type { RepoIdentity } from "../repoid.ts";
import { identityOf, listAllRepos, repoKeyOf, type Finding, type RepoRecord } from "../store.ts";
import { dismissalsFor, summarize } from "./common.ts";
import type { ProjectSummary, RepoGroup } from "./shapes.ts";

// ---------- operations ----------

/** See RepoGroup.folder. */
export function folderOf(path: string, roots: string[]): { path: string; label: string } | null {
  const tilde = (p: string): string => {
    const h = homedir();
    return p === h ? "~" : p.startsWith(`${h}/`) ? `~${p.slice(h.length)}` : p;
  };
  const root = roots
    .filter((r) => path === r || path.startsWith(r.endsWith("/") ? r : `${r}/`))
    .sort((a, b) => b.length - a.length)[0];
  if (root === undefined) return null;
  const rest = path.slice(root.length).split("/").filter(Boolean);
  if (rest.length <= 1) return { path: root, label: tilde(root) };
  const dir = join(root, rest[0]!);
  return { path: dir, label: rest[0]! };
}

export function getStatus(opts: { onlyVulnerable?: boolean } = {}): { repos: RepoGroup[]; projects: ProjectSummary[] } {
  const rank = (w: Severity | null): number => (w ? severityRank(w) : 99);
  const cfg = loadConfig();
  const records = listAllRepos(cfg.machines.map((m) => m.name));
  const activeDays = cfg.activeDays;
  const withRepo = records.map((rec) => ({ rec, repo: rec.machine || existsSync(rec.path) ? identityOf(rec) : null }));
  const dismissed = dismissalsFor(cfg, withRepo);
  const summaries = withRepo.map(({ rec, repo }) => summarize(rec, activeDays, dismissed, repo));
  const groups = new Map<string, { group: RepoGroup; active: Finding[]; all: Finding[] }>();
  summaries.forEach((p, i) => {
    const rec = records[i]!;
    const key = repoKeyOf(p, p.repo);
    let g = groups.get(key);
    if (!g) {
      const label = p.repo?.label ?? (p.path.split("/").pop() || p.path);
      g = {
        group: { key, label, machine: p.machine, active: false, dismissedAt: dismissed.get(key) ?? null, worstSeverity: null, vulnerablePackages: 0, inactiveCheckouts: 0, folder: null, checkouts: [] },
        active: [],
        all: [],
      };
      groups.set(key, g);
    }
    g.group.checkouts.push({
      path: p.path,
      machine: p.machine,
      branch: p.repo?.branch ?? null,
      worktree: p.repo?.worktree ?? false,
      orphaned: p.repo?.orphaned ?? false,
      exists: p.exists,
      active: p.active,
      lastActivity: p.lastActivity,
      worstSeverity: p.worstSeverity,
      vulnerablePackages: p.vulnerablePackages,
      advisories: p.advisories,
      error: p.error,
    });
    if (p.active) g.active.push(...rec.findings);
    else g.group.inactiveCheckouts++;
    g.all.push(...rec.findings);
  });
  const rootsOf = new Map<string | null, string[]>([[null, cfg.roots.map((r) => r.path)]]);
  for (const m of cfg.machines) {
    // Folders as the machine reported them (physical paths in restricted mode), else expanded.
    const st = loadMachineStatus(m.name);
    const reported = st.roots.filter((r) => r.ok).map((r) => r.path);
    rootsOf.set(m.name, [...reported, ...m.roots.map((r) => expandRemote(r.path, st.home))]);
  }
  const repos = [...groups.values()]
    .map(({ group, active, all }) => {
      group.active = group.checkouts.some((k) => k.active);
      const counted = group.active ? active : all;
      group.worstSeverity = worstSeverity(counted);
      group.vulnerablePackages = new Set(counted.map(packageKey)).size;
      // active first, main checkout first, then riskiest
      group.checkouts.sort(
        (a, b) =>
          Number(b.active) - Number(a.active) ||
          Number(a.worktree) - Number(b.worktree) ||
          rank(a.worstSeverity) - rank(b.worstSeverity) ||
          a.path.localeCompare(b.path),
      );
      const home = group.checkouts.find((k) => !k.worktree) ?? group.checkouts[0];
      const f = home ? folderOf(home.path, rootsOf.get(group.machine) ?? []) : null;
      group.folder = f && group.machine ? { path: `${group.machine}:${f.path}`, label: `${group.machine} › ${f.label}` } : f;
      if (!f && group.machine) group.folder = { path: `${group.machine}:`, label: group.machine };
      return group;
    })
    .filter((g) => !opts.onlyVulnerable || g.checkouts.some((k) => k.vulnerablePackages > 0))
    .sort(
      (a, b) =>
        Number(b.active) - Number(a.active) ||
        rank(a.worstSeverity) - rank(b.worstSeverity) ||
        b.vulnerablePackages - a.vulnerablePackages ||
        a.label.localeCompare(b.label),
    );
  const projects = summaries
    .filter((p) => !opts.onlyVulnerable || p.advisories > 0)
    .sort((a, b) => rank(a.worstSeverity) - rank(b.worstSeverity) || b.advisories - a.advisories || a.path.localeCompare(b.path));
  return { repos, projects };
}

/**
 * Input for reminders: per repo, the findings of the checkout that represents it — the main
 * clone if it is active, otherwise the most recently active checkout. Feature worktrees
 * branched from an old base get fixed when they merge, so they don't count twice.
 */
export function getAttention(): Array<AttentionRepo & { key: string; path: string; machine: string | null; branch: string | null }> {
  const cfg = loadConfig();
  const activeDays = cfg.activeDays;
  const best = new Map<string, { rec: RepoRecord; repo: RepoIdentity | null; main: boolean; at: number }>();
  const present = listAllRepos(cfg.machines.map((m) => m.name))
    .filter((rec) => rec.machine || existsSync(rec.path))
    .map((rec) => ({ rec, repo: identityOf(rec) }));
  const dismissed = dismissalsFor(cfg, present);
  for (const { rec, repo } of present) {
    const key = repoKeyOf(rec, repo);
    const act = activityOf(repo, activeDays, Date.now(), dismissed.get(key) ?? null);
    if (!act.active) continue;
    const cand = { rec, repo, main: !(repo?.worktree ?? false), at: act.lastActivity ? Date.parse(act.lastActivity) : 0 };
    const cur = best.get(key);
    if (!cur || (cand.main && !cur.main) || (cand.main === cur.main && cand.at > cur.at)) best.set(key, cand);
  }
  return [...best.entries()]
    .filter(([, b]) => b.rec.findings.length > 0)
    .map(([key, b]) => ({
      key,
      label: `${b.rec.machine ? `${b.rec.machine} · ` : ""}${b.repo?.label ?? (b.rec.path.split("/").pop() || b.rec.path)}`,
      path: b.rec.path,
      machine: b.rec.machine ?? null,
      branch: b.repo?.branch ?? null,
      findings: b.rec.findings,
    }));
}
