import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { placeCheckouts } from "../canonical.ts";
import type { AttentionRepo } from "../alerts.ts";
import { loadConfig, type Config } from "../config.ts";
import { packageKey } from "../lockfile/types.ts";
import { expandRemote, loadMachineStatus } from "../machines.ts";
import { severityRank, type Severity } from "../match.ts";
import { worstSeverity } from "../report.ts";
import type { RepoIdentity } from "../repoid.ts";
import { checkoutId, findingKey, identityOf, listAllRepos, repoKeyOf, type Finding } from "../store.ts";
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

/** Watched folders per machine (null: this Mac), as used to bucket repos by folder. */
export function folderRoots(cfg: Config): Map<string | null, string[]> {
  const rootsOf = new Map<string | null, string[]>([[null, cfg.roots.map((r) => r.path)]]);
  for (const m of cfg.machines) {
    // Folders as the machine reported them (physical paths in restricted mode), else expanded.
    const st = loadMachineStatus(m.name);
    const reported = st.roots.filter((r) => r.ok).map((r) => r.path);
    rootsOf.set(m.name, [...reported, ...m.roots.map((r) => expandRemote(r.path, st.home))]);
  }
  return rootsOf;
}

export function getStatus(opts: { onlyVulnerable?: boolean } = {}): { repos: RepoGroup[]; projects: ProjectSummary[] } {
  const rank = (w: Severity | null): number => (w ? severityRank(w) : 99);
  const cfg = loadConfig();
  const records = listAllRepos(cfg.machines.map((m) => m.name));
  const activeDays = cfg.activeDays;
  const withRepo = records.map((rec) => ({ rec, repo: rec.machine || existsSync(rec.path) ? identityOf(rec) : null }));
  const dismissed = dismissalsFor(cfg, withRepo);
  const placed = placeCheckouts(withRepo.filter((c) => c.rec.machine || existsSync(c.rec.path)), activeDays, dismissed);
  const summaries = withRepo.map(({ rec, repo }) => summarize(rec, activeDays, dismissed, repo));
  const groups = new Map<string, { group: RepoGroup; rep: Finding[] | null; all: Finding[] }>();
  summaries.forEach((p, i) => {
    const rec = records[i]!;
    const place = placed.get(checkoutId(rec));
    const key = place?.key ?? repoKeyOf(p, p.repo);
    let g = groups.get(key);
    if (!g) {
      const label = place?.label ?? p.repo?.label ?? (p.path.split("/").pop() || p.path);
      g = {
        group: { key, label, machine: p.machine, active: false, dismissedAt: dismissed.get(key) ?? null, worstSeverity: null, vulnerablePackages: 0, inactiveCheckouts: 0, folder: null, checkouts: [] },
        rep: null,
        all: [],
      };
      groups.set(key, g);
    }
    const active = place?.active ?? p.active;
    g.group.checkouts.push({
      path: p.path,
      machine: p.machine,
      branch: p.repo?.branch ?? null,
      worktree: p.repo?.worktree ?? false,
      orphaned: p.repo?.orphaned ?? false,
      exists: p.exists,
      active,
      lastActivity: p.lastActivity,
      worstSeverity: p.worstSeverity,
      vulnerablePackages: p.vulnerablePackages,
      advisories: p.advisories,
      error: p.error,
      role: place?.role ?? (p.repo ? "branch" : "folder"),
      representative: place?.representative ?? false,
    });
    if (!active) g.group.inactiveCheckouts++;
    if (place?.representative) g.rep = rec.findings;
    g.all.push(...rec.findings);
  });
  const rootsOf = folderRoots(cfg);
  const repos = [...groups.values()]
    .map(({ group, rep, all }) => {
      group.active = group.checkouts.some((k) => k.active && k.role !== "copy");
      // The repo's state is its representative's: the fix is made there, once.
      const counted = rep ?? all;
      group.worstSeverity = worstSeverity(counted);
      group.vulnerablePackages = new Set(counted.map(packageKey)).size;
      // representative first, then active, main checkout first, then riskiest; copies last
      group.checkouts.sort(
        (a, b) =>
          Number(b.representative) - Number(a.representative) ||
          Number(a.role === "copy") - Number(b.role === "copy") ||
          Number(b.active) - Number(a.active) ||
          Number(a.worktree) - Number(b.worktree) ||
          rank(a.worstSeverity) - rank(b.worstSeverity) ||
          a.path.localeCompare(b.path),
      );
      const home = group.checkouts.find((k) => !k.worktree && k.role !== "copy") ?? group.checkouts[0];
      const roots = rootsOf.get(group.machine) ?? [];
      const f = home ? folderOf(home.path, roots) : null;
      const folder = f && { ...f, root: roots.includes(f.path) };
      group.folder = folder && group.machine ? { path: `${group.machine}:${folder.path}`, label: `${group.machine} › ${folder.label}`, root: folder.root } : folder;
      if (!f && group.machine) group.folder = { path: `${group.machine}:`, label: group.machine, root: true };
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
 * Input for reminders, the menu bar and the packages view: per active repo, the findings of
 * its representative checkout (see canonical.ts). Worktrees, other clones and copies share
 * the repo's vulnerabilities and get fixed with it, so they don't count again.
 */
export function getAttention(): Array<AttentionRepo & { key: string; path: string; machine: string | null; branch: string | null }> {
  const cfg = loadConfig();
  const present = listAllRepos(cfg.machines.map((m) => m.name))
    .filter((rec) => rec.machine || existsSync(rec.path))
    .map((rec) => ({ rec, repo: identityOf(rec) }));
  const placed = placeCheckouts(present, cfg.activeDays, dismissalsFor(cfg, present));
  const activeKeys = new Set<string>();
  for (const { rec } of present) {
    const p = placed.get(checkoutId(rec));
    if (p?.active && p.role !== "copy") activeKeys.add(p.key);
  }
  // A malicious package doesn't wait for a merge: any checkout's (or copy's) counts.
  const maliciousElsewhere = new Map<string, Finding[]>();
  for (const { rec } of present) {
    const p = placed.get(checkoutId(rec));
    if (!p || p.representative) continue;
    const bad = rec.findings.filter((f) => f.severity === "malicious");
    if (bad.length) maliciousElsewhere.set(p.key, [...(maliciousElsewhere.get(p.key) ?? []), ...bad]);
  }
  const out: Array<AttentionRepo & { key: string; path: string; machine: string | null; branch: string | null }> = [];
  for (const { rec, repo } of present) {
    const p = placed.get(checkoutId(rec));
    if (!p?.representative) continue;
    const extra = maliciousElsewhere.get(p.key) ?? [];
    // Repos nobody works on (or dismissed) aren't nagged about; their malicious packages
    // still alert when a scan finds them.
    if (!activeKeys.has(p.key)) continue;
    const findings = extra.length ? [...rec.findings, ...extra.filter((f) => !rec.findings.some((g) => findingKey(g) === findingKey(f)))] : rec.findings;
    if (findings.length === 0) continue;
    out.push({
      key: p.key,
      label: `${rec.machine ? `${rec.machine} · ` : ""}${p.label ?? repo?.label ?? (rec.path.split("/").pop() || rec.path)}`,
      path: rec.path,
      machine: rec.machine ?? null,
      branch: repo?.branch ?? null,
      findings,
    });
  }
  return out;
}
