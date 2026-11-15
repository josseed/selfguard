/**
 * Structured operations shared by the CLI (`--json`) and the MCP server.
 * Every function returns plain JSON-serializable data with a stable shape
 * (documented in src/guide.ts). Human rendering lives elsewhere.
 */
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { activityOf } from "./activity.ts";
import type { AttentionRepo } from "./alerts.ts";
import { announce } from "./announce.ts";
import {
  candidateRoots,
  clampDepth,
  DEFAULT_DEPTH,
  isExcluded,
  loadConfig,
  normalizeDir,
  REMIND_VALUES,
  saveConfig,
  type RemindEvery,
  type Root,
} from "./config.ts";
import { discoverAll } from "./discover.ts";
import { tryLock } from "./fsutil.ts";
import { findProject, type Project } from "./lockfile/detect.ts";
import type { LockfileType } from "./lockfile/types.ts";
import { evaluate, severityOf, severityRank, type Severity } from "./match.ts";
import { getVulns, type OsvVuln } from "./osv.ts";
import { countBySeverity, groupByPackage, worstSeverity } from "./report.ts";
import { compare as compareVersions, isValid as isValidVersion } from "./semver.ts";
import { renderMarkdown, type MarkdownCheckout } from "./markdown.ts";
import { repoIdentity, type RepoIdentity } from "./repoid.ts";
import { clean } from "./sanitize.ts";
import { lockChanged, scanProjects, type ScanOutcome } from "./scan.ts";
import { loadState, updateState } from "./state.ts";
import { checkoutId, forgetRepo, identityOf, listAllRepos, listRepos, loadRepo, repoKeyOf, saveRepo, type Finding, type RepoRecord } from "./store.ts";
import { liveDismissals, pruneDismissals, trackedActivity } from "./dismiss.ts";
import { expandRemote, loadMachineStatus, syncMachine, syncMachines, getMachine, type MachineSyncResult } from "./machines.ts";

import { ApiError } from "./errors.ts";
import { appendEvents } from "./events.ts";
import { discoverEverywhere, groupPlaces, PROTECTED, type EverywhereProgress, type Place } from "./everywhere.ts";
import { notify } from "./notify.ts";
import { tildify } from "./report.ts";

export { ApiError };

const advisoryUrl = (id: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;

// ---------- shapes ----------

export interface ProjectSummary {
  path: string;
  /** Remote machine name (config.machines), null for this machine. */
  machine: string | null;
  exists: boolean;
  lockfile: string | null;
  lockType: LockfileType | null;
  packages: number;
  skippedEntries: number;
  scannedAt: string | null;
  error: string | null;
  worstSeverity: Severity | null;
  vulnerablePackages: number;
  advisories: number;
  bySeverity: Partial<Record<Severity, number>>;
  /** Repository this checkout belongs to (null when it isn't in a git repo). */
  repo: RepoIdentity | null;
  /** Git activity in the last `activeDays` days. Inactive checkouts only alert for malicious packages. */
  active: boolean;
  lastActivity: string | null;
  /** Its repo was turned off by the user and has had no git activity since (implies !active). */
  dismissed: boolean;
}

/** Worktrees / clones of the same repo (and same subfolder) grouped together. */
export interface RepoGroup {
  key: string;
  label: string;
  /** Remote machine of these checkouts (null: this machine). Repos never span machines. */
  machine: string | null;
  /** At least one checkout has recent git activity. */
  active: boolean;
  /** When the user turned this repo off (null: not dismissed). Comes back with new git activity. */
  dismissedAt: string | null;
  /** Worst severity across active checkouts (all checkouts if none is active). */
  worstSeverity: Severity | null;
  /** Distinct vulnerable name@version across active checkouts (all checkouts if none is active). */
  vulnerablePackages: number;
  inactiveCheckouts: number;
  /**
   * Folder the repo is filed under: the first folder below the watched root that holds its
   * main checkout (e.g. ~/code/acme for ~/code/acme/api). Repos directly in a root are filed
   * under the root. null when the checkout is outside every watched root.
   */
  folder: { path: string; label: string } | null;
  checkouts: Array<{
    path: string;
    machine: string | null;
    branch: string | null;
    worktree: boolean;
    orphaned: boolean;
    exists: boolean;
    active: boolean;
    lastActivity: string | null;
    worstSeverity: Severity | null;
    vulnerablePackages: number;
    advisories: number;
    error: string | null;
  }>;
}

export interface AdvisoryRef {
  id: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  fixedIn: string | null;
  firstSeen: string;
  url: string;
}

export interface VulnerablePackage {
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  worstSeverity: Severity;
  /** Lowest version that fixes every advisory that has a fix (null: none published). */
  upgradeTo: string | null;
  advisoriesWithoutFix: number;
  advisories: AdvisoryRef[];
}

export interface ProjectReport extends ProjectSummary {
  vulnerable: VulnerablePackage[];
}

// ---------- helpers ----------

const machineNames = (): string[] => loadConfig().machines.map((m) => m.name);

/** Dismissals still in effect (no git activity since), from the given checkouts' activity. */
function dismissalsFor(cfg: ReturnType<typeof loadConfig>, checkouts: Array<{ rec: RepoRecord; repo: RepoIdentity | null }>): Map<string, string> {
  if (cfg.dismissed.length === 0) return new Map();
  return liveDismissals(cfg.dismissed, checkouts.map(({ rec, repo }) => ({ key: repoKeyOf(rec, repo), lastActivity: repo?.lastActivity ?? null })));
}

function summarize(rec: RepoRecord, activeDays = loadConfig().activeDays, dismissed: Map<string, string> = new Map(), repoIn?: RepoIdentity | null): ProjectSummary {
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
    packages: rec.deps.length,
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

function resolveProject(path: string): Project {
  const abs = resolve(path);
  if (!existsSync(abs)) throw new ApiError("not_found", `no such directory: ${abs}`);
  const project = findProject(abs);
  if (!project) throw new ApiError("no_project", `no package.json found in ${abs} or its parents`);
  return project;
}

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
      group.vulnerablePackages = new Set(counted.map((f) => `${f.name}@${f.version}`)).size;
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
      const id = `${p.name}@${p.version}`;
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

export interface ScanResult {
  project: ProjectReport;
  firstScan: boolean;
  newAdvisories: number;
}

export async function scanPath(path: string, opts: { notify?: boolean } = {}): Promise<ScanResult> {
  const project = resolveProject(path);
  const release = tryLock(`scan:${project.root}`);
  if (!release) throw new ApiError("busy", "another scan of this project is running, try again in a moment");
  try {
    const [o] = await scanProjects([project]);
    saveRepo(o!.record);
    await announce([o!], { notify: opts.notify ?? false });
    return { project: toReport(o!.record), firstScan: o!.firstScan, newAdvisories: o!.newFindings.length };
  } finally {
    release();
  }
}

export interface SyncResult {
  projects: number;
  discovered: string[];
  /** Tracked folders that no longer exist (e.g. removed worktrees); no longer tracked. */
  pruned: string[];
  /** Per project, vulnerable packages with advisories not seen before. */
  news: Array<{ path: string; machine: string | null; packages: Array<{ name: string; version: string; worstSeverity: Severity; advisories: string[] }> }>;
  errors: Array<{ path: string; machine: string | null; error: string }>;
  /** Remote machines (config.machines): whether each one answered. */
  machines: MachineSummary[];
  /** Raw outcomes for notifications (not serialized). */
  outcomes: ScanOutcome[];
}

export interface MachineSummary {
  name: string;
  ok: boolean;
  error: string | null;
  projects: number;
  discovered: number;
  rescanned: number;
}

const summarizeMachine = (r: MachineSyncResult): MachineSummary => ({
  name: r.name,
  ok: r.ok,
  error: r.error,
  projects: r.projects,
  discovered: r.discovered.length,
  rescanned: r.outcomes.length,
});

function newsOf(outcomes: ScanOutcome[]): SyncResult["news"] {
  return outcomes
    .filter((o) => o.newFindings.length > 0)
    .map((o) => ({
      path: o.record.path,
      machine: o.record.machine ?? null,
      packages: groupByPackage(o.newFindings).map((g) => ({
        name: g.name,
        version: g.version,
        worstSeverity: g.worst,
        advisories: g.findings.map((f) => f.id),
      })),
    }));
}

const errorsOf = (outcomes: ScanOutcome[]): SyncResult["errors"] =>
  outcomes.filter((o) => o.record.error).map((o) => ({ path: o.record.path, machine: o.record.machine ?? null, error: o.record.error! }));

export async function sync(opts: { notify?: boolean } = {}): Promise<SyncResult> {
  const release = tryLock("sync");
  if (!release) throw new ApiError("busy", "a sync is already running");
  try {
    const cfg = loadConfig();
    const projects: Project[] = [];
    const seen = new Set<string>();
    const pruned: string[] = [];
    for (const r of listRepos()) {
      if (!existsSync(r.path)) {
        forgetRepo(r.path); // e.g. a worktree you removed: nothing left to protect
        pruned.push(r.path);
        continue;
      }
      if (isExcluded(r.path, cfg.exclude)) continue;
      const p = findProject(r.path);
      if (p && p.root === r.path) {
        projects.push(p);
        seen.add(p.root);
      }
    }
    // New clones inside your folders get tracked without you ever cd-ing into them.
    const discovered = (await discoverAll(cfg.roots, { exclude: cfg.exclude })).filter((p) => !seen.has(p.root));
    projects.push(...discovered);

    const local = await scanProjects(projects);
    for (const o of local) saveRepo(o.record);
    // Other machines: same checks, one SSH session at a time; a machine that doesn't answer
    // keeps its last results and shows the error.
    const remote = await syncMachines({ full: true });
    const outcomes = [...local, ...remote.flatMap((r) => r.outcomes)];
    await announceMachines(local, remote, opts.notify ?? false);
    updateState({ lastSync: new Date().toISOString() });
    pruneDismissed(loadConfig());
    return {
      projects: projects.length + remote.reduce((n, r) => n + r.projects, 0),
      discovered: discovered.map((p) => p.root),
      pruned,
      news: newsOf(outcomes),
      errors: errorsOf(outcomes),
      machines: remote.map(summarizeMachine),
      outcomes,
    };
  } finally {
    release();
  }
}

export interface DiscoverResult {
  dryRun: boolean;
  found: Array<{ path: string; lockType: LockfileType | null }>;
  registered: number;
  withVulnerabilities: number;
}

export async function discoverNew(opts: { dryRun?: boolean } = {}): Promise<DiscoverResult> {
  const cfg = loadConfig();
  if (cfg.roots.length === 0) throw new ApiError("no_roots", "no folders configured; add one with roots add <dir>");
  const known = new Set(listRepos().map((r) => r.path));
  const fresh = (await discoverAll(cfg.roots, { exclude: cfg.exclude })).filter((p) => !known.has(p.root));
  const found = fresh.map((p) => ({ path: p.root, lockType: p.lockType }));
  if (opts.dryRun || fresh.length === 0) return { dryRun: Boolean(opts.dryRun), found, registered: 0, withVulnerabilities: 0 };
  const outcomes = await scanProjects(fresh);
  for (const o of outcomes) saveRepo(o.record);
  await announce(outcomes, { notify: false });
  return {
    dryRun: false,
    found,
    registered: outcomes.length,
    withVulnerabilities: outcomes.filter((o) => o.record.findings.length > 0).length,
  };
}

export interface WhereResult {
  package: string;
  usedIn: Array<{ path: string; machine: string | null; versions: Array<{ version: string; direct: boolean; dev: boolean; vulnerable: boolean }> }>;
}

export function whereUsed(name: string): WhereResult {
  const usedIn: WhereResult["usedIn"] = [];
  for (const r of listAllRepos(machineNames())) {
    const versions = r.deps
      .filter((d) => d.name === name)
      .map((d) => ({
        version: d.version,
        direct: d.direct,
        dev: d.dev,
        vulnerable: r.findings.some((f) => f.name === name && f.version === d.version),
      }));
    if (versions.length) usedIn.push({ path: r.path, machine: r.machine ?? null, versions });
  }
  return { package: name, usedIn };
}

export interface RootsResult {
  roots: Root[];
  exclude: string[];
}

export function listRoots(): RootsResult {
  const { roots, exclude } = loadConfig();
  return { roots, exclude };
}

export function addRoot(path: string, depth?: number): RootsResult {
  const dir = normalizeDir(path);
  if (!dir) throw new ApiError("not_found", `not a directory: ${path}`);
  const cfg = loadConfig();
  const d = depth === undefined ? DEFAULT_DEPTH : clampDepth(depth);
  cfg.roots = [...cfg.roots.filter((r) => r.path !== dir), { path: dir, depth: d }];
  saveConfig(cfg);
  return { roots: cfg.roots, exclude: cfg.exclude };
}

export function removeRoot(path: string): RootsResult & { removed: boolean } {
  const cfg = loadConfig();
  const abs = normalizeDir(path) ?? resolve(path);
  const before = cfg.roots.length;
  cfg.roots = cfg.roots.filter((r) => r.path !== abs);
  saveConfig(cfg);
  const removed = cfg.roots.length < before;
  // Removed on purpose: automatic discovery won't add it back.
  if (removed) updateState({ dismissedPlaces: [...new Set([...(loadState().dismissedPlaces ?? []), abs])] });
  return { roots: cfg.roots, exclude: cfg.exclude, removed };
}

// ---------- find my projects (whole home folder) ----------

export interface EverywhereScan {
  home: string;
  places: Place[];
  projects: number;
  visited: number;
  ms: number;
  /** Zones cut short (too many folders, no project). */
  heavy: string[];
  /** Folders we couldn't read (permissions / macOS privacy). */
  denied: string[];
  /** Protected folders skipped on purpose. */
  skipped: string[];
}

/** Search the whole home folder and group what's found into places. Read-only. */
export async function findEverywhere(
  opts: { skipProtected?: boolean; onProgress?: (p: EverywhereProgress) => void; isCancelled?: () => boolean } = {},
): Promise<EverywhereScan> {
  const cfg = loadConfig();
  const r = await discoverEverywhere({ exclude: cfg.exclude, skipProtected: opts.skipProtected, onProgress: opts.onProgress, isCancelled: opts.isCancelled });
  updateState({ lastEverywhere: new Date().toISOString() });
  return {
    home: r.home,
    places: groupPlaces(r.projects, r.home, cfg.roots, cfg.activeDays, Date.now(), cfg.dismissed.length ? liveDismissals(cfg.dismissed, trackedActivity(cfg)) : new Map()),
    projects: r.projects.length,
    visited: r.visited,
    ms: r.ms,
    heavy: r.heavy,
    denied: r.denied,
    skipped: r.skipped,
  };
}

export interface ApplyPlacesResult {
  watching: Root[];
  excluded: string[];
  discovered: DiscoverResult | null;
}

/**
 * Watch the chosen places (folders + depth) and exclude the rejected ones, then register and
 * scan the new projects. Paths must be existing folders.
 */
export async function applyPlaces(watch: Array<{ path: string; depth: number }>, ignore: string[] = []): Promise<ApplyPlacesResult> {
  const watching: Root[] = [];
  for (const w of watch) {
    const dir = normalizeDir(w.path);
    if (!dir) throw new ApiError("not_found", `not a directory: ${w.path}`);
    if (!Number.isInteger(w.depth)) throw new ApiError("invalid", "depth must be an integer");
    const cfg = loadConfig();
    const existing = cfg.roots.find((r) => r.path === dir);
    const depth = Math.max(clampDepth(w.depth), existing?.depth ?? 0);
    addRoot(dir, depth);
    watching.push({ path: dir, depth });
  }
  const excluded: string[] = [];
  if (ignore.length) {
    const cfg = loadConfig();
    for (const path of ignore) {
      const dir = normalizeDir(path);
      if (!dir || cfg.exclude.includes(dir) || cfg.roots.some((r) => r.path === dir)) continue;
      cfg.exclude.push(dir);
      excluded.push(dir);
    }
    saveConfig(cfg);
  }
  const discovered = loadConfig().roots.length ? await discoverNew() : null;
  return { watching, excluded, discovered };
}

export interface AutoDiscoverResult {
  ran: boolean;
  reason: string | null;
  added: Array<{ path: string; depth: number; active: number; projects: number }>;
  scan: EverywhereScan | null;
}

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * The weekly background pass: search the home folder and start watching new places that
 * have repos with recent git activity (unless excluded or removed by the user before),
 * with a notification. Their current findings are the baseline: logged, not alerted.
 * Protected macOS folders are only searched if a watched folder already lives there.
 */
export async function autoDiscover(opts: { force?: boolean; notify?: boolean } = {}): Promise<AutoDiscoverResult> {
  const cfg = loadConfig();
  if (!cfg.autoDiscover && !opts.force) return { ran: false, reason: "automatic discovery is off", added: [], scan: null };
  const last = loadState().lastEverywhere;
  if (!opts.force && last && Date.now() - Date.parse(last) < WEEK_MS - 12 * 60 * 60 * 1000) {
    return { ran: false, reason: "ran less than a week ago", added: [], scan: null };
  }
  const release = tryLock("everywhere");
  if (!release) throw new ApiError("busy", "a search is already running");
  try {
    const home = homedir();
    const protectedAllowed = cfg.roots.some((r) => PROTECTED.some((p) => r.path === join(home, p) || r.path.startsWith(join(home, p) + "/")));
    const scan = await findEverywhere({ skipProtected: process.platform === "darwin" && !protectedAllowed });
    const dismissed = loadState().dismissedPlaces ?? [];
    const fresh = scan.places.filter((p) => p.recommended && !dismissed.some((d) => p.path === d || p.path.startsWith(d + "/")));
    if (fresh.length === 0) return { ran: true, reason: null, added: [], scan };
    const res = await applyPlaces(fresh.map((p) => ({ path: p.path, depth: p.depth })));
    const added = fresh.map((p) => ({ path: p.path, depth: p.depth, active: p.active, projects: p.projects }));
    const at = new Date().toISOString();
    appendEvents(added.map((a) => ({
      at, kind: "watching" as const, repo: tildify(a.path), repoKey: `place:${a.path}`, path: a.path, branch: null, active: true, total: a.projects, packages: [],
    })));
    if (opts.notify !== false) {
      const title = added.length === 1 ? `selfguard: now watching ${tildify(added[0]!.path)}` : `selfguard: now watching ${added.length} new folders`;
      const body = added.length === 1
        ? `${added[0]!.active} active repo(s) found there${res.discovered?.withVulnerabilities ? `, ${res.discovered.withVulnerabilities} with vulnerabilities` : ""}. Remove it in Folders if you don't want it.`
        : added.map((a) => tildify(a.path)).join(", ");
      await notify(title, body, "Find my projects");
    }
    return { ran: true, reason: null, added, scan };
  } finally {
    release();
  }
}

/**
 * Stop tracking a path. With `exclude` (default), it's also excluded from discovery
 * so it never comes back (use for fixtures, examples, archived repos).
 */
export function forget(path: string, opts: { exclude?: boolean } = {}): { path: string; wasTracked: boolean; excluded: boolean; alsoForgotten: string[] } {
  const abs = normalizeDir(path) ?? resolve(path);
  const root = loadRepo(abs) ? abs : (findProject(abs)?.root ?? abs);
  const wasTracked = forgetRepo(root);
  const alsoForgotten: string[] = [];
  const exclude = opts.exclude ?? true;
  if (exclude) {
    const cfg = loadConfig();
    if (!cfg.exclude.includes(root)) cfg.exclude.push(root);
    saveConfig(cfg);
    // Excluding a folder also drops tracked projects below it.
    for (const r of listRepos()) {
      if (r.path !== root && isExcluded(r.path, [root])) {
        forgetRepo(r.path);
        alsoForgotten.push(r.path);
      }
    }
  }
  return { path: root, wasTracked, excluded: exclude, alsoForgotten };
}

export function unexclude(path: string): RootsResult & { removed: boolean } {
  const cfg = loadConfig();
  const abs = normalizeDir(path) ?? resolve(path);
  const before = cfg.exclude.length;
  cfg.exclude = cfg.exclude.filter((e) => e !== abs);
  saveConfig(cfg);
  return { roots: cfg.roots, exclude: cfg.exclude, removed: cfg.exclude.length < before };
}

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
  if (cfg.dismissed.length < before) saveConfig(cfg);
  return { key, removed: cfg.dismissed.length < before };
}

/** Forget dismissals of repos that came back (git activity since). Never fails a scan. */
function pruneDismissed(cfg: ReturnType<typeof loadConfig>): void {
  try {
    if (cfg.dismissed.length && pruneDismissals(cfg, trackedActivity(cfg)).length) saveConfig(cfg);
  } catch {
    /* best effort */
  }
}

/** A machine's first sync is logged (Activity) but not notified: it is the baseline. */
async function announceMachines(local: ScanOutcome[], remote: MachineSyncResult[], notify: boolean): Promise<void> {
  const baseline = remote.filter((r) => r.initial).flatMap((r) => r.outcomes);
  const live = [...local, ...remote.filter((r) => !r.initial).flatMap((r) => r.outcomes)];
  if (baseline.length) await announce(baseline, { notify: false });
  await announce(live, { notify });
}

export interface MachinesCheckResult {
  machines: MachineSummary[];
  news: SyncResult["news"];
  errors: SyncResult["errors"];
}

/**
 * Quick pass over remote machines: new projects and changed lockfiles only (one SSH
 * listing per machine, files fetched only when they changed). Run every 15 minutes by
 * the background agent; `sync` does the full re-check.
 */
export async function checkMachines(opts: { notify?: boolean; only?: string[] } = {}): Promise<MachinesCheckResult> {
  const release = tryLock("sync");
  if (!release) throw new ApiError("busy", "a sync is already running");
  try {
    if (opts.only) for (const n of opts.only) getMachineOrThrow(n);
    const remote = await syncMachines({ full: false, only: opts.only });
    const outcomes = remote.flatMap((r) => r.outcomes);
    await announceMachines([], remote, opts.notify ?? false);
    return { machines: remote.map(summarizeMachine), news: newsOf(outcomes), errors: errorsOf(outcomes) };
  } finally {
    release();
  }
}

function getMachineOrThrow(name: string): ReturnType<typeof getMachine> {
  try {
    return getMachine(name);
  } catch {
    throw new ApiError("not_found", `unknown machine: ${name}`);
  }
}

/** Re-fetch and re-scan one checkout of a remote machine. */
export async function scanRemote(machine: string, path: string, opts: { notify?: boolean } = {}): Promise<ScanResult> {
  const m = getMachineOrThrow(machine);
  if (!loadRepo(path, machine)) throw new ApiError("not_tracked", "not a tracked project");
  const release = tryLock("sync");
  if (!release) throw new ApiError("busy", "a sync is already running");
  try {
    const r = await syncMachine(m, { force: [path] });
    if (!r.ok) throw new ApiError("unreachable", `${machine}: ${r.error}`);
    await announce(r.outcomes, { notify: opts.notify ?? false });
    const o = r.outcomes.find((x) => x.record.path === path);
    const rec = o?.record ?? loadRepo(path, machine);
    if (!rec) throw new ApiError("not_found", "the project is gone from that machine");
    return { project: toReport(rec), firstScan: o?.firstScan ?? false, newAdvisories: o?.newFindings.length ?? 0 };
  } finally {
    release();
  }
}

export interface CheckResult {
  /** Tracked projects whose lockfile changed and were re-scanned. */
  rescanned: string[];
  errors: Array<{ path: string; error: string }>;
}

/**
 * Re-scan only tracked projects whose lockfile changed (cheap stat first). Run by the
 * lockfile watcher after `git pull`, installs or branch switches.
 */
export async function check(opts: { notify?: boolean } = {}): Promise<CheckResult> {
  const release = tryLock("check");
  if (!release) throw new ApiError("busy", "a check is already running");
  try {
    const cfg = loadConfig();
    const changed: Project[] = [];
    for (const r of listRepos()) {
      if (!existsSync(r.path) || isExcluded(r.path, cfg.exclude)) continue;
      const p = findProject(r.path);
      if (p && p.root === r.path && p.lockfile && lockChanged(r, p)) changed.push(p);
    }
    updateState({ lastCheck: new Date().toISOString() });
    pruneDismissed(cfg);
    if (changed.length === 0) return { rescanned: [], errors: [] };
    const outcomes = await scanProjects(changed);
    for (const o of outcomes) saveRepo(o.record);
    await announce(outcomes, { notify: opts.notify ?? false });
    return {
      rescanned: outcomes.map((o) => o.record.path),
      errors: outcomes.filter((o) => o.record.error).map((o) => ({ path: o.record.path, error: o.record.error! })),
    };
  } finally {
    release();
  }
}

/** Paths for the lockfile watcher: lockfile + folder of active checkouts, most recent first. */
export function watchTargets(): string[] {
  const cfg = loadConfig();
  const items: Array<{ paths: string[]; at: number }> = [];
  const local = listRepos()
    .filter((r) => existsSync(r.path) && !isExcluded(r.path, cfg.exclude))
    .map((rec) => ({ rec, repo: repoIdentity(rec.path) }));
  const dismissed = dismissalsFor(cfg, local);
  for (const { rec: r, repo } of local) {
    const act = activityOf(repo, cfg.activeDays, Date.now(), dismissed.get(repoKeyOf(r, repo)) ?? null);
    if (!act.active) continue;
    const paths = [r.path];
    if (r.lockfile && existsSync(r.lockfile)) paths.push(r.lockfile);
    items.push({ paths, at: act.lastActivity ? Date.parse(act.lastActivity) : 0 });
  }
  return items.sort((a, b) => b.at - a.at).flatMap((i) => i.paths);
}

export interface Settings {
  remind: RemindEvery;
  activeDays: number;
  /** Weekly "find my projects" that starts watching new places with active repos. */
  autoDiscover: boolean;
  lastEverywhere: string | null;
  /** Daily check of npm for a newer selfguard. */
  updateCheck: boolean;
  lastReminder: string | null;
  lastSync: string | null;
  lastCheck: string | null;
}

export function getSettings(): Settings {
  const cfg = loadConfig();
  const st = loadState();
  return {
    remind: cfg.remind,
    activeDays: cfg.activeDays,
    autoDiscover: cfg.autoDiscover,
    lastEverywhere: st.lastEverywhere ?? null,
    updateCheck: cfg.updateCheck,
    lastReminder: st.lastReminder ?? null,
    lastSync: st.lastSync ?? null,
    lastCheck: st.lastCheck ?? null,
  };
}

export function updateSettings(patch: { remind?: unknown; activeDays?: unknown; autoDiscover?: unknown; updateCheck?: unknown }): Settings {
  const cfg = loadConfig();
  if (patch.remind !== undefined) {
    if (!REMIND_VALUES.includes(patch.remind as RemindEvery)) throw new ApiError("invalid", "remind must be daily, weekly or off");
    cfg.remind = patch.remind as RemindEvery;
  }
  if (patch.activeDays !== undefined) {
    const n = patch.activeDays;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 365) throw new ApiError("invalid", "activeDays must be an integer between 1 and 365");
    cfg.activeDays = n;
  }
  if (patch.autoDiscover !== undefined) {
    if (typeof patch.autoDiscover !== "boolean") throw new ApiError("invalid", "autoDiscover must be true or false");
    cfg.autoDiscover = patch.autoDiscover;
  }
  if (patch.updateCheck !== undefined) {
    if (typeof patch.updateCheck !== "boolean") throw new ApiError("invalid", "updateCheck must be true or false");
    cfg.updateCheck = patch.updateCheck;
  }
  saveConfig(cfg);
  return getSettings();
}

export interface FoldersResult {
  roots: Array<Root & { exists: boolean; trackedProjects: number }>;
  exclude: string[];
  /** Common code folders on this machine that aren't watched yet. */
  suggestions: string[];
}

/** Watched folders with how many tracked projects each contains, plus suggestions. */
export function getFolders(): FoldersResult {
  const cfg = loadConfig();
  const tracked = listRepos().map((r) => r.path);
  const roots = cfg.roots.map((r) => ({
    ...r,
    exists: existsSync(r.path),
    trackedProjects: tracked.filter((p) => isExcluded(p, [r.path])).length,
  }));
  const watched = cfg.roots.map((r) => r.path);
  const suggestions = candidateRoots().filter((c) => !watched.some((w) => c === w || isExcluded(c, [w])));
  return { roots, exclude: cfg.exclude, suggestions };
}

export interface DirectoryListing {
  path: string;
  parent: string | null;
  home: string;
  /** Visible subdirectories (no hidden ones, no node_modules-like folders). */
  dirs: Array<{ name: string; path: string; isProject: boolean }>;
  truncated: boolean;
}

/** Subfolders of a directory, for the dashboard's folder picker. Names only, read-only. */
export function listDirectories(path?: string): DirectoryListing {
  const dir = normalizeDir(path && path.trim() ? path : homedir());
  if (!dir) throw new ApiError("not_found", `not a directory: ${path}`);
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    throw new ApiError("not_found", `can't read ${dir}`);
  }
  const skip = new Set(["node_modules", "bower_components", "jspm_packages", "vendor", "Pods", "venv", "__pycache__", "target"]);
  const dirs = entries
    .filter((e) => e.isDirectory() && !e.name.startsWith(".") && !skip.has(e.name))
    .map((e) => e.name)
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  const LIMIT = 500;
  return {
    path: dir,
    parent: dir === "/" ? null : dirname(dir),
    home: homedir(),
    dirs: dirs.slice(0, LIMIT).map((name) => {
      const full = join(dir, name);
      return { name, path: full, isProject: existsSync(join(full, "package.json")) };
    }),
    truncated: dirs.length > LIMIT,
  };
}

export interface PackageOverview {
  name: string;
  worstSeverity: Severity;
  direct: boolean;
  /** Only in dev dependencies everywhere. */
  dev: boolean;
  /** Per installed vulnerable version: the version to upgrade to (null: no fix, or malicious). */
  fixes: Array<{ version: string; upgradeTo: string | null; worstSeverity: Severity }>;
  advisories: string[];
  repos: Array<{ key: string; label: string; path: string; machine: string | null; branch: string | null; version: string; direct: boolean; dev: boolean }>;
}

/**
 * Vulnerable packages across repos, judged on each repo's representative checkout (the same
 * one reminders use): "upgrading next fixes 5 repos". No network.
 */
export function getPackagesOverview(): PackageOverview[] {
  const byName = new Map<string, PackageOverview & { fixMap: Map<string, PackageOverview["fixes"][number]>; adv: Set<string> }>();
  for (const r of getAttention()) {
    for (const g of groupByPackage(r.findings)) {
      let p = byName.get(g.name);
      if (!p) {
        p = { name: g.name, worstSeverity: g.worst, direct: false, dev: true, fixes: [], advisories: [], repos: [], fixMap: new Map(), adv: new Set() };
        byName.set(g.name, p);
      }
      if (severityRank(g.worst) < severityRank(p.worstSeverity)) p.worstSeverity = g.worst;
      p.direct ||= g.direct;
      p.dev &&= g.dev;
      p.fixMap.set(g.version, { version: g.version, upgradeTo: g.worst === "malicious" ? null : (g.upgradeTo ?? null), worstSeverity: g.worst });
      for (const f of g.findings) p.adv.add(f.id);
      p.repos.push({ key: r.key, label: r.label, path: r.path, machine: r.machine, branch: r.branch, version: g.version, direct: g.direct, dev: g.dev });
    }
  }
  return [...byName.values()]
    .map(({ fixMap, adv, ...p }) => ({
      ...p,
      fixes: [...fixMap.values()].sort((a, b) => (isValidVersion(a.version) && isValidVersion(b.version) ? compareVersions(a.version, b.version) : a.version.localeCompare(b.version))),
      advisories: [...adv],
    }))
    .sort(
      (a, b) =>
        severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
        b.repos.length - a.repos.length ||
        a.name.localeCompare(b.name),
    );
}

export interface VulnerabilityDetail {
  id: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  details: string;
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
  affected: Array<{ package: string; ranges: Array<{ introduced?: string; fixed?: string; last_affected?: string }>; versions: string[] }>;
  references: string[];
  url: string;
  /** Tracked projects affected by this advisory. */
  affectsYourProjects: Array<{ path: string; machine: string | null; package: string; version: string; fixedIn: string | null }>;
}

export async function getVulnerability(id: string): Promise<VulnerabilityDetail> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) throw new ApiError("invalid", "invalid advisory id");
  const vulns = await getVulns([{ id, modified: "" }]);
  const v: OsvVuln | undefined = vulns.get(id);
  if (!v) throw new ApiError("not_found", `advisory ${id} not found`);
  const s = (x: unknown, n: number): string => clean(x ?? "", n);
  const affectsYourProjects: VulnerabilityDetail["affectsYourProjects"] = [];
  for (const r of listAllRepos(machineNames())) {
    for (const d of r.deps) {
      const ev = evaluate(v, d.name, d.version);
      if (ev.affected) affectsYourProjects.push({ path: r.path, machine: r.machine ?? null, package: d.name, version: d.version, fixedIn: ev.fixedIn ?? null });
    }
  }
  const raw = v as unknown as Record<string, unknown>;
  return {
    id: v.id,
    aliases: (v.aliases ?? []).map((a) => s(a, 64)),
    severity: severityOf(v),
    summary: s(v.summary, 300),
    details: clean(v.details ?? "", 4000),
    published: typeof raw.published === "string" ? raw.published : null,
    modified: v.modified ?? null,
    withdrawn: v.withdrawn ?? null,
    affected: (v.affected ?? [])
      .filter((a) => a.package?.ecosystem === "npm")
      .slice(0, 20)
      .map((a) => ({
        package: s(a.package?.name, 214),
        ranges: (a.ranges ?? []).flatMap((r) =>
          (r.events ?? []).map((e) => ({ ...e })),
        ).slice(0, 50),
        versions: (a.versions ?? []).slice(0, 50).map((x) => s(x, 64)),
      })),
    references: (Array.isArray(raw.references) ? raw.references : [])
      .map((r) => (r && typeof r === "object" ? (r as { url?: unknown }).url : undefined))
      .filter((u): u is string => typeof u === "string" && /^https:\/\//.test(u))
      .slice(0, 15)
      .map((u) => s(u, 300)),
    url: advisoryUrl(v.id),
    affectsYourProjects,
  };
}

// ---------- other machines ----------

export {
  addMachine,
  addMachineRoot,
  browseOnMachine,
  excludeOnMachine,
  installMachine,
  listMachines,
  machineSetup,
  verifyMachine,
  removeMachine,
  removeMachineRoot,
  suggestName,
  testMachine,
  unexcludeOnMachine,
  type AddMachineResult,
  type MachineInfo,
  type MachineSetup,
} from "./machines.ts";
export { tailnetPeers, type TailnetPeer } from "./remote.ts";

export const hasMachines = (): boolean => loadConfig().machines.length > 0;
