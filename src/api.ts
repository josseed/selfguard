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
import { repoIdentity, type RepoIdentity } from "./repoid.ts";
import { clean } from "./sanitize.ts";
import { lockChanged, scanProjects, type ScanOutcome } from "./scan.ts";
import { loadState, updateState } from "./state.ts";
import { forgetRepo, listRepos, loadRepo, saveRepo, type Finding, type RepoRecord } from "./store.ts";

export class ApiError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

const advisoryUrl = (id: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;

// ---------- shapes ----------

export interface ProjectSummary {
  path: string;
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
}

/** Worktrees / clones of the same repo (and same subfolder) grouped together. */
export interface RepoGroup {
  key: string;
  label: string;
  /** At least one checkout has recent git activity. */
  active: boolean;
  /** Worst severity across active checkouts (all checkouts if none is active). */
  worstSeverity: Severity | null;
  /** Distinct vulnerable name@version across active checkouts (all checkouts if none is active). */
  vulnerablePackages: number;
  inactiveCheckouts: number;
  checkouts: Array<{
    path: string;
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

function summarize(rec: RepoRecord, activeDays = loadConfig().activeDays): ProjectSummary {
  const exists = existsSync(rec.path);
  const repo = exists ? repoIdentity(rec.path) : null;
  const activity = exists ? activityOf(repo, activeDays) : { active: false, lastActivity: null };
  return {
    path: rec.path,
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

export function getStatus(opts: { onlyVulnerable?: boolean } = {}): { repos: RepoGroup[]; projects: ProjectSummary[] } {
  const rank = (w: Severity | null): number => (w ? severityRank(w) : 99);
  const records = listRepos();
  const activeDays = loadConfig().activeDays;
  const summaries = records.map((r) => summarize(r, activeDays));
  const groups = new Map<string, { group: RepoGroup; active: Finding[]; all: Finding[] }>();
  summaries.forEach((p, i) => {
    const rec = records[i]!;
    const key = p.repo?.key ?? `path:${p.path}`;
    let g = groups.get(key);
    if (!g) {
      const label = p.repo?.label ?? (p.path.split("/").pop() || p.path);
      g = {
        group: { key, label, active: false, worstSeverity: null, vulnerablePackages: 0, inactiveCheckouts: 0, checkouts: [] },
        active: [],
        all: [],
      };
      groups.set(key, g);
    }
    g.group.checkouts.push({
      path: p.path,
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
export function getAttention(): Array<AttentionRepo & { key: string; path: string; branch: string | null }> {
  const activeDays = loadConfig().activeDays;
  const best = new Map<string, { rec: RepoRecord; repo: RepoIdentity | null; main: boolean; at: number }>();
  for (const rec of listRepos()) {
    if (!existsSync(rec.path)) continue;
    const repo = repoIdentity(rec.path);
    const act = activityOf(repo, activeDays);
    if (!act.active) continue;
    const key = repo?.key ?? `path:${rec.path}`;
    const cand = { rec, repo, main: !(repo?.worktree ?? false), at: act.lastActivity ? Date.parse(act.lastActivity) : 0 };
    const cur = best.get(key);
    if (!cur || (cand.main && !cur.main) || (cand.main === cur.main && cand.at > cur.at)) best.set(key, cand);
  }
  return [...best.entries()]
    .filter(([, b]) => b.rec.findings.length > 0)
    .map(([key, b]) => ({
      key,
      label: b.repo?.label ?? (b.rec.path.split("/").pop() || b.rec.path),
      path: b.rec.path,
      branch: b.repo?.branch ?? null,
      findings: b.rec.findings,
    }));
}

export interface RepoPackage extends VulnerablePackage {
  /** Checkouts where this exact version is installed. */
  checkouts: Array<{ path: string; branch: string | null; active: boolean }>;
}

export interface RepoDetail {
  key: string;
  label: string;
  checkouts: RepoGroup["checkouts"];
  packages: RepoPackage[];
}

/** All vulnerable packages of one repo group, merged across its checkouts (no network). */
export function getRepoDetail(key: string): RepoDetail {
  const group = getStatus().repos.find((g) => g.key === key);
  if (!group) throw new ApiError("not_found", "unknown repo");
  const byPkg = new Map<string, RepoPackage>();
  for (const k of group.checkouts) {
    const rec = loadRepo(k.path);
    if (!rec) continue;
    for (const p of toReport(rec).vulnerable) {
      const id = `${p.name}@${p.version}`;
      let entry = byPkg.get(id);
      if (!entry) {
        entry = { ...p, checkouts: [] };
        byPkg.set(id, entry);
      }
      entry.checkouts.push({ path: k.path, branch: k.branch, active: k.active });
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
  return { key: group.key, label: group.label, checkouts: group.checkouts, packages };
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
  news: Array<{ path: string; packages: Array<{ name: string; version: string; worstSeverity: Severity; advisories: string[] }> }>;
  errors: Array<{ path: string; error: string }>;
  /** Raw outcomes for notifications (not serialized). */
  outcomes: ScanOutcome[];
}

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

    const outcomes = await scanProjects(projects);
    for (const o of outcomes) saveRepo(o.record);
    await announce(outcomes, { notify: opts.notify ?? false });
    updateState({ lastSync: new Date().toISOString() });
    return {
      projects: projects.length,
      discovered: discovered.map((p) => p.root),
      pruned,
      news: outcomes
        .filter((o) => o.newFindings.length > 0)
        .map((o) => ({
          path: o.record.path,
          packages: groupByPackage(o.newFindings).map((g) => ({
            name: g.name,
            version: g.version,
            worstSeverity: g.worst,
            advisories: g.findings.map((f) => f.id),
          })),
        })),
      errors: outcomes.filter((o) => o.record.error).map((o) => ({ path: o.record.path, error: o.record.error! })),
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
  usedIn: Array<{ path: string; versions: Array<{ version: string; direct: boolean; dev: boolean; vulnerable: boolean }> }>;
}

export function whereUsed(name: string): WhereResult {
  const usedIn: WhereResult["usedIn"] = [];
  for (const r of listRepos()) {
    const versions = r.deps
      .filter((d) => d.name === name)
      .map((d) => ({
        version: d.version,
        direct: d.direct,
        dev: d.dev,
        vulnerable: r.findings.some((f) => f.name === name && f.version === d.version),
      }));
    if (versions.length) usedIn.push({ path: r.path, versions });
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
  return { roots: cfg.roots, exclude: cfg.exclude, removed: cfg.roots.length < before };
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
  for (const r of listRepos()) {
    if (!existsSync(r.path) || isExcluded(r.path, cfg.exclude)) continue;
    const act = activityOf(repoIdentity(r.path), cfg.activeDays);
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
    lastReminder: st.lastReminder ?? null,
    lastSync: st.lastSync ?? null,
    lastCheck: st.lastCheck ?? null,
  };
}

export function updateSettings(patch: { remind?: unknown; activeDays?: unknown }): Settings {
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
  repos: Array<{ key: string; label: string; path: string; branch: string | null; version: string; direct: boolean; dev: boolean }>;
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
      p.repos.push({ key: r.key, label: r.label, path: r.path, branch: r.branch, version: g.version, direct: g.direct, dev: g.dev });
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
  affectsYourProjects: Array<{ path: string; package: string; version: string; fixedIn: string | null }>;
}

export async function getVulnerability(id: string): Promise<VulnerabilityDetail> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) throw new ApiError("invalid", "invalid advisory id");
  const vulns = await getVulns([{ id, modified: "" }]);
  const v: OsvVuln | undefined = vulns.get(id);
  if (!v) throw new ApiError("not_found", `advisory ${id} not found`);
  const s = (x: unknown, n: number): string => clean(x ?? "", n);
  const affectsYourProjects: VulnerabilityDetail["affectsYourProjects"] = [];
  for (const r of listRepos()) {
    for (const d of r.deps) {
      const ev = evaluate(v, d.name, d.version);
      if (ev.affected) affectsYourProjects.push({ path: r.path, package: d.name, version: d.version, fixedIn: ev.fixedIn ?? null });
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
