import { existsSync } from "node:fs";
import { activityOf } from "../activity.ts";
import { announce } from "../announce.ts";
import { isExcluded, loadConfig } from "../config.ts";
import { discoverAll } from "../discover.ts";
import { ApiError } from "../errors.ts";
import { tryLock } from "../fsutil.ts";
import { findProject, type Project } from "../lockfile/detect.ts";
import { getMachine, syncMachine, syncMachines, type MachineSyncResult } from "../machines.ts";
import type { Severity } from "../match.ts";
import { groupByPackage } from "../report.ts";
import { repoIdentity } from "../repoid.ts";
import { lockChanged, type ScanOutcome } from "../scan.ts";
import { scanTogether, type SourceOutcome } from "../sources.ts";
import { pruneSources, saveSourceOutcomes, sourcesWith, sourceWatchPaths } from "../sources/run.ts";
import { updateState } from "../state.ts";
import { forgetRepo, listRepos, loadRepo, repoKeyOf, saveRepo } from "../store.ts";
import { dismissalsFor, resolveProject, toReport } from "./common.ts";
import { pruneDismissed } from "./dismissals.ts";
import type { ProjectReport } from "./shapes.ts";

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
    // The repo's CI workflows and agent configs go in the same OSV batch.
    const { outcomes: [o], sources } = await scanTogether([project], sourcesWith([project.root]));
    saveRepo(o!.record);
    saveSourceOutcomes(sources);
    await announce([o!], { notify: opts.notify ?? false, sources });
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

    const tracked = projects.map((p) => p.root);
    const { outcomes: local, sources } = await scanTogether(projects, sourcesWith(tracked, { machine: true }));
    for (const o of local) saveRepo(o.record);
    saveSourceOutcomes(sources);
    pruneSources(tracked);
    // Other machines: same checks, one SSH session at a time; a machine that doesn't answer
    // keeps its last results and shows the error.
    const remote = await syncMachines({ full: true });
    const outcomes = [...local, ...remote.flatMap((r) => r.outcomes)];
    await announceMachines(local, remote, opts.notify ?? false, sources);
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

/** A machine's first sync is logged (Activity) but not notified: it is the baseline. */
async function announceMachines(local: ScanOutcome[], remote: MachineSyncResult[], notify: boolean, sources: SourceOutcome[] = []): Promise<void> {
  const baseline = remote.filter((r) => r.initial).flatMap((r) => r.outcomes);
  const live = [...local, ...remote.filter((r) => !r.initial).flatMap((r) => r.outcomes)];
  if (baseline.length) await announce(baseline, { notify: false });
  await announce(live, { notify, sources });
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
    const tracked: string[] = [];
    for (const r of listRepos()) {
      if (!existsSync(r.path) || isExcluded(r.path, cfg.exclude)) continue;
      tracked.push(r.path);
      const p = findProject(r.path);
      if (p && p.root === r.path && p.lockfile && lockChanged(r, p)) changed.push(p);
    }
    updateState({ lastCheck: new Date().toISOString() });
    pruneDismissed(cfg);
    const changedSources = sourcesWith(tracked, { machine: true, onlyChanged: true });
    if (changed.length === 0 && changedSources.length === 0) return { rescanned: [], errors: [] };
    // A changed agent config (~/.claude.json changes all the time) is re-read, but OSV is only
    // asked when its references changed or its last scan is a day old.
    const { outcomes, sources } = await scanTogether(changed, changedSources, { reuseRecent: true });
    for (const o of outcomes) saveRepo(o.record);
    saveSourceOutcomes(sources);
    await announce(outcomes, { notify: opts.notify ?? false, sources });
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
  const active: Array<{ rec: (typeof local)[number]["rec"]; at: number }> = [];
  for (const { rec, repo } of local) {
    const act = activityOf(repo, cfg.activeDays, Date.now(), dismissed.get(repoKeyOf(rec, repo)) ?? null);
    if (act.active) active.push({ rec, at: act.lastActivity ? Date.parse(act.lastActivity) : 0 });
  }
  // CI workflows and agent configs (none without extractors): machine-wide ones first.
  const sources = sourceWatchPaths(active.map(({ rec }) => rec.path));
  for (const { rec: r, at } of active) {
    const paths = [r.path];
    if (r.lockfile && existsSync(r.lockfile)) paths.push(r.lockfile);
    paths.push(...(sources.byProject.get(r.path) ?? []));
    items.push({ paths, at });
  }
  return [...new Set([...sources.machine, ...items.sort((a, b) => b.at - a.at).flatMap((i) => i.paths)])];
}
