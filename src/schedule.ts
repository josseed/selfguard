/**
 * Background work via per-user launchd agents (macOS):
 * - dev.selfguard.sync: `selfguard sync` every N hours (discovery, new advisories, reminders);
 * - dev.selfguard.watch: `selfguard check` as soon as a lockfile of an active checkout changes
 *   (git pull, installs, merges), so fixes and new risks show up in seconds;
 * - dev.selfguard.remote: `selfguard machines check` every 15 minutes, only when you added
 *   other machines (new projects and changed lockfiles there);
 * - dev.selfguard.discover: weekly search of the whole home folder for new places with
 *   active repos ("find my projects"), unless turned off in settings;
 * - dev.selfguard.share: `selfguard share serve`, kept alive while "Let my other machines see
 *   this one" is on (on Linux, a systemd user unit: selfguard-share.service).
 */
import { existsSync, readFileSync, rmSync } from "node:fs";
import { engineCommand } from "./hook.ts";
import { logFile } from "./paths.ts";
import {
  agentPlist,
  agentsManaged,
  assertMac,
  DISCOVER_INTERVAL,
  DISCOVER_LABEL,
  install,
  isLoaded,
  MAX_WATCH_PATHS,
  plistPath,
  plistWatchPaths,
  REMOTE_INTERVAL,
  REMOTE_LABEL,
  SYNC_LABEL,
  unload,
  WATCH_LABEL,
} from "./schedule/launchd.ts";

export { agentPlist, DISCOVER_INTERVAL, MAX_WATCH_PATHS, parseInterval, plistWatchPaths, REMOTE_INTERVAL } from "./schedule/launchd.ts";
export { shareAgentStatus, shareUnit, updateShareAgent } from "./schedule/share.ts";

export function scheduleOn(seconds: number, watchPaths: string[], opts: { machines?: boolean; autoDiscover?: boolean } = {}): string {
  assertMac();
  install(SYNC_LABEL, agentPlist(SYNC_LABEL, engineCommand("sync", "--background"), { interval: seconds }, logFile()));
  updateWatcher(watchPaths, { force: true });
  updateRemoteAgent(opts.machines ?? false);
  updateDiscoverAgent(opts.autoDiscover ?? true);
  return plistPath(SYNC_LABEL);
}

/** Install or remove the weekly whole-home discovery agent (only while the schedule is on). */
export function updateDiscoverAgent(enabled: boolean): { changed: boolean } {
  if (process.platform !== "darwin" || !agentsManaged()) return { changed: false };
  const exists = existsSync(plistPath(DISCOVER_LABEL));
  if (!enabled || !existsSync(plistPath(SYNC_LABEL))) {
    if (!exists) return { changed: false };
    unload(DISCOVER_LABEL);
    rmSync(plistPath(DISCOVER_LABEL), { force: true });
    return { changed: true };
  }
  const plist = agentPlist(DISCOVER_LABEL, engineCommand("discover", "--everywhere", "--background"), { interval: DISCOVER_INTERVAL }, logFile());
  let current = "";
  try {
    current = readFileSync(plistPath(DISCOVER_LABEL), "utf8");
  } catch {
    /* not installed */
  }
  if (current === plist && isLoaded(DISCOVER_LABEL)) return { changed: false };
  install(DISCOVER_LABEL, plist);
  return { changed: true };
}

/** Install or remove the remote-machines agent (only while the schedule is on). */
export function updateRemoteAgent(enabled: boolean): { changed: boolean } {
  if (process.platform !== "darwin" || !agentsManaged()) return { changed: false };
  const exists = existsSync(plistPath(REMOTE_LABEL));
  if (!enabled || !existsSync(plistPath(SYNC_LABEL))) {
    if (!exists) return { changed: false };
    unload(REMOTE_LABEL);
    rmSync(plistPath(REMOTE_LABEL), { force: true });
    return { changed: true };
  }
  const plist = agentPlist(REMOTE_LABEL, engineCommand("machines", "check", "--background"), { interval: REMOTE_INTERVAL }, logFile());
  let current = "";
  try {
    current = readFileSync(plistPath(REMOTE_LABEL), "utf8");
  } catch {
    /* not installed */
  }
  if (current === plist && isLoaded(REMOTE_LABEL)) return { changed: false };
  install(REMOTE_LABEL, plist);
  return { changed: true };
}

/**
 * (Re)install the lockfile watcher with these paths, only when the schedule is on and the
 * path set changed. Never call it from the watcher's own run: unloading would kill it.
 */
export function updateWatcher(paths: string[], opts: { force?: boolean } = {}): { watching: number; changed: boolean } {
  if (process.platform !== "darwin" || !agentsManaged()) return { watching: 0, changed: false };
  if (!opts.force && !existsSync(plistPath(SYNC_LABEL))) return { watching: 0, changed: false };
  const list = [...new Set(paths)].slice(0, MAX_WATCH_PATHS);
  if (list.length === 0) {
    const had = existsSync(plistPath(WATCH_LABEL));
    unload(WATCH_LABEL);
    rmSync(plistPath(WATCH_LABEL), { force: true });
    return { watching: 0, changed: had };
  }
  const plist = agentPlist(WATCH_LABEL, engineCommand("check", "--background"), { watch: list }, logFile());
  let current = "";
  try {
    current = readFileSync(plistPath(WATCH_LABEL), "utf8");
  } catch {
    /* not installed */
  }
  if (current === plist && isLoaded(WATCH_LABEL)) return { watching: list.length, changed: false };
  install(WATCH_LABEL, plist);
  return { watching: list.length, changed: true };
}

/**
 * What the installed watcher watches (null when it isn't installed or can't be read). The
 * watcher's own run uses it to look only at the checkouts that can have triggered it.
 */
export function watcherPaths(): string[] | null {
  try {
    return plistWatchPaths(readFileSync(plistPath(WATCH_LABEL), "utf8"));
  } catch {
    return null;
  }
}

export function scheduleOff(): boolean {
  assertMac();
  let existed = false;
  for (const label of [SYNC_LABEL, WATCH_LABEL, REMOTE_LABEL, DISCOVER_LABEL]) {
    unload(label);
    existed = existsSync(plistPath(label)) || existed;
    rmSync(plistPath(label), { force: true });
  }
  return existed;
}

/** Who runs the background agents: the Mac app's bundled engine, or a command-line install (npm). */
export type ScheduleOwner = "app" | "cli";

/** The owner of the agents, from the program the sync agent runs (null when it isn't installed). */
export function scheduleOwner(plist: string): ScheduleOwner | null {
  const program = /<key>ProgramArguments<\/key>\s*<array>\s*<string>([^<]*)<\/string>/.exec(plist)?.[1];
  if (!program) return null;
  return program.includes(".app/Contents/Resources/engine/") ? "app" : "cli";
}

export interface ScheduleStatus {
  installed: boolean;
  loaded: boolean;
  owner: ScheduleOwner | null;
  /** Seconds between full syncs (kept when the agents move to another engine). */
  intervalSeconds: number | null;
  plist: string;
  watcher: { installed: boolean; loaded: boolean; paths: number };
  remote: { installed: boolean; loaded: boolean };
  discover: { installed: boolean; loaded: boolean };
}

export function scheduleStatus(): ScheduleStatus {
  assertMac();
  let paths = 0;
  let owner: ScheduleOwner | null = null;
  let intervalSeconds: number | null = null;
  try {
    const sync = readFileSync(plistPath(SYNC_LABEL), "utf8");
    owner = scheduleOwner(sync);
    const every = /<key>StartInterval<\/key>\s*<integer>(\d+)<\/integer>/.exec(sync)?.[1];
    intervalSeconds = every ? Number(every) : null;
  } catch {
    /* not installed */
  }
  paths = watcherPaths()?.length ?? 0;
  return {
    installed: existsSync(plistPath(SYNC_LABEL)),
    loaded: isLoaded(SYNC_LABEL),
    owner,
    intervalSeconds,
    plist: plistPath(SYNC_LABEL),
    watcher: { installed: existsSync(plistPath(WATCH_LABEL)), loaded: isLoaded(WATCH_LABEL), paths },
    remote: { installed: existsSync(plistPath(REMOTE_LABEL)), loaded: isLoaded(REMOTE_LABEL) },
    discover: { installed: existsSync(plistPath(DISCOVER_LABEL)), loaded: isLoaded(DISCOVER_LABEL) },
  };
}
