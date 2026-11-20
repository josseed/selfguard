import { homedir } from "node:os";
import { join } from "node:path";

/** Root of all local state. Override with SELFGUARD_HOME (used by tests). */
export function stateRoot(): string {
  const override = process.env.SELFGUARD_HOME;
  if (override && override.trim() !== "") return override;
  return join(homedir(), ".selfguard");
}

export const reposDir = (): string => join(stateRoot(), "repos");
/** Records of a remote machine (name validated by config.MACHINE_NAME_RE). */
export const machineDir = (machine: string): string => join(stateRoot(), "machines", machine);
export const machineReposDir = (machine: string): string => join(machineDir(machine), "repos");
/** Records of CI workflows and agent configs (src/sources), beside the lockfile records. */
export const sourcesDir = (): string => join(stateRoot(), "sources");
export const vulnCacheDir = (): string => join(stateRoot(), "cache", "vulns");
/** Local index of the GitHub Actions advisories (src/scan/gha-index.ts). */
export const ghaIndexFile = (): string => join(stateRoot(), "cache", "github-actions-index.json");
export const locksDir = (): string => join(stateRoot(), "locks");
export const logFile = (): string => join(stateRoot(), "selfguard.log");
export const eventsFile = (): string => join(stateRoot(), "events.jsonl");
export const stateFile = (): string => join(stateRoot(), "state.json");
/** Summary for the macOS menu bar app (menubar.ts). */
export const menuBarFile = (): string => join(stateRoot(), "menubar.json");
/** Heartbeat of the Mac app, and the alerts it shows instead of osascript (appalerts.ts). */
export const appFile = (): string => join(stateRoot(), "app.json");
export const appAlertsDir = (): string => join(stateRoot(), "app-alerts");

/**
 * Running from the Mac app's bundle: its bundled node, started by the app or by launchd. macOS
 * then lets the engine use the app's privacy permissions, so nothing in the environment (which
 * `open --env` or `launchctl setenv` can set) may choose which program it runs.
 */
export const inAppBundle = (): boolean => /\.app\/Contents\//.test(process.execPath);

/** The program to run: `envName` may override `name` (CLI, tests); the app always uses `appPath`. */
export function program(envName: string, name: string, appPath: string): string {
  if (inAppBundle()) return appPath;
  return process.env[envName] || name;
}
