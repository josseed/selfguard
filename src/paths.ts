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
export const uiFile = (): string => join(stateRoot(), "ui.json");
