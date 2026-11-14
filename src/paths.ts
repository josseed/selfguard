import { homedir } from "node:os";
import { join } from "node:path";

/** Root of all local state. Override with SELFGUARD_HOME (used by tests). */
export function stateRoot(): string {
  const override = process.env.SELFGUARD_HOME;
  if (override && override.trim() !== "") return override;
  return join(homedir(), ".selfguard");
}

export const reposDir = (): string => join(stateRoot(), "repos");
export const vulnCacheDir = (): string => join(stateRoot(), "cache", "vulns");
export const locksDir = (): string => join(stateRoot(), "locks");
export const logFile = (): string => join(stateRoot(), "selfguard.log");
