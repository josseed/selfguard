export interface Dependency {
  name: string;
  version: string;
  /** Declared directly in a package.json of the project (root or workspace). */
  direct: boolean;
  /** Only reachable through devDependencies. */
  dev: boolean;
}

export interface ParsedLockfile {
  deps: Dependency[];
  /** Entries we could not check (git/file/link deps, non-semver versions). */
  skipped: number;
}

export type LockfileType = "npm" | "pnpm" | "yarn" | "bun";
