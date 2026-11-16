/** OSV ecosystem names (https://ossf.github.io/osv-schema/#affectedpackage-field). */
export type Ecosystem = "npm" | "PyPI" | "crates.io" | "Go";

export const SUPPORTED_ECOSYSTEMS: readonly Ecosystem[] = ["npm", "PyPI", "crates.io", "Go"];

/** "pypi", "Crates.io", "go"… -> the OSV name; null if it isn't one we support. */
export const parseEcosystem = (s: string): Ecosystem | null =>
  SUPPORTED_ECOSYSTEMS.find((e) => e.toLowerCase() === s.trim().toLowerCase()) ?? null;

export interface Dependency {
  name: string;
  version: string;
  /** Declared directly by the project (package.json, pyproject.toml, Cargo.toml or go.mod). */
  direct: boolean;
  /** Only reachable through development dependencies. */
  dev: boolean;
  /** Absent means npm (records stored before other ecosystems were supported). */
  ecosystem?: Ecosystem;
}

export interface ParsedLockfile {
  deps: Dependency[];
  /** Entries we could not check (git/file/link/path deps, non-registry sources, invalid versions). */
  skipped: number;
}

export type LockfileType = "npm" | "pnpm" | "yarn" | "bun" | "uv" | "poetry" | "cargo" | "gomod";

export const ECOSYSTEM_OF: Readonly<Record<LockfileType, Ecosystem>> = {
  npm: "npm",
  pnpm: "npm",
  yarn: "npm",
  bun: "npm",
  uv: "PyPI",
  poetry: "PyPI",
  cargo: "crates.io",
  gomod: "Go",
};

export const ecosystemOf = (x: { ecosystem?: Ecosystem | undefined }): Ecosystem => x.ecosystem ?? "npm";

/** "name@version" for npm (unchanged from older records), "PyPI:name@version" otherwise. */
export const packageKey = (x: { name: string; version: string; ecosystem?: Ecosystem | undefined }): string =>
  `${x.ecosystem && x.ecosystem !== "npm" ? `${x.ecosystem}:` : ""}${x.name}@${x.version}`;
