/**
 * Version handling per ecosystem: SemVer for npm, crates.io and Go (Go versions are stored
 * without their "v", like OSV does), PEP 440 for PyPI. GitHub Actions releases are SemVer
 * that may be partial ("41" = 41.0.0, "v4.1" = 4.1.0), as tags and OSV ranges write them.
 */
import type { Ecosystem } from "./lockfile/types.ts";
import { comparePep440, normalizePyName, parsePep440, type Pep440 } from "./pep440.ts";
import { compareParsed, parse, type SemVer } from "./semver.ts";

export type Parsed = { kind: "semver"; v: SemVer } | { kind: "pep440"; v: Pep440 };

export function parseVersion(eco: Ecosystem, version: string): Parsed | null {
  if (eco === "PyPI") {
    const v = parsePep440(version);
    return v ? { kind: "pep440", v } : null;
  }
  const v = parse(eco === "GitHub Actions" ? completeSemver(version) : version);
  return v ? { kind: "semver", v } : null;
}

/** "41" -> "41.0.0", "v4.1" -> "v4.1.0" (pre-release/build suffixes kept); anything else as is. */
export function completeSemver(version: string): string {
  if (typeof version !== "string") return version;
  const m = /^(v?\d+)(\.\d+)?([-+].*)?$/.exec(version.trim());
  if (!m) return version;
  return `${m[1]}${m[2] ?? ".0"}.0${m[3] ?? ""}`;
}

export function compareParsedVersions(a: Parsed, b: Parsed): number {
  if (a.kind === "pep440" && b.kind === "pep440") return comparePep440(a.v, b.v);
  if (a.kind === "semver" && b.kind === "semver") return compareParsed(a.v, b.v);
  throw new Error("cannot compare versions of different schemes");
}

/** Lowest possible version (OSV's `introduced: "0"`). */
export function lowest(eco: Ecosystem): Parsed {
  return eco === "PyPI"
    ? { kind: "pep440", v: { epoch: 0, release: [0], pre: null, post: null, dev: 0, local: [] } }
    : { kind: "semver", v: { major: 0, minor: 0, patch: 0, pre: [0] } };
}

export const isValidVersion = (eco: Ecosystem, version: string): boolean => parseVersion(eco, version) !== null;

/** Compare two version strings of the same ecosystem. Throws if either is invalid. */
export function compareVersions(eco: Ecosystem, a: string, b: string): number {
  const pa = parseVersion(eco, a);
  const pb = parseVersion(eco, b);
  if (!pa || !pb) throw new Error(`invalid ${eco} version: ${!pa ? a : b}`);
  return compareParsedVersions(pa, pb);
}

/** Package names as OSV and the registry compare them. */
export function normalizeName(eco: Ecosystem, name: string): string {
  return eco === "PyPI" ? normalizePyName(name) : name;
}
