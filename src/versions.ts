/**
 * Version handling per ecosystem: SemVer for npm, crates.io and Go (Go versions are stored
 * without their "v", like OSV does), PEP 440 for PyPI.
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
  const v = parse(version);
  return v ? { kind: "semver", v } : null;
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
