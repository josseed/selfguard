/**
 * Minimal SemVer 2.0.0 parser/comparator (no dependencies on purpose).
 * Only what we need to evaluate OSV ranges for the npm ecosystem.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  pre: Array<string | number>;
}

const SEMVER_RE =
  /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function parse(input: string): SemVer | null {
  if (typeof input !== "string" || input.length > 256) return null;
  const m = SEMVER_RE.exec(input.trim());
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;
  const pre = m[4]
    ? m[4].split(".").map((id) => (/^\d+$/.test(id) && Number.isSafeInteger(Number(id)) ? Number(id) : id))
    : [];
  return { major, minor, patch, pre };
}

export function isValid(input: string): boolean {
  return parse(input) !== null;
}

function cmpNum(a: number, b: number): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function cmpIdent(a: string | number, b: string | number): number {
  const an = typeof a === "number";
  const bn = typeof b === "number";
  if (an && bn) return cmpNum(a, b);
  if (an) return -1; // numeric identifiers have lower precedence
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareParsed(a: SemVer, b: SemVer): number {
  const core = cmpNum(a.major, b.major) || cmpNum(a.minor, b.minor) || cmpNum(a.patch, b.patch);
  if (core !== 0) return core;
  // A version without pre-release has higher precedence than one with.
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1;
  if (b.pre.length === 0) return -1;
  const len = Math.min(a.pre.length, b.pre.length);
  for (let i = 0; i < len; i++) {
    const c = cmpIdent(a.pre[i]!, b.pre[i]!);
    if (c !== 0) return c;
  }
  return cmpNum(a.pre.length, b.pre.length);
}

/** Compare two version strings. Throws if either is not valid SemVer. */
export function compare(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) throw new Error(`invalid semver: ${!pa ? a : b}`);
  return compareParsed(pa, pb);
}
