/**
 * Does an advisory apply to a source reference? Exact versions use match.ts; release lines
 * (@v4) are affected when any version of the line falls in a range; unknown versions list
 * every advisory of the package. Malicious advisories always apply.
 */
import type { Ecosystem } from "../lockfile/types.ts";
import { evaluate, severityOf } from "../match.ts";
import type { OsvEvent, OsvVuln } from "../osv.ts";
import type { Certainty } from "../store.ts";
import { compareParsedVersions, lowest, normalizeName, parseVersion, type Parsed } from "../versions.ts";
import type { SourceRef } from "./types.ts";

export interface RefEvaluation {
  applies: boolean;
  certainty: Certainty;
  fixedIn?: string;
}

type RefLike = Pick<SourceRef, "ecosystem" | "name" | "version" | "versionKind" | "lineOf">;

/** Lower (inclusive) and upper (exclusive) bounds of a release line in a version scheme. */
function lineBounds(scheme: Ecosystem, line: string): { lo: Parsed; hi: Parsed } | null {
  const m = /^v?(\d+)(?:\.(\d+))?$/.exec(line.trim());
  if (!m) return null;
  const major = Number(m[1]);
  const minor = m[2] === undefined ? null : Number(m[2]);
  const [lo, hi] = minor === null ? [`${major}`, `${major + 1}`] : [`${major}.${minor}`, `${major}.${minor + 1}`];
  // A line tag moves between releases: it starts at the first release (L.0.0, not its
  // pre-releases) and ends before anything of the next line (its lowest pre-release).
  const full = (v: string): string => (scheme === "PyPI" ? v : `${v}${minor === null ? ".0.0" : ".0"}`);
  const plo = parseVersion(scheme, full(lo));
  const phi = parseVersion(scheme, scheme === "PyPI" ? `${hi}.dev0` : `${full(hi)}-0`);
  return plo && phi ? { lo: plo, hi: phi } : null;
}

function eventVersion(scheme: Ecosystem, e: OsvEvent): Parsed | null {
  if (e.introduced === "0") return lowest(scheme);
  const v = e.introduced ?? e.fixed ?? e.last_affected ?? e.limit;
  return v === undefined ? null : parseVersion(scheme, v);
}

/**
 * Whether some version of the line is affected, and the highest fix among the affected
 * intervals that touch it (upgrading to it leaves the line safe as far as OSV knows).
 */
export function lineAffected(vuln: OsvVuln, ecosystem: Ecosystem, name: string, line: string): { affected: boolean; fixedIn?: string } {
  const wanted = normalizeName(ecosystem, name);
  let affected = false;
  let best: { raw: string; v: Parsed } | null = null;
  for (const aff of vuln.affected ?? []) {
    if (aff.package?.ecosystem !== ecosystem || normalizeName(ecosystem, aff.package?.name ?? "") !== wanted) continue;
    const own = lineBounds(ecosystem, line);
    if (own && Array.isArray(aff.versions)) {
      for (const x of aff.versions) {
        const v = typeof x === "string" ? parseVersion(ecosystem, x) : null;
        if (v && compareParsedVersions(v, own.lo) >= 0 && compareParsedVersions(v, own.hi) < 0) affected = true;
      }
    }
    for (const range of aff.ranges ?? []) {
      if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
      const scheme: Ecosystem = range.type === "SEMVER" ? "npm" : ecosystem;
      const bounds = lineBounds(scheme, line);
      if (!bounds) continue;
      const events = (range.events ?? [])
        .map((e) => ({ e, v: eventVersion(scheme, e) }))
        .filter((x): x is { e: OsvEvent; v: Parsed } => x.v !== null)
        .sort((a, b) => compareParsedVersions(a.v, b.v));
      // Walk the intervals [introduced, end) / [introduced, last_affected].
      let start: Parsed | null = null;
      const close = (end: Parsed | null, inclusive: boolean, fix?: string): void => {
        if (!start) return;
        const startsBeforeHi = compareParsedVersions(start, bounds.hi) < 0;
        const c = end ? compareParsedVersions(end, bounds.lo) : 1;
        const endsAfterLo = end === null || (inclusive ? c >= 0 : c > 0);
        if (startsBeforeHi && endsAfterLo) {
          affected = true;
          const fv = fix ? parseVersion(ecosystem, fix) : null;
          if (fix && fv && (!best || compareParsedVersions(fv, best.v) > 0)) best = { raw: fix, v: fv };
        }
        start = null;
      };
      for (const { e, v } of events) {
        if (e.introduced !== undefined) start ??= v;
        else if (e.fixed !== undefined) close(v, false, e.fixed);
        else if (e.last_affected !== undefined) close(v, true);
        else if (e.limit !== undefined) close(v, false);
      }
      close(null, false);
    }
  }
  const fix = best as { raw: string; v: Parsed } | null;
  return affected && fix ? { affected, fixedIn: fix.raw } : { affected };
}

const mentions = (vuln: OsvVuln, ecosystem: Ecosystem, name: string): boolean =>
  (vuln.affected ?? []).some(
    (a) => a.package?.ecosystem === ecosystem && normalizeName(ecosystem, a.package?.name ?? "") === normalizeName(ecosystem, name),
  );

/**
 * `serverMatched`: OSV already matched this exact version (a versioned query), so it applies
 * like a lockfile finding. Otherwise (name-only query) the version is evaluated here.
 */
export function evaluateRef(vuln: OsvVuln, ref: RefLike, serverMatched: boolean): RefEvaluation {
  const malicious = severityOf(vuln) === "malicious";
  if (!serverMatched && !mentions(vuln, ref.ecosystem, ref.name)) return { applies: false, certainty: "confirmed" };
  let result: RefEvaluation = { applies: false, certainty: "version-unknown" };
  if (ref.versionKind === "exact" && ref.version) {
    const ev = evaluate(vuln, ref.name, ref.version, ref.ecosystem);
    if (serverMatched || ev.affected) result = { applies: true, certainty: "confirmed", ...(ev.fixedIn ? { fixedIn: ev.fixedIn } : {}) };
    else result = { applies: false, certainty: "may-be-affected" };
  } else if (ref.versionKind === "line" && ref.lineOf) {
    const ev = lineAffected(vuln, ref.ecosystem, ref.name, ref.lineOf);
    result = ev.affected
      ? { applies: true, certainty: "may-be-affected", ...(ev.fixedIn ? { fixedIn: ev.fixedIn } : {}) }
      : { applies: false, certainty: "may-be-affected" };
  } else {
    result = { applies: true, certainty: "version-unknown" };
  }
  // A malicious package is reported whatever the version (with the certainty we have).
  if (malicious && !result.applies) return { applies: true, certainty: result.certainty };
  return result;
}
