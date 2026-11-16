/**
 * Local evaluation of OSV affected ranges (https://ossf.github.io/osv-schema/).
 * OSV already matched server-side; we evaluate locally to find the fixed version
 * and to classify severity.
 */
import type { Ecosystem } from "./lockfile/types.ts";
import type { OsvEvent, OsvVuln } from "./osv.ts";
import { compareParsedVersions, lowest, normalizeName, parseVersion, type Parsed } from "./versions.ts";

export type Severity = "malicious" | "critical" | "high" | "moderate" | "low" | "unknown";

export const SEVERITY_ORDER: Severity[] = ["malicious", "critical", "high", "moderate", "low", "unknown"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function severityOf(vuln: OsvVuln): Severity {
  if (vuln.id.startsWith("MAL-") || vuln.aliases?.some((a) => a.startsWith("MAL-"))) return "malicious";
  const raw = vuln.database_specific?.severity;
  switch (typeof raw === "string" ? raw.toUpperCase() : "") {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "moderate";
    case "LOW":
      return "low";
    default:
      return "unknown";
  }
}

function eventVersion(eco: Ecosystem, e: OsvEvent): Parsed | null {
  const v = e.introduced ?? e.fixed ?? e.last_affected ?? e.limit;
  if (v === undefined) return null;
  if (e.introduced === "0") return lowest(eco); // lower than anything, incl. 0.0.0-x
  return parseVersion(eco, v);
}

export interface Evaluation {
  affected: boolean;
  /** Lowest fixed version greater than the installed one, if any. */
  fixedIn?: string;
}

/** Exact match; for PyPI also equivalent spellings ("1.0" == "1.0.0", "1.0RC1" == "1.0rc1"). */
function sameVersion(eco: Ecosystem, listed: unknown, version: string, parsed: Parsed): boolean {
  if (listed === version) return true;
  if (eco !== "PyPI" || typeof listed !== "string") return false;
  const p = parseVersion(eco, listed);
  return p !== null && compareParsedVersions(p, parsed) === 0;
}

/**
 * Whether `name@version` of `ecosystem` (default npm) is affected, and the lowest fix.
 * SEMVER ranges are compared as SemVer; ECOSYSTEM ranges with the ecosystem's own
 * ordering (PEP 440 for PyPI). GIT ranges are ignored.
 */
export function evaluate(vuln: OsvVuln, name: string, version: string, ecosystem: Ecosystem = "npm"): Evaluation {
  const v = parseVersion(ecosystem, version);
  if (!v) return { affected: false };
  const wanted = normalizeName(ecosystem, name);
  let affected = false;
  const fixes: Array<{ raw: string; sv: Parsed }> = [];

  for (const aff of vuln.affected ?? []) {
    if (aff.package?.ecosystem !== ecosystem || normalizeName(ecosystem, aff.package?.name ?? "") !== wanted) continue;
    if (Array.isArray(aff.versions) && aff.versions.some((x) => sameVersion(ecosystem, x, version, v))) affected = true;

    for (const range of aff.ranges ?? []) {
      if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
      const scheme: Ecosystem = range.type === "SEMVER" ? "npm" : ecosystem; // "npm" = plain SemVer
      const cur = scheme === ecosystem ? v : parseVersion(scheme, version);
      if (!cur) continue;
      const events = (range.events ?? [])
        .map((e) => ({ e, sv: eventVersion(scheme, e) }))
        .filter((x): x is { e: OsvEvent; sv: Parsed } => x.sv !== null)
        .sort((a, b) => compareParsedVersions(a.sv, b.sv));

      let inRange = false;
      for (const { e, sv } of events) {
        const c = compareParsedVersions(cur, sv);
        if (e.introduced !== undefined) {
          if (c >= 0) inRange = true;
        } else if (e.fixed !== undefined) {
          if (c >= 0) inRange = false;
          else fixes.push({ raw: e.fixed, sv });
        } else if (e.last_affected !== undefined) {
          if (c > 0) inRange = false;
        } else if (e.limit !== undefined) {
          if (c >= 0) inRange = false;
        }
      }
      if (inRange) affected = true;
    }
  }

  if (!affected) return { affected };
  // Fixes from SEMVER and ECOSYSTEM ranges may use different schemes: rank in the ecosystem's.
  const ranked = fixes
    .map((f) => ({ raw: f.raw, sv: parseVersion(ecosystem, f.raw) }))
    .filter((f): f is { raw: string; sv: Parsed } => f.sv !== null)
    .sort((a, b) => compareParsedVersions(a.sv, b.sv));
  return ranked[0] ? { affected, fixedIn: ranked[0].raw } : { affected };
}
