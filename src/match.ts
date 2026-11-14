/**
 * Local evaluation of OSV affected ranges (https://ossf.github.io/osv-schema/).
 * OSV already matched server-side; we evaluate locally to find the fixed version
 * and to classify severity.
 */
import type { OsvEvent, OsvVuln } from "./osv.ts";
import { compareParsed, parse, type SemVer } from "./semver.ts";

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

const ZERO: SemVer = { major: 0, minor: 0, patch: 0, pre: [] };

function eventVersion(e: OsvEvent): SemVer | null {
  const v = e.introduced ?? e.fixed ?? e.last_affected ?? e.limit;
  if (v === undefined) return null;
  if (e.introduced === "0") return { ...ZERO, pre: [0] }; // lower than anything, incl. 0.0.0-x
  return parse(v);
}

export interface Evaluation {
  affected: boolean;
  /** Lowest fixed version greater than the installed one, if any. */
  fixedIn?: string;
}

export function evaluate(vuln: OsvVuln, name: string, version: string): Evaluation {
  const v = parse(version);
  if (!v) return { affected: false };
  let affected = false;
  const fixes: Array<{ raw: string; sv: SemVer }> = [];

  for (const aff of vuln.affected ?? []) {
    if (aff.package?.ecosystem !== "npm" || aff.package?.name !== name) continue;
    if (Array.isArray(aff.versions) && aff.versions.includes(version)) affected = true;

    for (const range of aff.ranges ?? []) {
      if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
      const events = (range.events ?? [])
        .map((e) => ({ e, sv: eventVersion(e) }))
        .filter((x): x is { e: OsvEvent; sv: SemVer } => x.sv !== null)
        .sort((a, b) => compareParsed(a.sv, b.sv));

      let inRange = false;
      for (const { e, sv } of events) {
        const c = compareParsed(v, sv);
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
  fixes.sort((a, b) => compareParsed(a.sv, b.sv));
  return fixes[0] ? { affected, fixedIn: fixes[0].raw } : { affected };
}
