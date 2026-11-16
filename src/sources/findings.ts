/** Source references -> OSV queries, and OSV answers -> findings (aliases collapsed as for lockfiles). */
import { aliasGroups, representative } from "../findings.ts";
import { isInformational, severityRank, type Severity } from "../match.ts";
import type { OsvVuln, PackageQuery } from "../osv.ts";
import { clean } from "../sanitize.ts";
import { queryKey } from "../scan/lookup.ts";
import { findingKey, type Certainty } from "../store.ts";
import { evaluateRef, type RefEvaluation } from "./evaluate.ts";
import type { SourceFinding, SourceRef } from "./types.ts";

/**
 * GitHub Actions are never matched by version server-side, and a reference without an exact
 * version can only be asked by name: both are name-only queries evaluated locally.
 */
export function queryFor(ref: SourceRef): PackageQuery {
  const exact = ref.versionKind === "exact" && ref.version !== null && ref.ecosystem !== "GitHub Actions";
  return exact ? { name: ref.name, version: ref.version!, ecosystem: ref.ecosystem } : { name: ref.name, ecosystem: ref.ecosystem };
}

/** The version shown for a reference: the exact one, "4.x" for a line, else what is written. */
export function refVersion(ref: Pick<SourceRef, "version" | "versionKind" | "lineOf" | "pin">): string {
  if (ref.versionKind === "exact" && ref.version) return ref.version;
  if (ref.versionKind === "line" && ref.lineOf) return `${ref.lineOf}.x`;
  return ref.pin ? clean(ref.pin, 64) : "*";
}

const CERTAINTY_RANK: Record<Certainty, number> = { confirmed: 0, "may-be-affected": 1, "version-unknown": 2 };

/** References of the same package and version, with every place they appear. */
function uniqueRefs(refs: SourceRef[]): Array<{ ref: SourceRef; locations: Array<{ file: string; line: number }> }> {
  const map = new Map<string, { ref: SourceRef; locations: Array<{ file: string; line: number }> }>();
  for (const ref of refs) {
    const key = `${ref.ecosystem}|${ref.name}|${ref.versionKind}|${refVersion(ref)}`;
    let e = map.get(key);
    if (!e) {
      e = { ref, locations: [] };
      map.set(key, e);
    }
    e.locations.push({ file: ref.file, line: ref.line });
  }
  return [...map.values()];
}

export function buildSourceFindings(
  refs: SourceRef[],
  found: { refs: Map<string, string[]>; vulns: Map<string, OsvVuln> },
  previous: { findings: SourceFinding[] } | null,
  now: string,
): SourceFinding[] {
  const prevSeen = new Map((previous?.findings ?? []).map((f) => [findingKey(f), f.firstSeen]));
  const out: SourceFinding[] = [];
  for (const { ref, locations } of uniqueRefs(refs)) {
    const q = queryFor(ref);
    const ids = [...new Set(found.refs.get(queryKey(q)) ?? [])].filter((id) => {
      const v = found.vulns.get(id);
      return !v?.withdrawn && !(v && isInformational(v));
    });
    for (const group of aliasGroups(ids, found.vulns)) {
      // Unknown advisory details: only a malicious id can be trusted to apply.
      const evals = group.map((m): RefEvaluation =>
        m.vuln
          ? evaluateRef(m.vuln, ref, q.version !== undefined)
          : { applies: q.version !== undefined || m.id.startsWith("MAL-"), certainty: q.version !== undefined ? "confirmed" : "version-unknown" },
      );
      const applying = evals.filter((e) => e.applies);
      if (applying.length === 0) continue;
      const certainty = applying.map((e) => e.certainty).sort((a, b) => CERTAINTY_RANK[a] - CERTAINTY_RANK[b])[0]!;
      const rep = representative(group);
      const known = group.map((m) => m.severity).filter((s) => s !== "unknown");
      const severity: Severity = known.sort((a, b) => severityRank(a) - severityRank(b))[0] ?? "unknown";
      const others = group.filter((m) => m !== rep);
      const aliases = [...new Set([...(rep.vuln?.aliases ?? []), ...others.map((m) => m.id)])].filter((a) => a !== rep.id);
      const summary = rep.vuln?.summary ?? others.find((m) => m.vuln?.summary)?.vuln?.summary ?? rep.vuln?.details ?? "";
      const fixedIn = applying.find((e) => e.fixedIn)?.fixedIn;
      const f: SourceFinding = {
        id: rep.id,
        aliases: aliases.map((a) => clean(a, 64)).slice(0, 10),
        severity,
        summary: clean(summary, 200),
        name: ref.name,
        version: refVersion(ref),
        direct: true,
        dev: false,
        firstSeen: "",
        locations: locations.slice(0, 50),
      };
      if (fixedIn) f.fixedIn = clean(fixedIn, 64);
      if (ref.ecosystem !== "npm") f.ecosystem = ref.ecosystem;
      if (certainty !== "confirmed") f.certainty = certainty;
      if (ref.pin && ref.versionKind !== "exact") f.pin = clean(ref.pin, 64);
      f.firstSeen = prevSeen.get(findingKey(f)) ?? now;
      out.push(f);
    }
  }
  return out.sort(
    (a, b) =>
      severityRank(a.severity) - severityRank(b.severity) ||
      CERTAINTY_RANK[a.certainty ?? "confirmed"] - CERTAINTY_RANK[b.certainty ?? "confirmed"] ||
      a.name.localeCompare(b.name),
  );
}
