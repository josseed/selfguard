/**
 * Turn OSV matches into findings: one per advisory per package, with duplicates published
 * under several ids (GHSA, CVE, PYSEC, GO, RUSTSEC) collapsed into one.
 */
import { ecosystemOf, packageKey, type Dependency } from "./lockfile/types.ts";
import { evaluate, isInformational, severityOf, severityRank, type Severity } from "./match.ts";
import type { OsvVuln } from "./osv.ts";
import { clean } from "./sanitize.ts";
import { findingKey, type Finding, type RepoRecord } from "./store.ts";

interface Member {
  id: string;
  vuln: OsvVuln | undefined;
  severity: Severity;
}

const severityFor = (id: string, vuln: OsvVuln | undefined): Severity =>
  vuln ? severityOf(vuln) : id.startsWith("MAL-") ? "malicious" : "unknown";

/**
 * Group ids that are aliases of each other, in either direction (a GO-* entry lists its GHSA,
 * but the GHSA doesn't list the GO-* id). Order of `ids` is kept for groups.
 */
export function aliasGroups(ids: string[], vulns: Map<string, OsvVuln>): Member[][] {
  const parent = new Map<string, string>(ids.map((id) => [id, id]));
  const find = (x: string): string => {
    while (parent.get(x) !== x) x = parent.get(x)!;
    return x;
  };
  const owner = new Map<string, string>(); // id or alias -> an id that names it
  for (const id of ids) {
    for (const name of [id, ...(vulns.get(id)?.aliases ?? [])]) {
      const other = owner.get(name);
      if (other === undefined) owner.set(name, id);
      else parent.set(find(id), find(other));
    }
  }
  const groups = new Map<string, Member[]>();
  for (const id of ids) {
    const root = find(id);
    const vuln = vulns.get(id);
    groups.set(root, [...(groups.get(root) ?? []), { id, vuln, severity: severityFor(id, vuln) }]);
  }
  return [...groups.values()];
}

/** The member to report: malicious first, then one with a known severity, then a GHSA. */
function representative(group: Member[]): Member {
  const score = (m: Member): number =>
    (m.severity === "malicious" ? 0 : m.severity === "unknown" ? 20 : 10) + (m.id.startsWith("GHSA-") ? 0 : 1) + (m.vuln ? 0 : 5);
  return [...group].sort((a, b) => score(a) - score(b))[0]!;
}

export function buildFindings(
  deps: Dependency[],
  refsPerDep: Map<string, string[]>,
  vulns: Map<string, OsvVuln>,
  previous: RepoRecord | null,
  now: string,
): Finding[] {
  const prevSeen = new Map((previous?.findings ?? []).map((f) => [findingKey(f), f.firstSeen]));
  const findings: Finding[] = [];
  for (const dep of deps) {
    const ids = [...new Set(refsPerDep.get(packageKey(dep)) ?? [])].filter((id) => {
      const v = vulns.get(id);
      return !v?.withdrawn && !(v && isInformational(v));
    });
    for (const group of aliasGroups(ids, vulns)) {
      const rep = representative(group);
      // The worst severity any copy of the advisory states.
      const known = group.map((m) => m.severity).filter((s) => s !== "unknown");
      const severity = known.sort((a, b) => severityRank(a) - severityRank(b))[0] ?? "unknown";
      const others = group.filter((m) => m !== rep);
      const aliases = [...new Set([...(rep.vuln?.aliases ?? []), ...others.map((m) => m.id)])].filter((a) => a !== rep.id);
      const ev = [rep, ...others].map((m) => (m.vuln ? evaluate(m.vuln, dep.name, dep.version, ecosystemOf(dep)) : null)).find((e) => e?.fixedIn);
      const summary = rep.vuln?.summary ?? others.find((m) => m.vuln?.summary)?.vuln?.summary ?? rep.vuln?.details ?? "";
      const f: Finding = {
        id: rep.id,
        aliases: aliases.map((a) => clean(a, 64)).slice(0, 10),
        severity,
        summary: clean(summary, 200),
        name: dep.name,
        version: dep.version,
        direct: dep.direct,
        dev: dep.dev,
        firstSeen: "",
      };
      if (ev?.fixedIn) f.fixedIn = ev.fixedIn;
      if (dep.ecosystem && dep.ecosystem !== "npm") f.ecosystem = dep.ecosystem;
      f.firstSeen = prevSeen.get(findingKey(f)) ?? now;
      findings.push(f);
    }
  }
  return findings.sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name),
  );
}
