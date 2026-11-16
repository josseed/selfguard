import { ApiError } from "../errors.ts";
import { ecosystemOf, packageKey, SUPPORTED_ECOSYSTEMS, type Ecosystem } from "../lockfile/types.ts";
import { evaluate, severityOf, severityRank, type Severity } from "../match.ts";
import { getVulns, type OsvVuln } from "../osv.ts";
import { groupByPackage } from "../report.ts";
import { clean } from "../sanitize.ts";
import { listSources } from "../sources/store.ts";
import type { SourceKind } from "../sources/types.ts";
import { listAllRepos } from "../store.ts";
import { compareVersions, isValidVersion, normalizeName } from "../versions.ts";
import { advisoryUrl, machineNames } from "./common.ts";
import { getAttention } from "./status.ts";

export interface WhereResult {
  package: string;
  usedIn: Array<{
    path: string;
    machine: string | null;
    versions: Array<{ version: string; ecosystem: Ecosystem; direct: boolean; dev: boolean; vulnerable: boolean }>;
    /** Set when found in a CI workflow ("ci") or an agent config ("agents") rather than a lockfile. */
    source?: SourceKind;
  }>;
}

/** Where a package is installed, in any ecosystem (PyPI names match PEP 503-normalized). */
export function whereUsed(name: string, ecosystem?: Ecosystem): WhereResult {
  const usedIn: WhereResult["usedIn"] = [];
  const pyName = normalizeName("PyPI", name);
  const matches = (d: { name: string; ecosystem?: Ecosystem }): boolean => {
    const eco = ecosystemOf(d);
    if (ecosystem && eco !== ecosystem) return false;
    if (eco === "GitHub Actions") return d.name.toLowerCase() === name.toLowerCase(); // GitHub ignores case
    return eco === "PyPI" ? normalizeName("PyPI", d.name) === pyName : d.name === name;
  };
  for (const r of listAllRepos(machineNames())) {
    const versions = r.deps
      .filter(matches)
      .map((d) => ({
        version: d.version,
        ecosystem: ecosystemOf(d),
        direct: d.direct,
        dev: d.dev,
        vulnerable: r.findings.some((f) => packageKey(f) === packageKey(d)),
      }));
    if (versions.length) usedIn.push({ path: r.path, machine: r.machine ?? null, versions });
  }
  // Workflows and agent configs: references written there (version as pinned when not exact).
  for (const r of listSources()) {
    const refs = r.refs.filter(matches);
    if (!refs.length) continue;
    const versions = [...new Map(refs.map((ref) => {
      const version = ref.version ?? (ref.lineOf ? `${ref.lineOf}.x` : (ref.pin ?? "*"));
      const vulnerable = r.findings.some((f) => f.name === ref.name && ecosystemOf(f) === ecosystemOf(ref));
      return [`${ecosystemOf(ref)}:${version}`, { version, ecosystem: ecosystemOf(ref), direct: true, dev: false, vulnerable }];
    })).values()];
    usedIn.push({ path: r.path, machine: null, versions, source: r.kind });
  }
  return { package: name, usedIn };
}

export interface PackageOverview {
  name: string;
  ecosystem: Ecosystem;
  worstSeverity: Severity;
  direct: boolean;
  /** Only in dev dependencies everywhere. */
  dev: boolean;
  /** Per installed vulnerable version: the version to upgrade to (null: no fix, or malicious). */
  fixes: Array<{ version: string; upgradeTo: string | null; worstSeverity: Severity }>;
  advisories: string[];
  repos: Array<{ key: string; label: string; path: string; machine: string | null; branch: string | null; version: string; direct: boolean; dev: boolean }>;
}

/**
 * Vulnerable packages across repos, judged on each repo's representative checkout (the same
 * one reminders use): "upgrading next fixes 5 repos". No network.
 */
export function getPackagesOverview(): PackageOverview[] {
  const byName = new Map<string, PackageOverview & { fixMap: Map<string, PackageOverview["fixes"][number]>; adv: Set<string> }>();
  for (const r of getAttention()) {
    for (const g of groupByPackage(r.findings)) {
      const key = `${g.ecosystem}:${g.name}`;
      let p = byName.get(key);
      if (!p) {
        p = { name: g.name, ecosystem: g.ecosystem, worstSeverity: g.worst, direct: false, dev: true, fixes: [], advisories: [], repos: [], fixMap: new Map(), adv: new Set() };
        byName.set(key, p);
      }
      if (severityRank(g.worst) < severityRank(p.worstSeverity)) p.worstSeverity = g.worst;
      p.direct ||= g.direct;
      p.dev &&= g.dev;
      p.fixMap.set(g.version, { version: g.version, upgradeTo: g.worst === "malicious" ? null : (g.upgradeTo ?? null), worstSeverity: g.worst });
      for (const f of g.findings) p.adv.add(f.id);
      p.repos.push({ key: r.key, label: r.label, path: r.path, machine: r.machine, branch: r.branch, version: g.version, direct: g.direct, dev: g.dev });
    }
  }
  return [...byName.values()]
    .map(({ fixMap, adv, ...p }) => ({
      ...p,
      fixes: [...fixMap.values()].sort((a, b) =>
        isValidVersion(p.ecosystem, a.version) && isValidVersion(p.ecosystem, b.version)
          ? compareVersions(p.ecosystem, a.version, b.version)
          : a.version.localeCompare(b.version),
      ),
      advisories: [...adv],
    }))
    .sort(
      (a, b) =>
        severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
        b.repos.length - a.repos.length ||
        a.name.localeCompare(b.name),
    );
}

export interface VulnerabilityDetail {
  id: string;
  aliases: string[];
  severity: Severity;
  summary: string;
  details: string;
  published: string | null;
  modified: string | null;
  withdrawn: string | null;
  affected: Array<{ ecosystem: string; package: string; ranges: Array<{ introduced?: string; fixed?: string; last_affected?: string }>; versions: string[] }>;
  references: string[];
  url: string;
  /** Tracked projects affected by this advisory. */
  affectsYourProjects: Array<{ path: string; machine: string | null; ecosystem: Ecosystem; package: string; version: string; fixedIn: string | null }>;
}

export async function getVulnerability(id: string): Promise<VulnerabilityDetail> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) throw new ApiError("invalid", "invalid advisory id");
  const vulns = await getVulns([{ id, modified: "" }]);
  const v: OsvVuln | undefined = vulns.get(id);
  if (!v) throw new ApiError("not_found", `advisory ${id} not found`);
  const s = (x: unknown, n: number): string => clean(x ?? "", n);
  const affectsYourProjects: VulnerabilityDetail["affectsYourProjects"] = [];
  for (const r of listAllRepos(machineNames())) {
    for (const d of r.deps) {
      const ev = evaluate(v, d.name, d.version, ecosystemOf(d));
      if (ev.affected) affectsYourProjects.push({ path: r.path, machine: r.machine ?? null, ecosystem: ecosystemOf(d), package: d.name, version: d.version, fixedIn: ev.fixedIn ?? null });
    }
  }
  const raw = v as unknown as Record<string, unknown>;
  return {
    id: v.id,
    aliases: (v.aliases ?? []).map((a) => s(a, 64)),
    severity: severityOf(v),
    summary: s(v.summary, 300),
    details: clean(v.details ?? "", 4000),
    published: typeof raw.published === "string" ? raw.published : null,
    modified: v.modified ?? null,
    withdrawn: v.withdrawn ?? null,
    affected: (v.affected ?? [])
      .filter((a) => typeof a.package?.ecosystem === "string" && (SUPPORTED_ECOSYSTEMS as readonly string[]).includes(a.package.ecosystem))
      .slice(0, 20)
      .map((a) => ({
        ecosystem: s(a.package?.ecosystem, 32),
        package: s(a.package?.name, 214),
        ranges: (a.ranges ?? []).flatMap((r) =>
          (r.events ?? []).map((e) => ({ ...e })),
        ).slice(0, 50),
        versions: (a.versions ?? []).slice(0, 50).map((x) => s(x, 64)),
      })),
    references: (Array.isArray(raw.references) ? raw.references : [])
      .map((r) => (r && typeof r === "object" ? (r as { url?: unknown }).url : undefined))
      .filter((u): u is string => typeof u === "string" && /^https:\/\//.test(u))
      .slice(0, 15)
      .map((u) => s(u, 300)),
    url: advisoryUrl(v.id),
    affectsYourProjects,
  };
}
