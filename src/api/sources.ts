/** CI workflows and agent configs: last results, no network (see docs/ci-and-agent-tools.md). */
import { resolve } from "node:path";
import { ApiError } from "../errors.ts";
import type { Ecosystem } from "../lockfile/types.ts";
import { severityRank, type Severity } from "../match.ts";
import { groupByPackage, worstSeverity } from "../report.ts";
import type { Certainty } from "../store.ts";
import { sourceLabel } from "../sources/news.ts";
import { gitRootsOf } from "../sources/run.ts";
import { sourceExtractors } from "../sources/registry.ts";
import { listSources } from "../sources/store.ts";
import type { SourceKind, SourceRecord, SourceRef, SourceScope, SourceWarning } from "../sources/types.ts";
import { advisoryUrl } from "./common.ts";
import { getRepoDetail } from "./reports.ts";

export interface SourceFindingReport {
  id: string;
  aliases: string[];
  severity: Severity;
  /** "confirmed" (exact version affected), "may-be-affected" (mutable tag) or "version-unknown". */
  certainty: Certainty;
  summary: string;
  name: string;
  ecosystem: Ecosystem;
  /** Exact version, "4.x" for a release line, or what is written (branch, SHA). */
  version: string;
  pin: string | null;
  /** Unpinned npx package: the version last run, when the advisory applies because of it. */
  lastRun: string | null;
  fixedIn: string | null;
  firstSeen: string;
  url: string;
  locations: Array<{ file: string; line: number }>;
}

export interface SourceReport {
  kind: SourceKind;
  scope: SourceScope;
  /** Git root, or the home folder for this machine's agent configs. */
  path: string;
  label: string;
  /** Repo group key (as in selfguard status) for repo sources; null for machine-wide ones. */
  repoKey: string | null;
  scannedAt: string | null;
  error: string | null;
  files: string[];
  references: Array<Omit<SourceRef, "lineOf" | "pin" | "agent" | "server" | "launcher"> & { lineOf: string | null; pin: string | null; agent: string | null; server: string | null; launcher: string | null }>;
  skippedReferences: number;
  /** Distinct references with at least one finding (warnings never count). */
  vulnerableReferences: number;
  worstSeverity: Severity | null;
  findings: SourceFindingReport[];
  /** Practices found without the network (unpinned references…). Not vulnerabilities. */
  warnings: SourceWarning[];
}

export interface SourcesResult {
  /** Kinds with an extractor in this version ([]: nothing is read yet). */
  kinds: SourceKind[];
  /** This machine's agent configs. */
  machine: SourceReport[];
  /** Per git root: CI workflows and project agent configs. */
  repos: SourceReport[];
}

export function toSourceReport(rec: SourceRecord): SourceReport {
  const s = sourceLabel(rec);
  return {
    kind: rec.kind,
    scope: rec.scope,
    path: rec.path,
    label: s.label,
    repoKey: rec.scope === "repo" ? s.key : null,
    scannedAt: rec.scannedAt,
    error: rec.error ?? null,
    files: rec.files.map((f) => f.path),
    references: rec.refs.map((r) => ({
      ecosystem: r.ecosystem,
      name: r.name,
      version: r.version,
      versionKind: r.versionKind,
      lineOf: r.lineOf ?? null,
      pin: r.pin ?? null,
      file: r.file,
      line: r.line,
      agent: r.agent ?? null,
      server: r.server ?? null,
      launcher: r.launcher ?? null,
    })),
    skippedReferences: rec.skipped,
    vulnerableReferences: groupByPackage(rec.findings).length,
    worstSeverity: worstSeverity(rec.findings),
    findings: rec.findings.map((f) => ({
      id: f.id,
      aliases: f.aliases,
      severity: f.severity,
      certainty: f.certainty ?? "confirmed",
      summary: f.summary,
      name: f.name,
      ecosystem: f.ecosystem ?? "npm",
      version: f.version,
      pin: f.pin ?? null,
      lastRun: f.lastRun ?? null,
      fixedIn: f.fixedIn ?? null,
      firstSeen: f.firstSeen,
      url: advisoryUrl(f.id),
      locations: f.locations,
    })),
    warnings: rec.warnings,
  };
}

const byRisk = (a: SourceReport, b: SourceReport): number =>
  severityRank(a.worstSeverity ?? "unknown") - severityRank(b.worstSeverity ?? "unknown") ||
  Number(a.worstSeverity === null) - Number(b.worstSeverity === null) ||
  b.warnings.length - a.warnings.length ||
  a.label.localeCompare(b.label);

/** Every source record; `path`: only the sources of the git repo around that folder. */
export function getSources(opts: { path?: string; kind?: SourceKind } = {}): SourcesResult {
  const kinds = [...new Set(sourceExtractors().map((e) => e.kind))];
  let records = listSources(opts.kind ? { kind: opts.kind } : {});
  if (opts.path !== undefined) {
    const roots = new Set(gitRootsOf([resolve(opts.path)]));
    if (roots.size === 0) throw new ApiError("not_found", `no git repository around ${resolve(opts.path)}`);
    records = records.filter((r) => r.scope === "repo" && roots.has(r.path));
  }
  const reports = records.map(toSourceReport);
  return {
    kinds,
    machine: reports.filter((r) => r.scope === "machine").sort(byRisk),
    repos: reports.filter((r) => r.scope === "repo").sort(byRisk),
  };
}

/** Sources of one repo group of the dashboard (its local checkouts' git roots). */
export function getRepoSources(key: string): SourceReport[] {
  const detail = getRepoDetail(key);
  const roots = new Set(gitRootsOf(detail.checkouts.filter((k) => !k.machine).map((k) => k.path)));
  return listSources({ scope: "repo" })
    .filter((r) => roots.has(r.path))
    .map(toSourceReport)
    .sort(byRisk);
}
