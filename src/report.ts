import { homedir } from "node:os";
import { severityRank, type Severity } from "./match.ts";
import { ecosystemOf, packageKey, type Ecosystem } from "./lockfile/types.ts";
import { compareVersions, isValidVersion } from "./versions.ts";
import { clean } from "./sanitize.ts";
import { packagesOf, type Finding, type RepoRecord } from "./store.ts";

function useColor(stream: NodeJS.WriteStream): boolean {
  return Boolean(stream.isTTY) && !process.env.NO_COLOR && process.env.TERM !== "dumb";
}

export function paint(stream: NodeJS.WriteStream) {
  const on = useColor(stream);
  const wrap = (open: number, close: number) => (s: string) => (on ? `\x1b[${open}m${s}\x1b[${close}m` : s);
  return {
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    red: wrap(31, 39),
    yellow: wrap(33, 39),
    green: wrap(32, 39),
    magenta: wrap(35, 39),
    cyan: wrap(36, 39),
    inverseRed: wrap(41, 49),
  };
}

export type Painter = ReturnType<typeof paint>;

export function severityLabel(s: Severity, c: Painter): string {
  switch (s) {
    case "malicious":
      return c.inverseRed(c.bold(" MALICIOUS "));
    case "critical":
      return c.red(c.bold("CRITICAL"));
    case "high":
      return c.red("HIGH");
    case "moderate":
      return c.yellow("MODERATE");
    case "low":
      return c.dim("LOW");
    default:
      return c.dim("UNKNOWN");
  }
}

export function tildify(p: string): string {
  const home = homedir();
  return p === home || p.startsWith(`${home}/`) ? `~${p.slice(home.length)}` : p;
}

export function countBySeverity(findings: Finding[]): Partial<Record<Severity, number>> {
  const counts: Partial<Record<Severity, number>> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

export function summarizeCounts(findings: Finding[]): string {
  const counts = countBySeverity(findings);
  const order: Severity[] = ["malicious", "critical", "high", "moderate", "low", "unknown"];
  return order
    .filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s}`)
    .join(", ");
}

export function renderFindings(rec: RepoRecord, stream: NodeJS.WriteStream, verbose = false): string {
  const c = paint(stream);
  const lines: string[] = [];
  const title = `${c.bold(tildify(rec.path))}  ${c.dim(`${packagesOf(rec)} packages`)}`;
  lines.push(title);
  if (rec.error) lines.push(`  ${c.yellow("!")} ${clean(rec.error)}`);
  if (rec.skipped > 0) lines.push(c.dim(`  ${rec.skipped} entries skipped (git, path, local or non-registry deps)`));
  if (rec.findings.length === 0) {
    if (!rec.error) lines.push(`  ${c.green("✓")} no known vulnerabilities`);
    return lines.join("\n");
  }
  const groups = groupByPackage(rec.findings);
  lines.push(`  ${groups.length} vulnerable package(s), ${rec.findings.length} advisories: ${summarizeCounts(rec.findings)}`);
  for (const g of groups) {
    const pkg = `${clean(g.name, 120)}@${clean(g.version, 60)}`;
    const tags = [g.ecosystem === "npm" ? "" : g.ecosystem, g.direct ? "direct" : "transitive", g.dev ? "dev" : ""].filter(Boolean).join(", ");
    lines.push("");
    lines.push(`  ${severityLabel(g.worst, c)} ${c.bold(pkg)} ${c.dim(`(${tags})`)}`);
    if (g.worst === "malicious") {
      lines.push(`    ${c.red("→ remove it now and rotate any credentials available on this machine/CI")}`);
    } else if (g.upgradeTo) {
      const partial = g.unfixed > 0 ? c.yellow(` (${g.unfixed} advisory(ies) have no fix yet)`) : "";
      lines.push(`    ${c.green(`→ upgrade to ${clean(g.upgradeTo, 60)} or later`)}${partial}`);
    } else {
      lines.push(`    ${c.yellow("→ no fixed version published; consider replacing it")}`);
    }
    const shown = verbose ? g.findings : g.findings.slice(0, 3);
    for (const f of shown) {
      lines.push(`    ${c.dim("•")} ${clean(f.id, 64)} ${c.dim(f.severity)}${f.summary ? ` ${clean(f.summary, 90)}` : ""}`);
    }
    if (shown.length < g.findings.length) lines.push(c.dim(`    • …and ${g.findings.length - shown.length} more (--verbose)`));
  }
  lines.push("");
  lines.push(c.dim("  Details: https://osv.dev/vulnerability/<ID>"));
  return lines.join("\n");
}

export function worstSeverity(findings: Finding[]): Severity | null {
  const order: Severity[] = ["malicious", "critical", "high", "moderate", "low", "unknown"];
  for (const s of order) if (findings.some((f) => f.severity === s)) return s;
  return null;
}

export interface PackageGroup {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  direct: boolean;
  dev: boolean;
  worst: Severity;
  findings: Finding[];
  /** Smallest version that fixes every advisory that has a fix. */
  upgradeTo?: string;
  unfixed: number;
}

export function groupByPackage(findings: Finding[]): PackageGroup[] {
  const map = new Map<string, PackageGroup>();
  for (const f of findings) {
    const key = packageKey(f);
    const eco = ecosystemOf(f);
    let g = map.get(key);
    if (!g) {
      g = { name: f.name, version: f.version, ecosystem: eco, direct: f.direct, dev: f.dev, worst: f.severity, findings: [], unfixed: 0 };
      map.set(key, g);
    }
    g.findings.push(f);
    if (severityRank(f.severity) < severityRank(g.worst)) g.worst = f.severity;
    if (f.fixedIn && isValidVersion(eco, f.fixedIn)) {
      if (!g.upgradeTo || compareVersions(eco, f.fixedIn, g.upgradeTo) > 0) g.upgradeTo = f.fixedIn;
    } else {
      g.unfixed++;
    }
  }
  return [...map.values()].sort(
    (a, b) => severityRank(a.worst) - severityRank(b.worst) || Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name),
  );
}
