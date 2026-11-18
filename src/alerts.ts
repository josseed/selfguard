/** Decide what to tell the user (and how) after a scan or sync. Pure: easy to test. */
import { basename } from "node:path";
import type { Severity } from "./match.ts";
import { queueForApp } from "./appalerts.ts";
import { criticalDialog, notify } from "./notify.ts";
import { groupByPackage, worstSeverity } from "./report.ts";
import { packageKey } from "./lockfile/types.ts";
import { findingKey, type Finding } from "./store.ts";

export interface ProjectNews {
  path: string;
  newFindings: Finding[];
  /** Findings that disappeared since the previous scan on the same branch. */
  resolvedFindings?: Finding[];
  /** Current findings after the scan (to say what is left). */
  findings?: Finding[];
  /** Same key = same repo (worktrees/clones): reported once. */
  repo?: { key: string; label: string } | null;
  /** Inactive checkouts (no recent git activity) only alert for malicious packages. */
  active?: boolean;
}

/** What the Mac app's mascot acts out for an alert (see appalerts.ts). */
export type AlertScene = "mal" | "crit" | "high" | "fixed";

/** `repoKey`: the one repo the alert is about, so the app can open it (absent: several). */
export type Alert =
  | { kind: "none" }
  | { kind: "banner"; title: string; subtitle: string; body: string; scene: AlertScene; repoKey?: string }
  | { kind: "critical"; title: string; subtitle: string; body: string; dialogTitle: string; dialogMessage: string; url: string; scene: "mal"; repoKey?: string };

const sceneOf = (findings: Finding[]): AlertScene => {
  const worst = worstSeverity(findings);
  return worst === "malicious" ? "mal" : worst === "critical" ? "crit" : "high";
};

const LABEL: Record<Severity, string> = {
  malicious: "MALICIOUS",
  critical: "CRITICAL",
  high: "HIGH",
  moderate: "MODERATE",
  low: "LOW",
  unknown: "UNKNOWN",
};

const name = (path: string): string => basename(path) || path;
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

function listFixes(findings: Finding[], max = 3): string {
  const groups = groupByPackage(findings);
  const parts = groups.slice(0, max).map((g) => (g.upgradeTo ? `${g.name} → ${g.upgradeTo}` : `${g.name} (no fix yet)`));
  if (groups.length > max) parts.push(`+${groups.length - max} more`);
  return parts.join(", ");
}

/** Merge checkouts of the same repo into one entry, de-duplicating findings. */
function byRepo(news: ProjectNews[]): Array<ProjectNews & { key: string; label: string; checkouts: number }> {
  const groups = new Map<string, ProjectNews & { key: string; label: string; checkouts: number; seen: Set<string> }>();
  for (const n of news) {
    if (n.newFindings.length === 0) continue;
    const key = n.repo?.key ?? `path:${n.path}`;
    let g = groups.get(key);
    if (!g) {
      g = { path: n.path, key, newFindings: [], label: n.repo?.label ?? name(n.path), checkouts: 0, seen: new Set() };
      groups.set(key, g);
    }
    g.checkouts++;
    for (const f of n.newFindings) {
      const k = findingKey(f);
      if (g.seen.has(k)) continue;
      g.seen.add(k);
      g.newFindings.push(f);
    }
  }
  return [...groups.values()].map(({ seen: _s, ...g }) => g);
}

export function buildAlert(news: ProjectNews[]): Alert {
  const relevant = news.map((n) =>
    n.active === false ? { ...n, newFindings: n.newFindings.filter((f) => f.severity === "malicious") } : n,
  );
  const affected = byRepo(relevant);
  if (affected.length === 0) return { kind: "none" };
  const all = affected.flatMap((n) => n.newFindings);

  const malicious = affected.flatMap((n) => n.newFindings.filter((f) => f.severity === "malicious").map((f) => ({ f, path: n.path })));
  if (malicious.length > 0) {
    const { f, path } = malicious[0]!;
    const group = affected.find((n) => n.path === path)!;
    const where = affected.length === 1 ? group.label : `${affected.length} projects`;
    const others = malicious.length > 1 ? ` (+${malicious.length - 1} more malicious)` : "";
    return {
      kind: "critical",
      title: `⛔ Malicious package in ${where}`,
      subtitle: `${f.name}@${f.version} · ${f.id}`,
      body: "Remove it now and rotate credentials on this machine.",
      dialogTitle: `selfguard: malicious package in ${where}`,
      dialogMessage:
        `${f.name}@${f.version} is a known malicious package${others}.\n\n` +
        `Project: ${path}${group.checkouts > 1 ? ` (and ${group.checkouts - 1} other checkout(s) of ${group.label})` : ""}\n\n` +
        "1. Remove it (or pin a safe version) and reinstall.\n" +
        "2. Rotate credentials this machine or CI could reach: npm tokens, cloud keys, SSH keys, .env secrets.\n" +
        "3. Check the advisory for what the payload does.",
      url: `https://osv.dev/vulnerability/${encodeURIComponent(f.id)}`,
      scene: "mal",
      ...(affected.length === 1 ? { repoKey: group.key } : {}),
    };
  }

  const worst = LABEL[worstSeverity(all) ?? "unknown"];
  if (affected.length === 1) {
    const n = affected[0]!;
    const pkgs = groupByPackage(n.newFindings).length;
    return {
      kind: "banner",
      title: `selfguard: ${n.label}${n.checkouts > 1 ? ` (${n.checkouts} checkouts)` : ""}`,
      subtitle: `${plural(pkgs, "vulnerable package")} · worst: ${worst}`,
      body: listFixes(n.newFindings),
      scene: sceneOf(n.newFindings),
      repoKey: n.key,
    };
  }
  const pkgs = affected.reduce((sum, n) => sum + groupByPackage(n.newFindings).length, 0);
  const names = affected.map((n) => n.label);
  return {
    kind: "banner",
    title: `selfguard: ${affected.length} projects affected`,
    subtitle: `${plural(pkgs, "vulnerable package")} · worst: ${worst}`,
    body: `${names.slice(0, 3).join(", ")}${names.length > 3 ? ` +${names.length - 3} more` : ""}. Run: selfguard status`,
    scene: sceneOf(all),
  };
}

const pkgKey = (f: Finding): string => packageKey(f);

/** "datahub ✓ 17 vulnerable packages fixed": only for active checkouts, grouped by repo. */
export function buildResolvedAlert(news: ProjectNews[]): Alert {
  const groups = new Map<string, { key: string; label: string; fixed: Set<string>; left: Map<string, Finding> }>();
  for (const n of news) {
    if (n.active === false || !n.resolvedFindings?.length) continue;
    const still = new Set((n.findings ?? []).map(pkgKey));
    const fixed = n.resolvedFindings.map(pkgKey).filter((k) => !still.has(k));
    if (fixed.length === 0) continue;
    const key = n.repo?.key ?? `path:${n.path}`;
    let g = groups.get(key);
    if (!g) {
      g = { key, label: n.repo?.label ?? name(n.path), fixed: new Set(), left: new Map() };
      groups.set(key, g);
    }
    for (const k of fixed) g.fixed.add(k);
    for (const f of n.findings ?? []) g.left.set(`${f.id}|${pkgKey(f)}`, f);
  }
  if (groups.size === 0) return { kind: "none" };
  const list = [...groups.values()];
  const total = list.reduce((sum, g) => sum + g.fixed.size, 0);
  if (list.length === 1) {
    const g = list[0]!;
    const left = [...g.left.values()];
    const leftPkgs = groupByPackage(left).length;
    return {
      kind: "banner",
      title: `selfguard: ${g.label} ✓`,
      subtitle: `${plural(g.fixed.size, "vulnerable package")} fixed`,
      body: leftPkgs
        ? `${leftPkgs} still vulnerable · worst: ${LABEL[worstSeverity(left) ?? "unknown"]}`
        : "No known vulnerabilities left.",
      scene: "fixed",
      repoKey: g.key,
    };
  }
  const names = list.map((g) => g.label);
  return {
    kind: "banner",
    title: `selfguard: fixes in ${list.length} repos`,
    subtitle: `${plural(total, "vulnerable package")} fixed`,
    body: `${names.slice(0, 3).join(", ")}${names.length > 3 ? ` +${names.length - 3} more` : ""}`,
    scene: "fixed",
  };
}

/**
 * What a reminder nags about: any malicious package; critical vulnerabilities outside dev
 * dependencies; high ones in direct (non-dev) dependencies. The rest stays in the dashboard,
 * so the reminder remains rare enough to be read.
 */
export const needsAttention = (f: Finding): boolean =>
  f.severity === "malicious" || (!f.dev && (f.severity === "critical" || (f.severity === "high" && f.direct)));

export interface AttentionRepo {
  label: string;
  /** Current findings of the repo's active checkouts (any severity; filtered here). */
  findings: Finding[];
}

function severityCounts(findings: Finding[]): string {
  const counts = new Map<Severity, number>();
  for (const g of groupByPackage(findings)) counts.set(g.worst, (counts.get(g.worst) ?? 0) + 1);
  return (["malicious", "critical", "high"] as Severity[])
    .filter((s) => counts.get(s))
    .map((s) => `${counts.get(s)} ${s}`)
    .join(", ");
}

/** Periodic reminder of unresolved serious findings in the repos you work on. */
export function buildReminder(repos: AttentionRepo[]): Alert {
  const rank = (s: Severity | null): number => ["malicious", "critical", "high"].indexOf(s ?? "");
  const serious = repos
    .map((r) => ({ label: r.label, findings: r.findings.filter(needsAttention) }))
    .filter((r) => r.findings.length > 0)
    .sort(
      (a, b) =>
        rank(worstSeverity(a.findings)) - rank(worstSeverity(b.findings)) ||
        groupByPackage(b.findings).length - groupByPackage(a.findings).length,
    );
  if (serious.length === 0) return { kind: "none" };
  const all = serious.flatMap((r) => r.findings);
  if (serious.length === 1) {
    const r = serious[0]!;
    return {
      kind: "banner",
      title: `selfguard: ${r.label} needs attention`,
      subtitle: `${severityCounts(r.findings)} · details: selfguard status`,
      body: listFixes(r.findings),
      scene: sceneOf(r.findings),
    };
  }
  const parts = serious.slice(0, 3).map((r) => `${r.label} (${severityCounts(r.findings)})`);
  if (serious.length > 3) parts.push(`+${serious.length - 3} more`);
  return {
    kind: "banner",
    title: `selfguard: ${serious.length} repos need attention`,
    subtitle: `worst: ${LABEL[worstSeverity(all) ?? "unknown"]} · details: selfguard status`,
    body: parts.join(", "),
    scene: sceneOf(all),
  };
}

/**
 * Tell the user. While the Mac app runs with its mascot alerts on, it shows the alert (once,
 * with Bastion); otherwise macOS banners and, for malicious packages, the blocking dialog.
 */
export async function deliver(alert: Alert): Promise<void> {
  if (alert.kind === "none") return;
  if (queueForApp(alert)) return;
  await notify(alert.title, alert.body, alert.subtitle);
  if (alert.kind === "critical") await criticalDialog(alert.dialogTitle, alert.dialogMessage, alert.url);
}
