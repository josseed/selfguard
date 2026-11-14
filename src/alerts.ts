/** Decide what to tell the user (and how) after a scan or sync. Pure: easy to test. */
import { basename } from "node:path";
import type { Severity } from "./match.ts";
import { criticalDialog, notify } from "./notify.ts";
import { groupByPackage, worstSeverity } from "./report.ts";
import type { Finding } from "./store.ts";

export interface ProjectNews {
  path: string;
  newFindings: Finding[];
}

export type Alert =
  | { kind: "none" }
  | { kind: "banner"; title: string; subtitle: string; body: string }
  | { kind: "critical"; title: string; subtitle: string; body: string; dialogTitle: string; dialogMessage: string; url: string };

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

export function buildAlert(news: ProjectNews[]): Alert {
  const affected = news.filter((n) => n.newFindings.length > 0);
  if (affected.length === 0) return { kind: "none" };
  const all = affected.flatMap((n) => n.newFindings);

  const malicious = affected.flatMap((n) => n.newFindings.filter((f) => f.severity === "malicious").map((f) => ({ f, path: n.path })));
  if (malicious.length > 0) {
    const { f, path } = malicious[0]!;
    const where = affected.length === 1 ? name(path) : `${affected.length} projects`;
    const others = malicious.length > 1 ? ` (+${malicious.length - 1} more malicious)` : "";
    return {
      kind: "critical",
      title: `⛔ Malicious package in ${where}`,
      subtitle: `${f.name}@${f.version} · ${f.id}`,
      body: "Remove it now and rotate credentials on this machine.",
      dialogTitle: `selfguard: malicious package in ${where}`,
      dialogMessage:
        `${f.name}@${f.version} is a known malicious package${others}.\n\n` +
        `Project: ${path}\n\n` +
        "1. Remove it (or pin a safe version) and reinstall.\n" +
        "2. Rotate credentials this machine or CI could reach: npm tokens, cloud keys, SSH keys, .env secrets.\n" +
        "3. Check the advisory for what the payload does.",
      url: `https://osv.dev/vulnerability/${encodeURIComponent(f.id)}`,
    };
  }

  const worst = LABEL[worstSeverity(all) ?? "unknown"];
  if (affected.length === 1) {
    const n = affected[0]!;
    const pkgs = groupByPackage(n.newFindings).length;
    return {
      kind: "banner",
      title: `selfguard: ${name(n.path)}`,
      subtitle: `${plural(pkgs, "vulnerable package")} · worst: ${worst}`,
      body: listFixes(n.newFindings),
    };
  }
  const pkgs = affected.reduce((sum, n) => sum + groupByPackage(n.newFindings).length, 0);
  const names = affected.map((n) => name(n.path));
  return {
    kind: "banner",
    title: `selfguard: ${affected.length} projects affected`,
    subtitle: `${plural(pkgs, "vulnerable package")} · worst: ${worst}`,
    body: `${names.slice(0, 3).join(", ")}${names.length > 3 ? ` +${names.length - 3} more` : ""}. Run: selfguard status`,
  };
}

export async function deliver(alert: Alert): Promise<void> {
  if (alert.kind === "none") return;
  await notify(alert.title, alert.body, alert.subtitle);
  if (alert.kind === "critical") await criticalDialog(alert.dialogTitle, alert.dialogMessage, alert.url);
}
