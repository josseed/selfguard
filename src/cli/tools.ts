// `selfguard tools`: this machine's agent tools and each repo's CI workflows / agent configs.
import { relative } from "node:path";
import { parseArgs } from "node:util";
import * as api from "../api.ts";
import { paint, severityLabel, tildify, type Painter } from "../report.ts";
import { clean } from "../sanitize.ts";
import { emit, JSON_OPT, out } from "./output.ts";

const CERTAINTY: Record<api.SourceFindingReport["certainty"], string> = {
  confirmed: "",
  "may-be-affected": "mutable reference: may be affected",
  "version-unknown": "version unknown",
};

function where(file: string, line: number, root: string): string {
  const rel = file.startsWith(`${root}/`) ? relative(root, file) : tildify(file);
  return `${clean(rel, 200)}${line > 0 ? `:${line}` : ""}`;
}

function renderSource(s: api.SourceReport, c: Painter, verbose: boolean): string[] {
  const lines: string[] = [];
  const counts = [`${s.references.length} reference(s)`, s.skippedReferences ? `${s.skippedReferences} not checked` : ""].filter(Boolean).join(", ");
  lines.push(`${c.bold(clean(s.label, 120))}  ${c.dim(`${tildify(s.path)} · ${counts}`)}`);
  if (s.error) lines.push(`  ${c.yellow("!")} ${clean(s.error, 200)}`);
  if (s.findings.length === 0 && !s.error) lines.push(`  ${c.green("✓")} no known advisories`);
  const shown = verbose ? s.findings : s.findings.slice(0, 10);
  for (const f of shown) {
    const pkg = `${clean(f.name, 120)}@${clean(f.version, 60)}`;
    const certainty = f.lastRun ? `last run ${clean(f.lastRun, 40)} is affected` : CERTAINTY[f.certainty];
    const tags = [f.ecosystem === "npm" ? "" : f.ecosystem, certainty].filter(Boolean).join(", ");
    lines.push(`  ${severityLabel(f.severity, c)} ${c.bold(pkg)} ${clean(f.id, 64)}${tags ? c.dim(` (${tags})`) : ""}`);
    if (f.summary) lines.push(`    ${clean(f.summary, 100)}`);
    const loc = f.locations[0];
    if (loc) lines.push(c.dim(`    ${where(loc.file, loc.line, s.path)}${f.locations.length > 1 ? ` +${f.locations.length - 1} more` : ""}`));
    if (f.severity !== "malicious" && f.fixedIn) lines.push(`    ${c.green(`→ use ${clean(f.fixedIn, 60)} or later`)}`);
  }
  if (shown.length < s.findings.length) lines.push(c.dim(`  …and ${s.findings.length - shown.length} more (--verbose)`));
  const warnings = verbose ? s.warnings : s.warnings.slice(0, 5);
  for (const w of warnings) {
    lines.push(`  ${c.yellow("warning")} ${clean(w.message, 160)} ${c.dim(`[${clean(w.rule, 40)}] ${where(w.file, w.line, s.path)}`)}`);
  }
  if (warnings.length < s.warnings.length) lines.push(c.dim(`  …and ${s.warnings.length - warnings.length} more warning(s) (--verbose)`));
  return lines;
}

export function cmdTools(args: string[]): number {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { ...JSON_OPT, verbose: { type: "boolean", short: "v" } },
  });
  const result = api.getSources(positionals[0] !== undefined ? { path: positionals[0] } : {});
  if (values.json) {
    emit(result);
    return 0;
  }
  const c = paint(out);
  const verbose = values.verbose ?? false;
  if (result.kinds.length === 0) {
    out.write(`${c.dim("CI workflows and agent tools aren't checked by this version yet.")}\n`);
    return 0;
  }
  const blocks: string[] = [];
  if (positionals[0] === undefined) {
    blocks.push(c.bold("Agent tools on this machine"));
    blocks.push(...(result.machine.length ? result.machine.flatMap((s) => renderSource(s, c, verbose)) : [c.dim("  none found")]));
    blocks.push("");
  }
  blocks.push(c.bold("Repos"));
  blocks.push(...(result.repos.length ? result.repos.flatMap((s) => [...renderSource(s, c, verbose), ""]) : [c.dim("  no CI workflows or agent configs found"), ""]));
  blocks.push(c.dim("Warnings are practices to review, not vulnerabilities. Details: https://osv.dev/vulnerability/<ID>"));
  out.write(`${blocks.join("\n")}\n`);
  return 0;
}
