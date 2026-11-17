// Project commands: scan, report, status, where, vuln.
import { parseArgs } from "node:util";
import * as api from "../api.ts";
import { paint, renderFindings, severityLabel, tildify } from "../report.ts";
import { clean } from "../sanitize.ts";
import { loadRepo } from "../store.ts";
import { cachedUpdate } from "../update.ts";
import { ago, emit, JSON_OPT, out, usage } from "./output.ts";
import { parseEcosystem } from "../lockfile/types.ts";

/** Detached scan started by the shell hook: log + notify, never print to a terminal. */
async function backgroundScan(path: string): Promise<number> {
  const stamp = new Date().toISOString();
  try {
    const r = await api.scanPath(path, { notify: true });
    out.write(`${stamp} scan ${r.project.path}: ${r.project.advisories} finding(s)${r.project.error ? ` (${r.project.error})` : ""}\n`);
  } catch (e) {
    if (!(e instanceof api.ApiError && e.code === "busy")) out.write(`${stamp} scan ${path}: ${(e as Error).message}\n`);
  }
  return 0;
}

export async function cmdScan(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { ...JSON_OPT, background: { type: "boolean" }, verbose: { type: "boolean", short: "v" } },
  });
  const path = positionals[0] ?? ".";
  if (values.background) return backgroundScan(path);
  const r = await api.scanPath(path);
  if (values.json) emit(r);
  else out.write(`${renderFindings(loadRepo(r.project.path)!, out, values.verbose ?? false)}\n${sourcesLine(r.project.path)}`);
  return r.project.advisories > 0 ? 1 : 0;
}

/** One line pointing to `selfguard tools` when the repo's workflows or agent configs need a look. */
function sourcesLine(path: string): string {
  let repos: api.SourceReport[];
  try {
    repos = api.getSources({ path }).repos;
  } catch {
    return ""; // not in a git repo: no workflows to check
  }
  const vulnerable = repos.reduce((n, r) => n + r.vulnerableReferences, 0);
  const warnings = repos.reduce((n, r) => n + r.warnings.length, 0);
  if (!vulnerable && !warnings) return "";
  const c = paint(out);
  const what = [vulnerable ? c.red(`${vulnerable} vulnerable reference(s)`) : "", warnings ? c.yellow(`${warnings} warning(s)`) : ""].filter(Boolean).join(", ");
  return `\n  CI workflows and agent configs: ${what} ${c.dim(`→ selfguard tools ${clean(path, 200)}`)}\n`;
}

export function cmdReport(args: string[]): number {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { ...JSON_OPT, verbose: { type: "boolean", short: "v" }, markdown: { type: "boolean", short: "m" } },
  });
  if (values.markdown) {
    const md = api.getReportMarkdown(positionals[0] ?? ".");
    out.write(md.markdown);
    return md.packages > 0 ? 1 : 0;
  }
  const report = api.getReport(positionals[0] ?? ".");
  if (values.json) emit(report);
  else out.write(`${renderFindings(loadRepo(report.path)!, out, values.verbose ?? false)}\n`);
  return report.advisories > 0 ? 1 : 0;
}

export function cmdStatus(args: string[]): number {
  const { values } = parseArgs({
    args,
    options: { ...JSON_OPT, vulnerable: { type: "boolean" }, flat: { type: "boolean" }, all: { type: "boolean" } },
  });
  const status = api.getStatus({ onlyVulnerable: values.vulnerable ?? false });
  if (values.json) {
    emit(status);
    return 0;
  }
  const c = paint(out);
  if (status.projects.length === 0) {
    out.write(`No projects tracked yet. Run ${c.bold("selfguard setup")}.\n`);
    return 0;
  }
  const badge = (w: api.ProjectSummary["worstSeverity"], error: string | null) =>
    w ? severityLabel(w, c) : error ? c.yellow("!") : c.green("✓");

  if (values.flat) {
    for (const p of status.projects) {
      const counts = Object.entries(p.bySeverity).map(([s, n]) => `${n} ${s}`).join(", ");
      const detail = p.advisories
        ? `${p.vulnerablePackages} vulnerable pkg(s) ${c.dim(`(${counts})`)}`
        : p.error
          ? c.dim(clean(p.error, 80))
          : c.dim(`${p.packages} packages, clean`);
      out.write(`${badge(p.worstSeverity, p.error)} ${c.bold(`${p.machine ? `${p.machine}:` : ""}${tildify(p.path)}`)}${p.exists ? "" : c.dim(" (missing)")}  ${detail}\n`);
    }
    return 0;
  }

  const showAll = values.all ?? false;
  let hiddenRepos = 0;
  let hiddenDismissed = 0;
  for (const g0 of status.repos) {
    if (!g0.active && !showAll) {
      if (g0.dismissedAt) hiddenDismissed++;
      else hiddenRepos++;
      continue;
    }
    const visible = showAll ? g0.checkouts : g0.checkouts.filter((k) => k.active);
    const hiddenCheckouts = g0.checkouts.length - visible.length;
    const g = { ...g0, checkouts: visible };
    const many = g.checkouts.length > 1;
    const firstError = g.checkouts.find((k) => k.error)?.error ?? null;
    // Headline: the main checkout; mention a branch that is worse than it.
    const main = g.checkouts.find((k) => !k.worktree) ?? g.checkouts[0]!;
    const worse = g.checkouts
      .filter((k) => k !== main && k.vulnerablePackages > main.vulnerablePackages)
      .sort((a, b) => b.vulnerablePackages - a.vulnerablePackages)[0];
    const mainText = main.vulnerablePackages
      ? `${main.vulnerablePackages} vulnerable pkg(s)${many && main.branch ? ` on ${clean(main.branch, 40)}` : ""}`
      : main.error && !many
        ? c.dim(clean(main.error, 80))
        : many && main.branch
          ? c.dim(`clean on ${clean(main.branch, 40)}`)
          : c.dim("clean");
    const head = worse ? `${mainText} ${c.yellow(`· ${worse.vulnerablePackages} on ${clean(worse.branch ?? "another checkout", 40)}`)}` : mainText;
    const where = many ? c.dim(`${g.checkouts.length} checkouts`) : c.dim(tildify(g.checkouts[0]!.path));
    const more = (hiddenCheckouts ? c.dim(` +${hiddenCheckouts} inactive`) : "") + (g.dismissedAt ? c.dim(` dismissed ${ago(g.dismissedAt)}`) : "");
    const dimIf = (s: string) => (g.active ? s : c.dim(s));
    out.write(`${badge(g.worstSeverity, firstError)} ${g.machine ? c.dim(`${g.machine} · `) : ""}${c.bold(dimIf(clean(g.label, 80)))}  ${head}  ${where}${more}\n`);
    if (!many) continue;
    g.checkouts.forEach((k, i) => {
      const branch = k.branch ? c.cyan(clean(k.branch, 50)) : c.dim("(no branch)");
      const kind = (k.worktree ? c.dim(" worktree") : "") + (k.active ? "" : c.dim(` inactive${k.lastActivity ? ` ${ago(k.lastActivity)}` : ""}`));
      const detail = k.advisories ? `${k.vulnerablePackages} vulnerable` : k.error ? c.dim(clean(k.error, 60)) : c.dim("clean");
      const tree = i === g.checkouts.length - 1 ? "└" : "├";
      out.write(`   ${c.dim(tree)} ${branch}${kind}  ${detail}  ${c.dim(tildify(k.path))}${k.exists ? "" : c.dim(" (missing)")}\n`);
    });
  }
  if (hiddenRepos) out.write(c.dim(`${hiddenRepos} inactive repo(s) hidden (no git activity in ${api.getSettings().activeDays} days). Show them with --all.\n`));
  if (hiddenDismissed) out.write(c.dim(`${hiddenDismissed} dismissed repo(s) hidden until their next git activity. List them with selfguard dismiss --list.\n`));
  const upd = cachedUpdate();
  if (upd.available) out.write(c.yellow(`selfguard ${upd.latest} is available (you have ${upd.current}): ${upd.command ?? "selfguard menu → Check for Updates…"}\n`));
  return 0;
}

export function cmdWhere(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { ...JSON_OPT, ecosystem: { type: "string" } } });
  const name = positionals[0];
  if (!name) usage("usage: selfguard where <package> [--ecosystem npm|PyPI|crates.io|Go|GitHub Actions]");
  const eco = values.ecosystem === undefined ? undefined : parseEcosystem(values.ecosystem);
  if (eco === null) usage(`unknown ecosystem: ${values.ecosystem} (npm, PyPI, crates.io, Go or "GitHub Actions")`);
  const r = api.whereUsed(name, eco);
  if (values.json) {
    emit(r);
    return 0;
  }
  const c = paint(out);
  if (r.usedIn.length === 0) out.write(`${clean(name)} is not used in any tracked project.\n`);
  for (const p of r.usedIn) {
    const list = p.versions
      .map(
        (v) =>
          `${v.vulnerable ? c.red(clean(v.version)) : clean(v.version)}${v.ecosystem === "npm" ? "" : c.dim(` [${v.ecosystem}]`)}${v.direct ? "" : c.dim(" (transitive)")}`,
      )
      .join(", ");
    const from = p.source === "ci" ? c.dim(" (CI workflows)") : p.source === "agents" ? c.dim(" (agent configs)") : "";
    out.write(`${c.bold(tildify(p.path))}${from}  ${list}\n`);
  }
  return 0;
}

export async function cmdVuln(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  const id = positionals[0];
  if (!id) usage("usage: selfguard vuln <advisory-id>");
  const v = await api.getVulnerability(id);
  if (values.json) {
    emit(v);
    return 0;
  }
  const c = paint(out);
  out.write(`${severityLabel(v.severity, c)} ${c.bold(v.id)}${v.aliases.length ? c.dim(` (${v.aliases.join(", ")})`) : ""}\n`);
  if (v.summary) out.write(`${v.summary}\n`);
  for (const a of v.affected) {
    const ranges = a.ranges.map((e) => Object.entries(e).map(([k, x]) => `${k} ${clean(x)}`).join("")).join(", ");
    const versions = a.versions.length ? ` versions ${a.versions.slice(0, 10).join(", ")}` : "";
    out.write(c.dim(`  ${a.package}: ${ranges}${versions}\n`));
  }
  out.write(
    v.affectsYourProjects.length
      ? c.red(`Affects ${v.affectsYourProjects.length} place(s) in your projects:\n`)
      : c.green("None of your tracked projects are affected.\n"),
  );
  for (const p of v.affectsYourProjects) {
    out.write(`  ${tildify(p.path)}  ${clean(p.package)}@${clean(p.version)}${p.fixedIn ? c.green(` → ${clean(p.fixedIn)}`) : ""}\n`);
  }
  out.write(c.dim(`${v.url}\n`));
  return 0;
}
