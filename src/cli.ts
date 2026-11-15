#!/usr/bin/env node
import { parseArgs } from "node:util";
import { buildReminder, needsAttention } from "./alerts.ts";
import { maybeRemind } from "./announce.ts";
import * as api from "./api.ts";
import { appStatus, installApp, uninstallApp } from "./app.ts";
import { GUIDE } from "./guide.ts";
import { hookEnter, ZSH_HOOK } from "./hook.ts";
import { findProject } from "./lockfile/detect.ts";
import { runMcpServer } from "./mcp.ts";
import { groupByPackage, paint, renderFindings, severityLabel, tildify } from "./report.ts";
import { clean } from "./sanitize.ts";
import { parseInterval, scheduleOff, scheduleOn, scheduleStatus, updateWatcher } from "./schedule.ts";
import { runSetup } from "./setup.ts";
import { loadRepo } from "./store.ts";
import { isInteractive } from "./tui.ts";
import { runUi } from "./ui/server.ts";
import { VERSION } from "./version.ts";

const HELP = `selfguard ${VERSION} — keeps an eye on the dependencies of every repo you work on

Setup:
  selfguard setup                    interactive: choose the folders where your repos live
  selfguard init zsh                 print the shell hook (eval "$(selfguard init zsh)" in ~/.zshrc)
  selfguard schedule on [--every 6h] | off | status
                                     background watching with macOS notifications (launchd):
                                     lockfile changes right away, full sync every 6h

Dashboard and alerts:
  selfguard ui [--no-open] [--port N]
                                     local dashboard in your browser (127.0.0.1 only)
  selfguard app install | uninstall | status
                                     macOS: ~/Applications/selfguard.app opens the dashboard
                                     (Spotlight, Launchpad, Dock)
  selfguard remind                   send the reminder of serious open issues now
  selfguard settings [--remind daily|weekly|off] [--active-days N]
                                     reminder frequency; days of git inactivity before a
                                     checkout stops alerting (default 30)

Projects:
  selfguard status [--vulnerable] [--flat] [--all]
                                     tracked repos, riskiest first (worktrees/clones grouped;
                                     inactive checkouts hidden unless --all)
  selfguard scan [dir] [-v]          scan a project now (exit 1 if vulnerable) and track it
  selfguard report [dir] [-v] [-m]   last scan results, no network (-m: markdown)
  selfguard sync                     find new repos in your folders + re-check everything
  selfguard check                    re-scan only projects whose lockfile changed
  selfguard where <package>          which projects use <package>, which versions
  selfguard vuln <id>                details of an advisory and which projects it affects

Folders:
  selfguard roots                    list watched folders and exclusions
  selfguard roots add <dir> [--depth N] | remove <dir>
  selfguard discover [--dry-run]     register new projects found in your folders
  selfguard forget [dir] [--keep-discoverable]
                                     stop tracking (and exclude) a project or folder
  selfguard unexclude <dir>          allow an excluded path to be discovered again

AI / automation:
  --json                             any command: one JSON document on stdout
  selfguard mcp                      MCP server over stdio (claude mcp add selfguard -- selfguard mcp)
  selfguard guide                    usage guide for AI agents

Data: OSV.dev (GitHub advisories, CVEs, malicious packages). Only package names and versions
leave your machine. Nothing in your projects is executed. State: ~/.selfguard (SELFGUARD_HOME).
Exit codes: 0 ok, 1 vulnerabilities found (scan/report), 2 error.`;

const out = process.stdout;
const err = process.stderr;
const jsonMode = process.argv.includes("--json");
const JSON_OPT = { json: { type: "boolean" } } as const;

class UsageError extends Error {}

function emit(data: unknown): void {
  out.write(`${JSON.stringify(data, null, 2)}\n`);
}

function usage(message: string): never {
  throw new UsageError(message);
}

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

async function cmdScan(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { ...JSON_OPT, background: { type: "boolean" }, verbose: { type: "boolean", short: "v" } },
  });
  const path = positionals[0] ?? ".";
  if (values.background) return backgroundScan(path);
  const r = await api.scanPath(path);
  if (values.json) emit(r);
  else out.write(`${renderFindings(loadRepo(r.project.path)!, out, values.verbose ?? false)}\n`);
  return r.project.advisories > 0 ? 1 : 0;
}

function cmdReport(args: string[]): number {
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

function cmdStatus(args: string[]): number {
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
      out.write(`${badge(p.worstSeverity, p.error)} ${c.bold(tildify(p.path))}${p.exists ? "" : c.dim(" (missing)")}  ${detail}\n`);
    }
    return 0;
  }

  const showAll = values.all ?? false;
  let hiddenRepos = 0;
  for (const g0 of status.repos) {
    if (!g0.active && !showAll) {
      hiddenRepos++;
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
    const more = hiddenCheckouts ? c.dim(` +${hiddenCheckouts} inactive`) : "";
    const dimIf = (s: string) => (g.active ? s : c.dim(s));
    out.write(`${badge(g.worstSeverity, firstError)} ${c.bold(dimIf(clean(g.label, 80)))}  ${head}  ${where}${more}\n`);
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
  return 0;
}

function ago(iso: string): string {
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  return days < 1 ? "today" : days < 60 ? `${days}d ago` : `${Math.floor(days / 30)}mo ago`;
}

async function cmdSync(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, background: { type: "boolean" } } });
  let r: api.SyncResult;
  try {
    r = await api.sync({ notify: true });
  } catch (e) {
    if (values.background && e instanceof api.ApiError && e.code === "busy") return 0;
    throw e;
  }
  try {
    updateWatcher(api.watchTargets());
  } catch (e) {
    err.write(`selfguard: could not update the lockfile watcher: ${clean((e as Error).message, 200)}\n`);
  }
  if (values.background) await maybeRemind(api.getAttention);
  const { outcomes: _o, ...data } = r;
  const total = data.news.reduce((n, p) => n + p.packages.length, 0);
  if (values.json) emit(data);
  else if (values.background) {
    out.write(
      `${new Date().toISOString()} sync: ${data.projects} project(s), ${data.discovered.length} discovered, ${total} newly vulnerable package(s)\n`,
    );
  } else {
    const c = paint(out);
    if (data.discovered.length) out.write(`Discovered ${data.discovered.length} new project(s) in your folders.\n`);
    if (data.pruned.length) out.write(c.dim(`Stopped tracking ${data.pruned.length} folder(s) that no longer exist.\n`));
    out.write(`Synced ${data.projects} project(s). ${total ? c.red(`${total} newly vulnerable package(s).`) : c.green("Nothing new.")}\n`);
    for (const p of data.news) {
      const pkgs = p.packages.map((g) => `${clean(g.name)}@${clean(g.version)} ${c.dim(`(${g.advisories.length})`)}`);
      out.write(`  ${c.bold(tildify(p.path))}: ${pkgs.join(", ")}\n`);
    }
    for (const e of data.errors) out.write(c.dim(`  ! ${tildify(e.path)}: ${clean(e.error)}\n`));
  }
  return 0;
}

async function cmdCheck(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, background: { type: "boolean" } } });
  let r: api.CheckResult;
  try {
    r = await api.check({ notify: true });
  } catch (e) {
    if (values.background && e instanceof api.ApiError && e.code === "busy") return 0;
    throw e;
  }
  if (values.background) {
    if (r.rescanned.length) out.write(`${new Date().toISOString()} check: re-scanned ${r.rescanned.join(", ")}\n`);
    await maybeRemind(api.getAttention);
  } else if (values.json) emit(r);
  else out.write(r.rescanned.length ? `Re-scanned ${r.rescanned.length} project(s) with changed lockfiles.\n` : "No lockfile changed.\n");
  return 0;
}

async function cmdRemind(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, "dry-run": { type: "boolean" } } });
  const repos = api.getAttention();
  const alert = buildReminder(repos);
  const sent = values["dry-run"] ? false : await maybeRemind(repos, { force: true });
  const serious = repos
    .map((r) => ({ repo: r.label, packages: groupByPackage(r.findings.filter(needsAttention)) }))
    .filter((r) => r.packages.length > 0);
  if (values.json) {
    emit({
      sent,
      notification: alert.kind === "none" ? null : { title: alert.title, subtitle: alert.subtitle, body: alert.body },
      repos: serious.map((r) => ({
        repo: r.repo,
        packages: r.packages.map((g) => ({ name: g.name, version: g.version, worstSeverity: g.worst, upgradeTo: g.upgradeTo ?? null, direct: g.direct })),
      })),
    });
    return 0;
  }
  const c = paint(out);
  if (serious.length === 0) {
    out.write(`${c.green("✓")} Nothing serious open in your active repos (malicious packages, critical vulnerabilities, or high ones in direct dependencies).\n`);
    return 0;
  }
  for (const r of serious) {
    out.write(`${c.bold(clean(r.repo, 80))}\n`);
    for (const g of r.packages.slice(0, 6)) {
      const fix = g.worst === "malicious" ? c.red("remove it") : g.upgradeTo ? c.green(`→ ${clean(g.upgradeTo, 40)}`) : c.yellow("no fix yet");
      out.write(`  ${severityLabel(g.worst, c)} ${clean(g.name, 100)}@${clean(g.version, 40)} ${c.dim(g.direct ? "direct" : "transitive")} ${fix}\n`);
    }
    if (r.packages.length > 6) out.write(c.dim(`  …and ${r.packages.length - 6} more (selfguard ui)\n`));
  }
  out.write(c.dim(sent ? "\nNotification sent.\n" : "\n"));
  return 0;
}

function cmdSettings(args: string[]): number {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, remind: { type: "string" }, "active-days": { type: "string" } } });
  const patch: { remind?: unknown; activeDays?: unknown } = {};
  if (values.remind !== undefined) patch.remind = values.remind;
  if (values["active-days"] !== undefined) patch.activeDays = Number(values["active-days"]);
  const s = Object.keys(patch).length ? api.updateSettings(patch) : api.getSettings();
  if (values.json) emit(s);
  else {
    out.write(`remind        ${s.remind}${s.lastReminder ? paint(out).dim(`  (last ${s.lastReminder})`) : ""}\n`);
    out.write(`active-days   ${s.activeDays}\n`);
    if (s.lastSync) out.write(paint(out).dim(`last sync     ${s.lastSync}\n`));
  }
  return 0;
}

async function cmdUi(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: { "no-open": { type: "boolean" }, port: { type: "string" }, serve: { type: "boolean" } },
  });
  const port = values.port === undefined ? 0 : Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) usage("--port must be a port number");
  await runUi({ port, open: !values["no-open"], foreground: values.serve ?? false, log: (line) => out.write(`${line}\n`) });
  return 0;
}

function cmdApp(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  const c = paint(out);
  switch (positionals[0]) {
    case "install": {
      const s = installApp();
      if (values.json) emit(s);
      else {
        out.write(`${c.green("✓")} Installed ${tildify(s.path)}\n`);
        out.write(`Open the dashboard with ⌘+Space → "selfguard", or drag it to the Dock.\n`);
        out.write(c.dim(`It runs ${process.execPath}; re-run this if you change Node versions.\n`));
      }
      return 0;
    }
    case "uninstall": {
      const was = uninstallApp();
      if (values.json) emit({ installed: false, wasInstalled: was });
      else out.write(was ? "Removed selfguard.app.\n" : "selfguard.app was not installed.\n");
      return 0;
    }
    case "status":
    case undefined: {
      const s = appStatus();
      if (values.json) emit(s);
      else if (!s.installed) out.write("not installed (selfguard app install)\n");
      else out.write(`installed (${tildify(s.path)})${s.upToDate ? "" : c.yellow(" · outdated, run: selfguard app install")}\n`);
      return 0;
    }
    default:
      usage("usage: selfguard app install | uninstall | status");
  }
}

async function cmdDiscover(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, "dry-run": { type: "boolean" } } });
  const r = await api.discoverNew({ dryRun: values["dry-run"] ?? false });
  if (values.json) {
    emit(r);
    return 0;
  }
  const c = paint(out);
  if (r.found.length === 0) out.write("No new projects found.\n");
  for (const p of r.found) {
    const note = p.lockType ? c.dim(` (${p.lockType})`) : c.dim(" (no lockfile)");
    out.write(`  ${c.green("+")} ${tildify(p.path)}${note}\n`);
  }
  if (r.dryRun && r.found.length) out.write(`${r.found.length} new project(s) (dry run, nothing registered).\n`);
  else if (r.registered) out.write(`Registered ${r.registered} project(s); ${r.withVulnerabilities} with vulnerabilities. See: selfguard status\n`);
  return 0;
}

function printRoots(r: api.RootsResult): void {
  const c = paint(out);
  if (r.roots.length === 0) out.write("No folders configured. Run: selfguard setup\n");
  for (const root of r.roots) out.write(`${tildify(root.path)}  ${c.dim(`depth ${root.depth}`)}\n`);
  if (r.exclude.length) {
    out.write(c.dim("excluded:\n"));
    for (const e of r.exclude) out.write(c.dim(`  ${tildify(e)}\n`));
  }
}

function cmdRoots(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { ...JSON_OPT, depth: { type: "string" } } });
  const [action, target] = positionals;
  let r: api.RootsResult;
  if (action === "add") {
    if (!target) usage("usage: selfguard roots add <dir> [--depth N]");
    const depth = values.depth === undefined ? undefined : Number(values.depth);
    if (depth !== undefined && !Number.isInteger(depth)) usage("--depth must be an integer");
    r = api.addRoot(target, depth);
  } else if (action === "remove") {
    if (!target) usage("usage: selfguard roots remove <dir>");
    r = api.removeRoot(target);
  } else if (action === undefined || action === "list") {
    r = api.listRoots();
  } else {
    usage("usage: selfguard roots [add <dir> [--depth N] | remove <dir>]");
  }
  if (values.json) emit(r);
  else printRoots(r);
  return 0;
}

function cmdWhere(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  const name = positionals[0];
  if (!name) usage("usage: selfguard where <package>");
  const r = api.whereUsed(name);
  if (values.json) {
    emit(r);
    return 0;
  }
  const c = paint(out);
  if (r.usedIn.length === 0) out.write(`${clean(name)} is not used in any tracked project.\n`);
  for (const p of r.usedIn) {
    const list = p.versions
      .map((v) => `${v.vulnerable ? c.red(clean(v.version)) : clean(v.version)}${v.direct ? "" : c.dim(" (transitive)")}`)
      .join(", ");
    out.write(`${c.bold(tildify(p.path))}  ${list}\n`);
  }
  return 0;
}

async function cmdVuln(args: string[]): Promise<number> {
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

function cmdForget(args: string[]): number {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { ...JSON_OPT, "keep-discoverable": { type: "boolean" } },
  });
  const r = api.forget(positionals[0] ?? ".", { exclude: !values["keep-discoverable"] });
  if (values.json) emit(r);
  else {
    out.write(r.wasTracked ? `Stopped tracking ${tildify(r.path)}` : `${tildify(r.path)} was not tracked`);
    out.write(r.excluded ? " (excluded from discovery; undo with selfguard unexclude)\n" : "\n");
    if (r.alsoForgotten.length) out.write(`Also stopped tracking ${r.alsoForgotten.length} project(s) inside it.\n`);
  }
  return 0;
}

function cmdUnexclude(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  if (!positionals[0]) usage("usage: selfguard unexclude <dir>");
  const r = api.unexclude(positionals[0]);
  if (values.json) emit(r);
  else out.write(r.removed ? "Removed from exclusions.\n" : "That path was not excluded.\n");
  return 0;
}

function cmdSchedule(args: string[]): number {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { ...JSON_OPT, every: { type: "string", default: "6h" } },
  });
  switch (positionals[0]) {
    case "on": {
      const seconds = parseInterval(values.every ?? "6h");
      const targets = api.watchTargets();
      const plist = scheduleOn(seconds, targets);
      // Same Node-path concern as the agents: keep the launcher app in sync.
      if (appStatus().installed && !appStatus().upToDate) installApp();
      if (values.json) emit({ enabled: true, intervalSeconds: seconds, plist, node: process.execPath, watchedPaths: targets.length });
      else {
        out.write(`Background sync every ${values.every}, plus instant checks when a lockfile changes. (${tildify(plist)})\n`);
        out.write(`Note: it runs with ${process.execPath}; re-run this if you change Node versions.\n`);
      }
      return 0;
    }
    case "off": {
      const was = scheduleOff();
      if (values.json) emit({ enabled: false, wasEnabled: was });
      else out.write(was ? "Background sync and lockfile watcher disabled.\n" : "Background sync was not enabled.\n");
      return 0;
    }
    case "status":
    case undefined: {
      const s = scheduleStatus();
      if (values.json) emit(s);
      else {
        out.write(s.loaded ? `enabled (${tildify(s.plist)})\n` : s.installed ? "installed but not loaded\n" : "disabled\n");
        if (s.loaded) out.write(s.watcher.loaded ? `lockfile watcher: ${s.watcher.paths} path(s)\n` : "lockfile watcher: not running (run selfguard sync)\n");
      }
      return 0;
    }
    default:
      usage("usage: selfguard schedule on [--every 6h] | off | status");
  }
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case "setup":
      if (!isInteractive()) usage("setup needs an interactive terminal; use `selfguard roots add <dir>` instead");
      return runSetup();
    case "init":
      if (rest[0] !== "zsh") usage("only zsh is supported for now: selfguard init zsh");
      out.write(ZSH_HOOK);
      return 0;
    case "hook-enter": {
      const { values } = parseArgs({ args: rest, options: { dir: { type: "string" }, prompt: { type: "boolean" } }, strict: false });
      hookEnter(typeof values.dir === "string" ? values.dir : process.cwd(), values.prompt === true);
      return 0;
    }
    case "scan":
      return cmdScan(rest);
    case "report":
      return cmdReport(rest);
    case "status":
      return cmdStatus(rest);
    case "sync":
      return cmdSync(rest);
    case "check":
      return cmdCheck(rest);
    case "remind":
      return cmdRemind(rest);
    case "settings":
      return cmdSettings(rest);
    case "ui":
      return cmdUi(rest);
    case "app":
      return cmdApp(rest);
    case "discover":
      return cmdDiscover(rest);
    case "roots":
      return cmdRoots(rest);
    case "where":
      return cmdWhere(rest);
    case "vuln":
      return cmdVuln(rest);
    case "forget":
      return cmdForget(rest);
    case "unexclude":
      return cmdUnexclude(rest);
    case "schedule":
      return cmdSchedule(rest);
    case "mcp":
      await runMcpServer();
      return 0;
    case "guide":
      out.write(GUIDE);
      return 0;
    case "-v":
    case "--version":
    case "version":
      if (jsonMode) emit({ version: VERSION });
      else out.write(`${VERSION}\n`);
      return 0;
    case undefined:
    case "-h":
    case "--help":
    case "help":
      out.write(`${HELP}\n`);
      return 0;
    default:
      usage(`unknown command "${clean(cmd, 40)}". See selfguard --help`);
  }
}

function errorCode(e: unknown): string {
  if (e instanceof api.ApiError) return e.code;
  if (e instanceof UsageError) return "usage";
  const nodeCode = (e as { code?: unknown })?.code;
  if (typeof nodeCode === "string" && nodeCode.startsWith("ERR_PARSE_ARGS")) return "usage";
  return "error";
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    const message = clean(e instanceof Error ? e.message : String(e), 500);
    if (jsonMode) emit({ error: { code: errorCode(e), message } });
    else err.write(`selfguard: ${message}\n`);
    process.exitCode = 2;
  },
);
