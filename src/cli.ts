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
import { parseInterval, scheduleOff, scheduleOn, scheduleStatus, updateDiscoverAgent, updateRemoteAgent, updateWatcher } from "./schedule.ts";
import { runSetup } from "./setup.ts";
import { loadRepo } from "./store.ts";
import { confirm, isInteractive, withSpinner } from "./tui.ts";
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
  selfguard settings [--remind daily|weekly|off] [--active-days N] [--auto-discover on|off]
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
  selfguard discover --everywhere [--dry-run] [--yes]
                                     find projects anywhere in your home folder, grouped
                                     into places to watch (skips caches, dependencies,
                                     cloud drives, copies); weekly in the background
  selfguard forget [dir] [--keep-discoverable]
                                     stop tracking (and exclude) a project or folder
  selfguard unexclude <dir>          allow an excluded path to be discovered again
  selfguard dismiss [dir|key]        turn a repo off (all its checkouts): no reminders, alerts
                                     only for malicious packages. It turns back on by itself
                                     with the next git activity (commit, checkout, pull...)
  selfguard dismiss --list           repos turned off
  selfguard undismiss [dir|key]      turn a dismissed repo back on now

Other machines (dev servers over SSH; read-only, project code never runs there):
  selfguard machines                 list machines and their last sync
  selfguard machines peers           machines on your tailnet (Tailscale)
  selfguard machines add <host> [--name N] [--root DIR]... [--depth N] [--scope DIR]
                                     [--port N] [--manual] [--mode restricted|ssh]
                                     restricted (default): a dedicated key that the machine
                                     accepts only for a read-only reader limited to --scope
                                     (default ~), installed once with your SSH access
  selfguard machines setup <name>    print the reader and key line to install by hand
  selfguard machines install <name> | verify <name>
  selfguard machines roots <name> add <dir> [--depth N] | remove <dir>
  selfguard machines sync [name]     new projects + changed lockfiles now
  selfguard machines remove <name> [--keep-remote]
                                     forget a machine, its results and key (and remove the
                                     key line from it with your SSH access)

AI / automation:
  --json                             any command: one JSON document on stdout
  selfguard mcp                      MCP server over stdio (claude mcp add selfguard -- selfguard mcp)
  selfguard guide                    usage guide for AI agents

Data: OSV.dev (GitHub advisories, CVEs, malicious packages). Only package names and versions
leave your machine. Nothing in your projects is executed. State: ~/.selfguard (SELFGUARD_HOME).
Exit codes: 0 ok, 1 vulnerabilities found (scan/report), 2 error.`;

const out = process.stdout;
// `selfguard status | head`: the reader went away; stop quietly instead of crashing.
out.on("error", (e: NodeJS.ErrnoException) => {
  if (e.code === "EPIPE") process.exit(process.exitCode ?? 0);
  throw e;
});
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
      out.write(`  ${c.bold(`${p.machine ? `${p.machine}:` : ""}${tildify(p.path)}`)}: ${pkgs.join(", ")}\n`);
    }
    for (const e of data.errors) out.write(c.dim(`  ! ${e.machine ? `${e.machine}:` : ""}${tildify(e.path)}: ${clean(e.error)}\n`));
    for (const m of data.machines) {
      out.write(m.ok ? c.dim(`  ${m.name}: ${m.projects} project(s)\n`) : c.yellow(`  ! ${m.name}: ${clean(m.error ?? "")}\n`));
    }
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
  const { values } = parseArgs({ args, options: { ...JSON_OPT, remind: { type: "string" }, "active-days": { type: "string" }, "auto-discover": { type: "string" } } });
  const patch: { remind?: unknown; activeDays?: unknown; autoDiscover?: unknown } = {};
  if (values.remind !== undefined) patch.remind = values.remind;
  if (values["active-days"] !== undefined) patch.activeDays = Number(values["active-days"]);
  if (values["auto-discover"] !== undefined) {
    if (values["auto-discover"] !== "on" && values["auto-discover"] !== "off") usage("--auto-discover must be on or off");
    patch.autoDiscover = values["auto-discover"] === "on";
  }
  const s = Object.keys(patch).length ? api.updateSettings(patch) : api.getSettings();
  if (patch.autoDiscover !== undefined) {
    try {
      updateDiscoverAgent(s.autoDiscover);
    } catch {
      /* the agent follows the setting next time the schedule is turned on */
    }
  }
  if (values.json) emit(s);
  else {
    out.write(`remind        ${s.remind}${s.lastReminder ? paint(out).dim(`  (last ${s.lastReminder})`) : ""}\n`);
    out.write(`active-days   ${s.activeDays}\n`);
    out.write(`auto-discover ${s.autoDiscover ? "on" : "off"}${s.lastEverywhere ? paint(out).dim(`  (last search ${s.lastEverywhere})`) : ""}\n`);
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

function printPlaces(scan: api.EverywhereScan): void {
  const c = paint(out);
  const secs = Math.round(scan.ms / 1000);
  out.write(`Searched ${scan.visited.toLocaleString("en-US")} folders in ${secs}s: ${scan.projects} project(s) in ${scan.places.length} place(s).\n`);
  for (const p of scan.places) {
    const box = p.watched ? c.dim("[✓]") : p.recommended ? c.green("[x]") : "[ ]";
    const bits = [`${p.projects} project(s)`, `${p.active} active`];
    if (p.secondary) bits.push(`${p.secondary} samples/copies`);
    if (p.noGit) bits.push(`${p.noGit} without git`);
    const state = p.watched ? c.dim("  already watched") : "";
    out.write(`${box} ${c.bold(tildify(p.path))} ${c.dim(`depth ${p.depth}`)}  ${c.dim(bits.join(", "))}${state}\n`);
  }
  if (scan.skipped.length) out.write(c.dim(`Skipped (macOS privacy, no watched folder there yet): ${scan.skipped.map(tildify).join(", ")}\n`));
  if (scan.denied.length) out.write(c.dim(`Not allowed to read: ${scan.denied.slice(0, 5).map(tildify).join(", ")}${scan.denied.length > 5 ? "…" : ""}\n`));
  if (scan.heavy.length) out.write(c.dim(`Cut short (many folders, no project): ${scan.heavy.map(tildify).join(", ")}\n`));
}

async function cmdDiscoverEverywhere(values: { json?: boolean; "dry-run"?: boolean; background?: boolean; yes?: boolean }): Promise<number> {
  const c = paint(out);
  if (values.background) {
    let r: api.AutoDiscoverResult;
    try {
      r = await api.autoDiscover();
    } catch (e) {
      if (e instanceof api.ApiError && e.code === "busy") return 0;
      throw e;
    }
    if (r.ran) out.write(`${new Date().toISOString()} discover --everywhere: ${r.scan?.projects ?? 0} project(s), ${r.added.length} new place(s)${r.added.length ? `: ${r.added.map((a) => a.path).join(", ")}` : ""}\n`);
    return 0;
  }
  const scan = await (out.isTTY && !values.json
    ? withSpinner("Searching your home folder (this can take a minute)…", () => api.findEverywhere())
    : api.findEverywhere());
  const chosen = scan.places.filter((p) => p.recommended);
  if (values.json && (values["dry-run"] || !values.yes)) {
    emit(scan);
    return 0;
  }
  if (!values.json) printPlaces(scan);
  if (values["dry-run"] || chosen.length === 0) {
    if (!values.json && chosen.length === 0) out.write("Nothing new to watch.\n");
    return 0;
  }
  if (!values.yes) {
    if (!isInteractive()) {
      out.write(`Run again with --yes to watch the ${chosen.length} checked place(s), or use selfguard roots add.\n`);
      return 0;
    }
    if (!(await confirm(`Watch the ${chosen.length} checked place(s)?`))) return 0;
  }
  const r = await api.applyPlaces(chosen.map((p) => ({ path: p.path, depth: p.depth })));
  if (values.json) emit({ scan, applied: r });
  else out.write(`${c.green("✓")} Watching ${r.watching.length} more folder(s); ${r.discovered?.registered ?? 0} new project(s) registered, ${r.discovered?.withVulnerabilities ?? 0} with vulnerabilities.\n`);
  return 0;
}

async function cmdDiscover(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: { ...JSON_OPT, "dry-run": { type: "boolean" }, everywhere: { type: "boolean" }, background: { type: "boolean" }, yes: { type: "boolean", short: "y" } },
  });
  if (values.everywhere) return cmdDiscoverEverywhere(values);
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

function refreshRemoteAgent(): void {
  try {
    updateRemoteAgent(api.hasMachines());
  } catch (e) {
    err.write(`selfguard: could not update the background agent: ${clean((e as Error).message, 200)}\n`);
  }
}

function printMachines(list: api.MachineInfo[]): void {
  const c = paint(out);
  if (list.length === 0) {
    out.write(`No other machines yet. Add one with ${c.bold("selfguard machines add <host>")} (see ${c.bold("selfguard machines peers")}).\n`);
    return;
  }
  for (const m of list) {
    const st = m.status;
    const state = st.error ? c.yellow(`! ${clean(st.error, 120)}`) : st.lastSync ? c.green(`synced ${clean(st.lastSync.slice(0, 16).replace("T", " "))} UTC`) : c.dim("never synced");
    const how = m.mode === "restricted" ? `restricted to ${clean(m.scope)}` : "your SSH access";
    out.write(`${c.bold(m.name)} ${c.dim(`ssh ${m.host}${m.port ? `:${m.port}` : ""}${st.os ? ` · ${clean(st.os)}` : ""} · ${how}`)}  ${m.trackedProjects} project(s)  ${state}\n`);
    for (const r of m.roots) out.write(`  ${clean(r.path)} ${c.dim(`(depth ${r.depth})`)}\n`);
    if (m.roots.length === 0) out.write(c.dim(`  no folders yet: selfguard machines roots ${m.name} add ~/code\n`));
  }
}

async function cmdMachines(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      ...JSON_OPT,
      name: { type: "string" },
      root: { type: "string", multiple: true },
      depth: { type: "string" },
      scope: { type: "string" },
      port: { type: "string" },
      mode: { type: "string" },
      manual: { type: "boolean" },
      "keep-remote": { type: "boolean" },
      background: { type: "boolean" },
    },
  });
  const [action, a1, a2, a3] = positionals;
  const depth = values.depth === undefined ? undefined : Number(values.depth);
  if (depth !== undefined && !Number.isInteger(depth)) usage("--depth must be an integer");
  const c = paint(out);
  switch (action) {
    case undefined:
    case "list": {
      const list = api.listMachines();
      if (values.json) emit({ machines: list });
      else printMachines(list);
      return 0;
    }
    case "peers": {
      const peers = api.tailnetPeers();
      if (values.json) emit({ peers });
      else if (peers.length === 0) out.write("No Tailscale peers found (is Tailscale installed and running?).\n");
      else for (const p of peers) out.write(`${p.online ? c.green("●") : c.dim("○")} ${c.bold(p.name)} ${c.dim(`${p.dnsName} ${p.os}`)}\n`);
      return 0;
    }
    case "test": {
      if (!a1) usage("usage: selfguard machines test <host>");
      const r = await api.testMachine(a1);
      if (values.json) emit(r);
      else out.write(`${c.green("✓")} ${clean(a1)} answers: ${clean(r.os)}, home ${clean(r.home)}\n`);
      return 0;
    }
    case "add": {
      if (!a1) usage("usage: selfguard machines add <host> [--name N] [--root DIR]... [--depth N] [--scope DIR] [--port N] [--manual] [--mode restricted|ssh]");
      const name = values.name ?? api.suggestName(a1);
      const port = values.port === undefined ? undefined : Number(values.port);
      if (port !== undefined && !Number.isInteger(port)) usage("--port must be an integer");
      if (values.mode !== undefined && values.mode !== "restricted" && values.mode !== "ssh") usage("--mode must be restricted or ssh");
      const r = await api.addMachine(name, a1, {
        mode: values.mode as "restricted" | "ssh" | undefined,
        port,
        scope: values.scope,
        roots: (values.root ?? []).map((path) => ({ path, depth })),
        install: !values.manual,
      });
      refreshRemoteAgent();
      if (values.json) {
        emit(r);
        return r.installed ? 0 : 2;
      }
      const m = r.machine;
      if (r.installed) {
        const how = m.mode === "restricted" ? `restricted key, reader limited to ${clean(m.scope)}` : "your SSH access";
        out.write(`${c.green("✓")} Added ${c.bold(m.name)} (${clean(m.status.os ?? "")}, ${how}).\n`);
        if (r.setup?.pinnedTo.length) out.write(c.dim(`  The key only works from this Mac's tailnet address (${r.setup.pinnedTo.join(", ")}).\n`));
        if (m.roots.length === 0) out.write(`Now choose its folders: ${c.bold(`selfguard machines roots ${m.name} add ~/code`)}\n`);
        else out.write(`Run ${c.bold(`selfguard machines sync ${m.name}`)} to scan it now.\n`);
        return 0;
      }
      out.write(`${c.yellow("!")} Saved ${c.bold(m.name)}, but the reader isn't installed yet.\n`);
      if (r.installError) out.write(c.dim(`  ${clean(r.installError, 300)}\n`));
      out.write(`Install it by hand: ${c.bold(`selfguard machines setup ${m.name}`)} shows what to paste on the machine; then ${c.bold(`selfguard machines verify ${m.name}`)}.\n`);
      return 2;
    }
    case "setup": {
      if (!a1) usage("usage: selfguard machines setup <name>");
      const st = api.machineSetup(a1);
      if (values.json) emit(st);
      else {
        out.write(`${c.bold(`# Install the selfguard reader on ${st.host}`)}\n`);
        out.write(c.dim(`# Paste this in a terminal on that machine (as the user selfguard connects as). It writes\n# ~/.selfguard-reader/reader.sh and adds one line to ~/.ssh/authorized_keys:\n#   ${st.authorizedKeysLine}\n# Then run: selfguard machines verify ${st.name}\n\n`));
        out.write(`sh -s <<'SELFGUARD_INSTALL'\n${st.installScript}SELFGUARD_INSTALL\n`);
      }
      return 0;
    }
    case "install":
    case "verify": {
      if (!a1) usage(`usage: selfguard machines ${action} <name>`);
      const m = action === "install" ? await api.installMachine(a1) : await api.verifyMachine(a1);
      if (values.json) emit(m);
      else out.write(`${c.green("✓")} ${c.bold(m.name)} answers${m.mode === "restricted" ? " through the restricted reader" : ""} (${clean(m.status.os ?? "")}).\n`);
      return 0;
    }
    case "remove": {
      if (!a1) usage("usage: selfguard machines remove <name> [--keep-remote]");
      const r = await api.removeMachine(a1, { revoke: !values["keep-remote"] });
      refreshRemoteAgent();
      if (values.json) emit(r);
      else if (!r.removed) out.write(`No machine named ${clean(a1)}.\n`);
      else {
        out.write(`Removed ${clean(a1)}, its results and its key.\n`);
        if (r.revoked) out.write(c.dim("  Key line and reader removed from the machine.\n"));
        else if (r.revoked === false) out.write(c.dim(`  Couldn't clean up the machine (${clean(r.revokeError ?? "", 200)}). The key line there is useless now; remove the "selfguard:" line from ~/.ssh/authorized_keys when you can.\n`));
      }
      return 0;
    }
    case "roots": {
      if (!a1 || (a2 !== "add" && a2 !== "remove") || !a3) usage("usage: selfguard machines roots <name> add <dir> [--depth N] | remove <dir>");
      const m = a2 === "add" ? api.addMachineRoot(a1, a3, depth) : api.removeMachineRoot(a1, a3);
      if (values.json) emit(m);
      else for (const r of m.roots) out.write(`${clean(r.path)} ${c.dim(`(depth ${r.depth})`)}\n`);
      return 0;
    }
    case "sync":
    case "check": {
      let r: api.MachinesCheckResult;
      try {
        r = await api.checkMachines({ notify: true, only: a1 ? [a1] : undefined });
      } catch (e) {
        if (values.background && e instanceof api.ApiError && e.code === "busy") return 0;
        throw e;
      }
      if (values.background) {
        const bad = r.machines.filter((m) => !m.ok);
        out.write(`${new Date().toISOString()} machines: ${r.machines.map((m) => `${m.name} ${m.ok ? `${m.rescanned} re-scanned` : "unreachable"}`).join(", ")}\n`);
        for (const m of bad) out.write(`  ${m.name}: ${clean(m.error ?? "")}\n`);
        await maybeRemind(api.getAttention);
      } else if (values.json) emit(r);
      else {
        for (const m of r.machines) {
          out.write(m.ok
            ? `${c.green("✓")} ${c.bold(m.name)}: ${m.projects} project(s), ${m.discovered} new, ${m.rescanned} re-scanned\n`
            : `${c.yellow("!")} ${c.bold(m.name)}: ${clean(m.error ?? "")}\n`);
        }
        for (const p of r.news) {
          const pkgs = p.packages.map((g) => `${clean(g.name)}@${clean(g.version)}`);
          out.write(`  ${c.bold(`${p.machine}:${tildify(p.path)}`)}: ${c.red(pkgs.join(", "))}\n`);
        }
        if (r.machines.length === 0) printMachines([]);
      }
      return r.machines.some((m) => !m.ok) && !values.background ? 2 : 0;
    }
    default:
      usage("usage: selfguard machines [list | peers | test <host> | add <host> | setup|install|verify <name> | roots <name> add|remove <dir> | sync [name] | remove <name>]");
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

function cmdDismiss(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { ...JSON_OPT, list: { type: "boolean" } } });
  const c = paint(out);
  if (values.list) {
    const list = api.listDismissed();
    if (values.json) emit({ dismissed: list });
    else if (!list.length) out.write("No dismissed repos.\n");
    else for (const d of list) out.write(`${c.bold(clean(d.label, 80))}  ${c.dim(`dismissed ${ago(d.dismissedAt)} · ${clean(d.key, 120)}`)}\n`);
    return 0;
  }
  const r = api.dismissRepo(api.resolveRepoKey(positionals[0] ?? "."));
  if (values.json) emit(r);
  else out.write(`Dismissed ${clean(r.label, 80)}. It turns back on with its next git activity (or: selfguard undismiss).\n`);
  return 0;
}

function cmdUndismiss(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  const r = api.undismissRepo(api.resolveRepoKey(positionals[0] ?? "."));
  if (values.json) emit(r);
  else out.write(r.removed ? "Turned back on.\n" : "That repo was not dismissed.\n");
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
      const plist = scheduleOn(seconds, targets, { machines: api.hasMachines(), autoDiscover: api.getSettings().autoDiscover });
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
        if (s.loaded) out.write(s.discover.loaded ? "find my projects: weekly search of your home folder\n" : "find my projects: off (selfguard settings --auto-discover on)\n");
        if (s.loaded && api.hasMachines()) out.write(s.remote.loaded ? "other machines: checked every 15 minutes\n" : "other machines: not scheduled (run selfguard schedule on)\n");
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
    case "machines":
      return cmdMachines(rest);
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
    case "dismiss":
      return cmdDismiss(rest);
    case "undismiss":
      return cmdUndismiss(rest);
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
