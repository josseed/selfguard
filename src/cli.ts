#!/usr/bin/env node
import { parseArgs } from "node:util";
import { buildAlert, deliver } from "./alerts.ts";
import * as api from "./api.ts";
import { GUIDE } from "./guide.ts";
import { hookEnter, ZSH_HOOK } from "./hook.ts";
import { findProject } from "./lockfile/detect.ts";
import { runMcpServer } from "./mcp.ts";
import { paint, renderFindings, severityLabel, tildify, worstSeverity } from "./report.ts";
import { clean } from "./sanitize.ts";
import type { ScanOutcome } from "./scan.ts";
import { parseInterval, scheduleOff, scheduleOn, scheduleStatus } from "./schedule.ts";
import { runSetup } from "./setup.ts";
import { findingKey, loadRepo, type Finding } from "./store.ts";
import { isInteractive } from "./tui.ts";
import { VERSION } from "./version.ts";

const HELP = `selfguard ${VERSION} — keeps an eye on the dependencies of every repo you work on

Setup:
  selfguard setup                    interactive: choose the folders where your repos live
  selfguard init zsh                 print the shell hook (eval "$(selfguard init zsh)" in ~/.zshrc)
  selfguard schedule on [--every 6h] | off | status
                                     periodic sync with macOS notifications (launchd)

Projects:
  selfguard status [--vulnerable]    every tracked project, riskiest first
  selfguard scan [dir] [-v]          scan a project now (exit 1 if vulnerable) and track it
  selfguard report [dir] [-v]        last scan results, no network
  selfguard sync                     find new repos in your folders + re-check everything
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

function notifyNew(outcomes: ScanOutcome[]): Promise<void> {
  return deliver(buildAlert(outcomes.map((o) => ({ path: o.record.path, newFindings: o.newFindings }))));
}

/** Detached scan started by the shell hook: log + notify, never print to a terminal. */
async function backgroundScan(path: string): Promise<number> {
  const stamp = new Date().toISOString();
  try {
    const project = findProject(path);
    const before = new Set((project ? loadRepo(project.root)?.findings ?? [] : []).map(findingKey));
    const r = await api.scanPath(path);
    const rec = loadRepo(r.project.path)!;
    await notifyNew([{ record: rec, newFindings: rec.findings.filter((f) => !before.has(findingKey(f))), firstScan: r.firstScan }]);
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
    options: { ...JSON_OPT, verbose: { type: "boolean", short: "v" } },
  });
  const report = api.getReport(positionals[0] ?? ".");
  if (values.json) emit(report);
  else out.write(`${renderFindings(loadRepo(report.path)!, out, values.verbose ?? false)}\n`);
  return report.advisories > 0 ? 1 : 0;
}

function cmdStatus(args: string[]): number {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, vulnerable: { type: "boolean" } } });
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
  for (const p of status.projects) {
    const badge = p.worstSeverity ? severityLabel(p.worstSeverity, c) : p.error ? c.yellow("!") : c.green("✓");
    const counts = Object.entries(p.bySeverity).map(([s, n]) => `${n} ${s}`).join(", ");
    const detail = p.advisories
      ? `${p.vulnerablePackages} vulnerable pkg(s) ${c.dim(`(${counts})`)}`
      : p.error
        ? c.dim(clean(p.error, 80))
        : c.dim(`${p.packages} packages, clean`);
    out.write(`${badge} ${c.bold(tildify(p.path))}${p.exists ? "" : c.dim(" (missing)")}  ${detail}\n`);
  }
  return 0;
}

async function cmdSync(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, background: { type: "boolean" } } });
  let r: api.SyncResult;
  try {
    r = await api.sync();
  } catch (e) {
    if (values.background && e instanceof api.ApiError && e.code === "busy") return 0;
    throw e;
  }
  await notifyNew(r.outcomes);
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
    out.write(`Synced ${data.projects} project(s). ${total ? c.red(`${total} newly vulnerable package(s).`) : c.green("Nothing new.")}\n`);
    for (const p of data.news) {
      const pkgs = p.packages.map((g) => `${clean(g.name)}@${clean(g.version)} ${c.dim(`(${g.advisories.length})`)}`);
      out.write(`  ${c.bold(tildify(p.path))}: ${pkgs.join(", ")}\n`);
    }
    for (const e of data.errors) out.write(c.dim(`  ! ${tildify(e.path)}: ${clean(e.error)}\n`));
  }
  return 0;
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
      const plist = scheduleOn(seconds);
      if (values.json) emit({ enabled: true, intervalSeconds: seconds, plist, node: process.execPath });
      else {
        out.write(`Background sync every ${values.every}. (${tildify(plist)})\n`);
        out.write(`Note: it runs with ${process.execPath}; re-run this if you change Node versions.\n`);
      }
      return 0;
    }
    case "off": {
      const was = scheduleOff();
      if (values.json) emit({ enabled: false, wasEnabled: was });
      else out.write(was ? "Background sync disabled.\n" : "Background sync was not enabled.\n");
      return 0;
    }
    case "status":
    case undefined: {
      const s = scheduleStatus();
      if (values.json) emit(s);
      else out.write(s.loaded ? `enabled (${tildify(s.plist)})\n` : s.installed ? "installed but not loaded\n" : "disabled\n");
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
