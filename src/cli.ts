#!/usr/bin/env node
import { parseArgs } from "node:util";
import * as api from "./api.ts";
import { GUIDE } from "./guide.ts";
import { hookEnter, ZSH_HOOK } from "./hook.ts";
import { runMcpServer } from "./mcp.ts";
import { clean } from "./sanitize.ts";
import { runSetup } from "./setup.ts";
import { isInteractive } from "./tui.ts";
import { VERSION } from "./version.ts";
import { cmdDiscover, cmdDismiss, cmdForget, cmdRoots, cmdUndismiss, cmdUnexclude } from "./cli/folders.ts";
import { cmdMachines } from "./cli/machines.ts";
import { emit, err, jsonMode, out, usage, UsageError } from "./cli/output.ts";
import { cmdReport, cmdScan, cmdStatus, cmdVuln, cmdWhere } from "./cli/projects.ts";
import { cmdApp, cmdSchedule, cmdSettings, cmdUi } from "./cli/settings.ts";
import { cmdShare } from "./cli/share.ts";
import { cmdCheck, cmdRemind, cmdSync, cmdUpdate } from "./cli/sync.ts";
import { cmdTools } from "./cli/tools.ts";

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
                     [--update-check on|off]
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
                                     (--ecosystem npm|PyPI|crates.io|Go to narrow it)
  selfguard vuln <id>                details of an advisory and which projects it affects
  selfguard tools [dir] [-v]         agent tools (MCP servers) on this machine, and each repo's
                                     CI workflows and agent configs: advisories and warnings

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
  selfguard machines peers           machines on your tailnet, what each one can do
  selfguard machines add <peer> --via share
                                     pair with another machine running selfguard with
                                     sharing on: no SSH (you approve it over there)
  selfguard machines migrate <name> --via share|ssh
                                     switch how a machine is reached, keeping its history
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

Sharing (let your other machines see this one, over Tailscale, without SSH):
  selfguard share on | off | status  start/stop answering on this machine's tailnet addresses
  selfguard share requests           pairing requests waiting, with their codes
  selfguard share approve <id> [--scope DIR] [--root DIR]... | reject <id>
  selfguard share list | revoke <name>
                                     machines that can see this one

Updates:
  selfguard update                   check npm for a newer selfguard and show how to update
                                     (it never installs anything by itself)

AI / automation:
  --json                             any command: one JSON document on stdout
  selfguard mcp                      MCP server over stdio (claude mcp add selfguard -- selfguard mcp)
  selfguard guide                    usage guide for AI agents

Data: OSV.dev (GitHub advisories, CVEs, malicious packages). Only package names and versions
leave your machine. Nothing in your projects is executed. State: ~/.selfguard (SELFGUARD_HOME).
Exit codes: 0 ok, 1 vulnerabilities found (scan/report), 2 error.`;

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
    case "update":
      return cmdUpdate(rest);
    case "share":
      return cmdShare(rest);
    case "roots":
      return cmdRoots(rest);
    case "where":
      return cmdWhere(rest);
    case "vuln":
      return cmdVuln(rest);
    case "tools":
      return cmdTools(rest);
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
