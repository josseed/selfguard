/**
 * Shell integration. The shell does the cheap work (walk up for a project file,
 * stat the lockfile on each prompt); node only runs when you enter a different
 * project or the lockfile changes. Network work always happens in a detached
 * background process so your prompt never waits on it.
 */
import { spawn } from "node:child_process";
import { existsSync, openSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isExcluded, loadConfig } from "./config.ts";
import { ensureDir } from "./fsutil.ts";
import { findProject, PROJECT_MARKERS } from "./lockfile/detect.ts";
import { logFile, stateRoot } from "./paths.ts";
import { groupByPackage, paint, summarizeCounts, worstSeverity } from "./report.ts";
import { lockChanged } from "./scan.ts";
import { loadRepo } from "./store.ts";

const RESCAN_AFTER_MS = 24 * 60 * 60 * 1000;

export const ZSH_HOOK = String.raw`# selfguard shell hook (zsh)
if (( $+commands[selfguard] )); then
  zmodload -F zsh/stat b:zstat 2>/dev/null
  typeset -g _selfguard_dir="" _selfguard_lock="" _selfguard_mtime=""

  _selfguard_mtime_of() {
    local -a m
    if zstat -A m +mtime -- "$1" 2>/dev/null; then REPLY=$m[1]; else REPLY=""; fi
  }

  _selfguard_enter() {
    _selfguard_lock=$(command selfguard hook-enter --dir "$1" $2)
    if [[ -n $_selfguard_lock ]]; then
      _selfguard_mtime_of "$_selfguard_lock"; _selfguard_mtime=$REPLY
    else
      _selfguard_mtime=""
    fi
  }

  _selfguard_chpwd() {
    local d=$PWD found=""
    while [[ $d != / && $d != $HOME ]]; do
      if [[ ${PROJECT_MARKERS.map((f) => `-f $d/${f}`).join(" || ")} ]]; then found=$d; break; fi
      [[ -e $d/.git ]] && break
      d=$d:h
    done
    [[ $found == $_selfguard_dir ]] && return
    _selfguard_dir=$found
    if [[ -n $found ]]; then _selfguard_enter "$found"; else _selfguard_lock=""; _selfguard_mtime=""; fi
  }

  _selfguard_precmd() {
    [[ -z $_selfguard_lock ]] && return
    _selfguard_mtime_of "$_selfguard_lock"
    [[ $REPLY == $_selfguard_mtime ]] && return
    _selfguard_enter "$_selfguard_dir" --prompt
  }

  autoload -Uz add-zsh-hook
  add-zsh-hook chpwd _selfguard_chpwd
  add-zsh-hook precmd _selfguard_precmd
  _selfguard_chpwd
fi
`;

/**
 * V8 options for every engine process selfguard starts (agents, background scans, the app).
 * A small young generation keeps the peak memory of a run that reads many records low (about a
 * third less), at no measurable cost in time.
 */
export const NODE_FLAGS: readonly string[] = ["--max-semi-space-size=2"];

/** The command line of `selfguard <args>` with this Node: [node, ...flags, cli.js, ...args]. */
export const engineCommand = (...args: string[]): string[] => [process.execPath, ...NODE_FLAGS, cliEntry(), ...args];

export function cliEntry(): string {
  // dist/hook.js -> dist/cli.js (same directory)
  return join(fileURLToPath(new URL(".", import.meta.url)), "cli.js");
}

/** Start `selfguard scan <dir> --background` fully detached from the shell. */
export function spawnBackgroundScan(dir: string): void {
  ensureDir(stateRoot());
  const out = openSync(logFile(), "a", 0o600);
  const child = spawn(process.execPath, engineCommand("scan", dir, "--background").slice(1), {
    detached: true,
    stdio: ["ignore", out, out],
    env: process.env,
  });
  child.unref();
}

/**
 * Called by the shell when entering a project. Prints the lockfile path to watch on
 * stdout (consumed by the hook) and human messages on stderr. Must be fast and silent
 * on errors: a broken guard must never break the user's shell.
 */
export function hookEnter(dir: string, onPrompt = false): void {
  try {
    const project = findProject(dir);
    if (!project) {
      // A Python or Rust project without its lockfile yet: watch the folder itself (its mtime
      // changes when `uv lock` or `cargo generate-lockfile` creates one), so it is picked up.
      if (["pyproject.toml", "Cargo.toml"].some((f) => existsSync(join(dir, f))) && !isExcluded(dir, loadConfig().exclude)) process.stdout.write(dir);
      return;
    }
    if (isExcluded(project.root, loadConfig().exclude)) return;
    process.stdout.write(project.lockfile ?? join(project.root, "package-lock.json"));

    const c = paint(process.stderr);
    const tag = c.cyan("selfguard");
    const rec = loadRepo(project.root);

    const stale = !rec?.scannedAt || Date.now() - Date.parse(rec.scannedAt) > RESCAN_AFTER_MS;
    const changed = !rec || lockChanged(rec, project);
    if (changed || stale) {
      if (!project.lockfile) return; // nothing to scan until a lockfile exists
      spawnBackgroundScan(project.root);
      if (!rec) process.stderr.write(`${tag} ${c.dim("new project registered, scanning in background…")}\n`);
      else if (changed) process.stderr.write(`${tag} ${c.dim("dependencies changed, re-scanning in background…")}\n`);
    }

    // On a prompt-triggered re-check with no real change, stay quiet.
    if (rec && rec.findings.length > 0 && !changed && !onPrompt) {
      const worst = worstSeverity(rec.findings);
      const color = worst === "malicious" || worst === "critical" || worst === "high" ? c.red : c.yellow;
      const pkgs = groupByPackage(rec.findings).length;
      process.stderr.write(
        `${tag} ${color(`${pkgs} vulnerable package(s)`)} ${c.dim(`(${summarizeCounts(rec.findings)})`)} ${c.dim("→ selfguard scan")}\n`,
      );
    }
  } catch {
    /* never break the shell */
  }
}
