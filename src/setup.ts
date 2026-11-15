/** `selfguard setup`: interactive wizard to choose where your repos live. */
import { appendFileSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { candidateRoots, clampDepth, DEFAULT_DEPTH, loadConfig, MAX_DEPTH, normalizeDir, saveConfig, type Root } from "./config.ts";
import { discover, discoverAll } from "./discover.ts";
import type { Project } from "./lockfile/detect.ts";
import { groupByPackage, paint, summarizeCounts, tildify, worstSeverity } from "./report.ts";
import { scanProjects, type ScanOutcome } from "./scan.ts";
import { scheduleOn, scheduleStatus } from "./schedule.ts";
import { appStatus, installApp } from "./app.ts";
import { findEverywhere, watchTargets } from "./api.ts";
import { announce } from "./announce.ts";
import { listRepos, saveRepo } from "./store.ts";
import { confirm, fitStart, isPrintable, readKeys, Screen, withSpinner } from "./tui.ts";

const out = process.stdout;

interface Item {
  path: string;
  selected: boolean;
  depth: number;
  count: number | null; // null = still counting
  generation: number;
}

/** Interactive folder picker. Resolves to the chosen roots, or null if cancelled. */
async function pickRoots(initial: Root[], exclude: string[], suggested: Root[] = []): Promise<Root[] | null> {
  const c = paint(out);
  const items: Item[] = [];
  const add = (path: string, selected: boolean, depth: number): void => {
    if (items.some((i) => i.path.toLowerCase() === path.toLowerCase())) return;
    items.push({ path, selected, depth, count: null, generation: 0 });
  };
  for (const r of initial) add(r.path, true, r.depth);
  for (const r of suggested) add(r.path, false, r.depth);
  for (const p of candidateRoots()) add(p, false, DEFAULT_DEPTH);

  let cursor = 0; // items.length = the "add folder" row
  let mode: "list" | "input" = "list";
  let input = "";
  let message = "";
  const screen = new Screen();

  const draw = (): void => {
    const lines: string[] = [];
    lines.push(c.bold("Where do you keep your code?"));
    lines.push(c.dim("selfguard only looks inside the folders you pick, nothing else on your disk."));
    lines.push("");
    const width = Math.max(20, Math.min(50, (out.columns ?? 80) - 40));
    items.forEach((it, i) => {
      const pointer = i === cursor && mode === "list" ? c.cyan("›") : " ";
      const box = it.selected ? c.green("[x]") : "[ ]";
      const name = fitStart(tildify(it.path), width).padEnd(width);
      const label = (
        it.count === null ? "counting…" : it.count === 0 ? "no JS projects" : `${it.count} project${it.count === 1 ? "" : "s"}`
      ).padEnd(14);
      const count = it.count ? label : c.dim(label);
      lines.push(`${pointer} ${box} ${i === cursor ? c.bold(name) : name}  ${count} ${c.dim(`depth ${it.depth}`)}`);
    });
    const addRow = cursor === items.length && mode === "list";
    lines.push(`${addRow ? c.cyan("›") : " "} ${c.cyan("+")} ${addRow ? c.bold("add another folder…") : "add another folder…"}`);
    lines.push("");
    if (mode === "input") {
      lines.push(`${c.cyan("Folder:")} ${input}${c.inverseRed(" ")}`);
      lines.push(c.dim("enter add · esc cancel · ~ = home"));
    } else {
      lines.push(c.dim("↑/↓ move · space select · ←/→ depth · a add folder · enter continue · q quit"));
    }
    lines.push(message ? c.yellow(message) : "");
    screen.render(lines);
  };

  const count = (it: Item): void => {
    const gen = ++it.generation;
    it.count = null;
    discover(it.path, { depth: it.depth, exclude, isCancelled: () => it.generation !== gen }).then((found) => {
      if (it.generation !== gen) return;
      it.count = found.length;
      draw();
    });
  };
  items.forEach(count);
  draw();

  return readKeys<Root[] | null>((key, finish) => {
    message = "";
    if (mode === "input") {
      if (key.name === "escape") {
        mode = "list";
        input = "";
      } else if (key.name === "return" || key.name === "enter") {
        const dir = normalizeDir(input);
        if (!dir) {
          message = `Not a folder: ${input}`;
        } else if (dir === homedir() || dir === "/") {
          message = "Pick a more specific folder than your whole home directory.";
        } else {
          add(dir, true, DEFAULT_DEPTH);
          const it = items.find((i) => i.path === dir)!;
          it.selected = true;
          count(it);
          cursor = items.indexOf(it);
          mode = "list";
          input = "";
        }
      } else if (key.name === "backspace") {
        input = input.slice(0, -1);
      } else if (isPrintable(key) && input.length < 400) {
        input += key.sequence;
      }
      draw();
      return;
    }

    const it = items[cursor];
    switch (key.name) {
      case "up":
      case "k":
        cursor = cursor === 0 ? items.length : cursor - 1;
        break;
      case "down":
      case "j":
        cursor = cursor === items.length ? 0 : cursor + 1;
        break;
      case "space":
        if (it) it.selected = !it.selected;
        else mode = "input";
        break;
      case "left":
      case "right":
        if (it) {
          const d = clampDepth(it.depth + (key.name === "right" ? 1 : -1));
          if (d !== it.depth) {
            it.depth = d;
            count(it);
          } else {
            message = `Depth goes from 1 to ${MAX_DEPTH}.`;
          }
        }
        break;
      case "a":
        mode = "input";
        break;
      case "return":
      case "enter":
        if (!it && cursor === items.length) {
          mode = "input";
          break;
        }
        if (!items.some((i) => i.selected)) {
          message = "Select at least one folder (space), or press q to quit.";
          break;
        }
        screen.done();
        finish(items.filter((i) => i.selected).map((i) => ({ path: i.path, depth: i.depth })));
        return;
      case "q":
      case "escape":
        screen.done();
        finish(null);
        return;
    }
    draw();
  });
}

function hasZshHook(): boolean {
  try {
    return readFileSync(join(homedir(), ".zshrc"), "utf8").includes("selfguard init zsh");
  } catch {
    return false;
  }
}

function printScanSummary(outcomes: ScanOutcome[]): void {
  const c = paint(out);
  const risky = outcomes
    .filter((o) => o.record.findings.length > 0)
    .sort((a, b) => b.record.findings.length - a.record.findings.length);
  const unsupported = outcomes.filter((o) => o.record.error && o.record.findings.length === 0).length;
  out.write(`\n${c.bold(`${outcomes.length} project(s) scanned.`)}\n`);
  if (risky.length === 0) out.write(`${c.green("✓")} no known vulnerabilities\n`);
  for (const o of risky.slice(0, 10)) {
    const w = worstSeverity(o.record.findings);
    const color = w === "malicious" || w === "critical" || w === "high" ? c.red : c.yellow;
    const pkgs = groupByPackage(o.record.findings).length;
    out.write(`  ${color("●")} ${c.bold(tildify(o.record.path))}  ${pkgs} vulnerable pkg(s) ${c.dim(`(${summarizeCounts(o.record.findings)})`)}\n`);
  }
  if (risky.length > 10) out.write(c.dim(`  …and ${risky.length - 10} more (selfguard status)\n`));
  if (unsupported > 0) out.write(c.dim(`  ${unsupported} project(s) skipped: no lockfile yet, or unreadable\n`));
}

export async function runSetup(): Promise<number> {
  const c = paint(out);
  out.write(`\n${c.bold(c.cyan("selfguard setup"))}\n\n`);

  const cfg = loadConfig();
  // People who don't keep code in one folder: search the whole home folder first and
  // pre-select the places with active repos.
  let initial = cfg.roots;
  let suggested: Root[] = [];
  if (await confirm("Search your whole home folder for projects first? (recommended if your code isn't all in one folder)", cfg.roots.length === 0)) {
    const scan = await withSpinner("Searching your home folder (a minute or two; macOS may ask for access to Desktop/Documents/Downloads)…", () => findEverywhere());
    out.write(`\r${c.green("✓")} ${scan.projects} project(s) in ${scan.places.length} place(s).\n\n`);
    initial = [...cfg.roots, ...scan.places.filter((p) => p.recommended).map((p) => ({ path: p.path, depth: p.depth }))];
    suggested = scan.places.filter((p) => !p.recommended && !p.watched).map((p) => ({ path: p.path, depth: p.depth }));
  }
  const roots = await pickRoots(initial, cfg.exclude, suggested);
  if (!roots) {
    out.write("Cancelled, nothing changed.\n");
    return 0;
  }
  saveConfig({ ...cfg, roots });
  out.write(`${c.green("✓")} Saved ${roots.length} folder(s) to watch.\n\n`);

  const projects = await withSpinner("Looking for projects…", () => discoverAll(roots, { exclude: cfg.exclude }));
  const known = new Set(listRepos().map((r) => r.path));
  const fresh: Project[] = projects.filter((p) => !known.has(p.root));
  out.write(`Found ${c.bold(String(projects.length))} project(s), ${c.bold(String(fresh.length))} not tracked yet.\n`);
  for (const p of fresh.slice(0, 8)) out.write(c.dim(`  ${tildify(p.root)}\n`));
  if (fresh.length > 8) out.write(c.dim(`  …and ${fresh.length - 8} more\n`));

  if (fresh.length > 0) {
    out.write("\n");
    if (await confirm(`Scan ${fresh.length} new project(s) now? (sends only package names+versions to OSV.dev)`)) {
      const outcomes = await withSpinner(`Scanning ${fresh.length} project(s)…`, () => scanProjects(fresh));
      for (const o of outcomes) saveRepo(o.record);
      await announce(outcomes, { notify: false });
      printScanSummary(outcomes);
    }
  }

  out.write("\n");
  if (hasZshHook()) {
    out.write(`${c.green("✓")} Shell hook already in ~/.zshrc\n`);
  } else if (await confirm("Add the shell hook to ~/.zshrc (alerts when you cd into a project)?")) {
    appendFileSync(join(homedir(), ".zshrc"), `\n# selfguard: dependency vulnerability alerts\neval "$(selfguard init zsh)"\n`);
    out.write(`${c.green("✓")} Added. Open a new terminal to activate it.\n`);
  }

  if (process.platform === "darwin") {
    if (scheduleStatus().loaded) {
      out.write(`${c.green("✓")} Background sync already enabled\n`);
    } else if (await confirm("Watch your repos in the background (macOS notifications, daily reminder of serious issues)?")) {
      scheduleOn(6 * 3600, watchTargets(), { autoDiscover: loadConfig().autoDiscover });
      out.write(`${c.green("✓")} Enabled. Lockfile changes are checked right away; new repos are picked up every 6h.\n`);
    }
  }

  if (process.platform === "darwin") {
    if (appStatus().installed) {
      out.write(`${c.green("✓")} selfguard.app already in ~/Applications\n`);
    } else if (await confirm("Add selfguard.app to ~/Applications (open the dashboard from Spotlight or the Dock)?")) {
      installApp();
      out.write(`${c.green("✓")} Added. Open it with ⌘+Space → "selfguard".\n`);
    }
  }

  out.write(`\nDone. ${c.dim("selfguard ui (dashboard) · selfguard status · selfguard --help")}\n`);
  return 0;
}
