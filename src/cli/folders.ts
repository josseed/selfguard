// Folder commands: discover, roots, forget, unexclude, dismiss, undismiss.
import { parseArgs } from "node:util";
import * as api from "../api.ts";
import { paint, tildify } from "../report.ts";
import { clean } from "../sanitize.ts";
import { confirm, isInteractive, withSpinner } from "../tui.ts";
import { ago, emit, JSON_OPT, out, usage } from "./output.ts";

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

export async function cmdDiscover(args: string[]): Promise<number> {
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

export function cmdRoots(args: string[]): number {
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

export function cmdForget(args: string[]): number {
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

export function cmdUnexclude(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  if (!positionals[0]) usage("usage: selfguard unexclude <dir>");
  const r = api.unexclude(positionals[0]);
  if (values.json) emit(r);
  else out.write(r.removed ? "Removed from exclusions.\n" : "That path was not excluded.\n");
  return 0;
}

export function cmdDismiss(args: string[]): number {
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

export function cmdUndismiss(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  const r = api.undismissRepo(api.resolveRepoKey(positionals[0] ?? "."));
  if (values.json) emit(r);
  else out.write(r.removed ? "Turned back on.\n" : "That repo was not dismissed.\n");
  return 0;
}
