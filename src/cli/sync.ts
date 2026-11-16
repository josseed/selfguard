// Background-friendly commands: sync, check, remind, update.
import { parseArgs } from "node:util";
import { buildReminder, needsAttention } from "../alerts.ts";
import { maybeRemind } from "../announce.ts";
import * as api from "../api.ts";
import { notify } from "../notify.ts";
import { groupByPackage, paint, severityLabel, tildify } from "../report.ts";
import { clean } from "../sanitize.ts";
import { updateWatcher } from "../schedule.ts";
import { checkForUpdate, installedVersion, notifyUpdateOnce } from "../update.ts";
import { VERSION } from "../version.ts";
import { emit, err, JSON_OPT, out } from "./output.ts";

export async function cmdSync(args: string[]): Promise<number> {
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
  if (values.background) {
    await maybeRemind(api.getAttention);
    // Once a day at most; one notification per new version.
    const info = await checkForUpdate();
    await notifyUpdateOnce(info, (title, body) => notify(title, body, "Update"));
  }
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

export async function cmdCheck(args: string[]): Promise<number> {
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

export async function cmdRemind(args: string[]): Promise<number> {
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
        packages: r.packages.map((g) => ({ name: g.name, version: g.version, ecosystem: g.ecosystem, worstSeverity: g.worst, upgradeTo: g.upgradeTo ?? null, direct: g.direct })),
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

export async function cmdUpdate(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { ...JSON_OPT } });
  const info = await checkForUpdate({ force: true });
  const disk = installedVersion();
  if (values.json) {
    emit({ ...info, installed: disk });
    return 0;
  }
  const c = paint(out);
  if (!info.enabled) out.write(c.dim("Update checks are off (selfguard settings --update-check on).\n"));
  if (info.available) {
    out.write(`${c.yellow("●")} selfguard ${c.bold(info.latest ?? "")} is available (you have ${VERSION}).\n`);
    out.write(`  What's new: ${info.releaseNotes}\n`);
    if (info.provenance === false) out.write(c.yellow("  Warning: this release has no npm provenance attestation. Check it before installing.\n"));
    else if (info.provenance) out.write(c.dim("  Built and signed by GitHub Actions (npm provenance).\n"));
    out.write(`  Update with: ${c.bold(info.command ?? "")}\n`);
  } else if (info.latest) {
    out.write(`${c.green("✓")} selfguard ${VERSION} is the latest version.\n`);
  } else if (info.enabled) {
    out.write(c.dim("Couldn't reach the npm registry; try again later.\n"));
  }
  return 0;
}
