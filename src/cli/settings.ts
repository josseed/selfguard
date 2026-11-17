// Settings and local integration: settings, menubar, schedule.
import { writeMenuBar } from "../menubar.ts";
import { parseArgs } from "node:util";
import * as api from "../api.ts";
import { paint, tildify } from "../report.ts";
import { parseInterval, scheduleOff, scheduleOn, scheduleStatus, updateDiscoverAgent } from "../schedule.ts";
import { emit, JSON_OPT, out, usage } from "./output.ts";

export function cmdSettings(args: string[]): number {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, remind: { type: "string" }, "active-days": { type: "string" }, "auto-discover": { type: "string" }, "update-check": { type: "string" } } });
  const patch: { remind?: unknown; activeDays?: unknown; autoDiscover?: unknown; updateCheck?: unknown } = {};
  if (values["update-check"] !== undefined) {
    if (values["update-check"] !== "on" && values["update-check"] !== "off") usage("--update-check must be on or off");
    patch.updateCheck = values["update-check"] === "on";
  }
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
    out.write(`update-check  ${s.updateCheck ? "on" : "off"}\n`);
    out.write(`auto-discover ${s.autoDiscover ? "on" : "off"}${s.lastEverywhere ? paint(out).dim(`  (last search ${s.lastEverywhere})`) : ""}\n`);
    if (s.lastSync) out.write(paint(out).dim(`last sync     ${s.lastSync}\n`));
  }
  return 0;
}

/** `selfguard menubar`: rewrite the Mac app's summary (~/.selfguard/menubar.json) and print it. */
export function cmdMenuBar(args: string[]): number {
  parseArgs({ args, options: JSON_OPT });
  const m = writeMenuBar();
  if (!m) {
    process.stderr.write("selfguard: could not write the menu bar summary\n");
    return 1;
  }
  emit(m);
  return 0;
}

export function cmdSchedule(args: string[]): number {
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
