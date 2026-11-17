// Settings and local integration: settings, ui, app, schedule.
import { writeMenuBar } from "../menubar.ts";
import { parseArgs } from "node:util";
import * as api from "../api.ts";
import { appStatus, installApp, uninstallApp } from "../app.ts";
import { paint, tildify } from "../report.ts";
import { parseInterval, scheduleOff, scheduleOn, scheduleStatus, updateDiscoverAgent } from "../schedule.ts";
import { runUi } from "../ui/server.ts";
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

export async function cmdUi(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: { "no-open": { type: "boolean" }, port: { type: "string" }, serve: { type: "boolean" } },
  });
  const port = values.port === undefined ? 0 : Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65535) usage("--port must be a port number");
  await runUi({ port, open: !values["no-open"], foreground: values.serve ?? false, log: (line) => out.write(`${line}\n`) });
  return 0;
}

export function cmdApp(args: string[]): number {
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
