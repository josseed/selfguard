// `selfguard ui` and `selfguard app`: the dashboard is the Mac app; these only point to it.
import { parseArgs } from "node:util";
import { DASHBOARD_PAGES, hasLegacyLauncher, macAppPath, openDashboard, RELEASES_URL, removeLegacyLauncher } from "../app.ts";
import { paint, tildify } from "../report.ts";
import { emit, JSON_OPT, out, usage } from "./output.ts";

const GET_THE_APP = `The dashboard is part of the selfguard Mac app: ${RELEASES_URL}`;

export function cmdUi(args: string[]): number {
  const { values } = parseArgs({ args, options: { ...JSON_OPT, repo: { type: "string" }, page: { type: "string" } } });
  if (values.page !== undefined && !DASHBOARD_PAGES.includes(values.page)) usage(`--page must be one of: ${DASHBOARD_PAGES.join(", ")}`);
  const say = (opened: boolean, message: string): number => {
    if (values.json) emit({ opened, message });
    else out.write(`${message}\n`);
    return opened ? 0 : 1;
  };
  if (process.platform !== "darwin") {
    return say(false, "The visual dashboard is the selfguard Mac app; there is no dashboard on this system.\nEverything is in the CLI: selfguard status, selfguard report, selfguard --help");
  }
  if (openDashboard({ repo: values.repo, page: values.page })) return say(true, "Opening the selfguard dashboard in the Mac app.");
  return say(false, `selfguard for Mac is not installed.\n${GET_THE_APP}\nMeanwhile: selfguard status, selfguard report`);
}

export function cmdApp(args: string[]): number {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: JSON_OPT });
  const c = paint(out);
  const legacy = process.platform === "darwin" && hasLegacyLauncher();
  switch (positionals[0]) {
    case "uninstall": {
      const was = removeLegacyLauncher();
      if (values.json) emit({ removed: was });
      else out.write(was ? "Removed the old script launcher (~/Applications/selfguard.app).\n" : "No old script launcher to remove. (The Mac app is removed by dragging it to the Trash.)\n");
      return 0;
    }
    case "install":
    case "status":
    case undefined: {
      const app = process.platform === "darwin" ? macAppPath() : null;
      if (values.json) emit({ installed: app !== null, path: app, legacyLauncher: legacy, download: RELEASES_URL });
      else if (app) out.write(`${c.green("✓")} selfguard for Mac is installed (${tildify(app)}). Open the dashboard with: selfguard ui\n`);
      else if (process.platform === "darwin") out.write(`${GET_THE_APP}\nThe old script launcher (selfguard app install) no longer exists.\n`);
      else out.write("selfguard for Mac is macOS-only; the CLI is complete on this system (selfguard --help).\n");
      if (legacy && !values.json) out.write(c.dim("An old script launcher is in ~/Applications; remove it with: selfguard app uninstall\n"));
      return 0;
    }
    default:
      usage("usage: selfguard app [install | uninstall | status]");
  }
}
