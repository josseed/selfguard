/** The JSON API: one function from (method, path, body) to an answer. */
import type { IncomingMessage } from "node:http";
import { maybeRemind } from "../announce.ts";
import * as api from "../api.ts";
import { isObject } from "../fsutil.ts";
import { installApp, uninstallApp } from "../app.ts";
import { scheduleOff, scheduleOn, updateDiscoverAgent, updateRemoteAgent, updateWatcher } from "../schedule.ts";
import { loadRepo } from "../store.ts";
import { checkForUpdate } from "../update.ts";
import { VERSION } from "../version.ts";
import { readBody } from "./http.ts";
import { everywhere, everywhereStatus, pairJobs, pairStatus, startEverywhere, startPairJob } from "./jobs.ts";
import { getMenuBar } from "./menubar.ts";
import { getOverview, updateStatus } from "./overview.ts";

function str(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  if (typeof v !== "string" || !v.trim()) throw new api.ApiError("invalid", `"${key}" is required`);
  return v;
}

/** Only act on projects selfguard already tracks (never arbitrary paths). */
function trackedPath(body: Record<string, unknown>): string {
  const path = body.path;
  if (typeof path !== "string" || !loadRepo(path)) throw new api.ApiError("not_tracked", "not a tracked project");
  return path;
}

/** Machine named in the body, if any (must be a configured one). */
function machineOf(body: Record<string, unknown>): string | null {
  const m = body.machine;
  if (m === undefined || m === null) return null;
  if (typeof m !== "string" || !api.listMachines().some((x) => x.name === m)) throw new api.ApiError("not_found", "unknown machine");
  return m;
}

function depthOf(body: Record<string, unknown>): number | undefined {
  const depth = body.depth === undefined ? undefined : Number(body.depth);
  if (depth !== undefined && !Number.isInteger(depth)) throw new api.ApiError("invalid", "depth must be an integer");
  return depth;
}

function refreshRemoteAgent(): void {
  try {
    updateRemoteAgent(api.hasMachines());
  } catch {
    /* best effort */
  }
}

export interface RouteContext {
  /** Restart this dashboard with the code on disk (same port and token). */
  restart?: () => void;
  /** Where the page files are (tests). */
  staticDir?: string;
}

export async function route(method: string, url: URL, req: IncomingMessage, ctx: RouteContext = {}): Promise<unknown> {
  const p = url.pathname;
  if (method === "GET") {
    if (p === "/api/ping") return { ok: true, version: VERSION };
    if (p === "/api/overview") return getOverview();
    if (p === "/api/menubar") return getMenuBar();
    if (p === "/api/repo") return api.getRepoDetail(url.searchParams.get("key") ?? "");
    if (p === "/api/repo/markdown") {
      const path = url.searchParams.get("path");
      return api.getRepoMarkdown(url.searchParams.get("key") ?? "", path ? { path } : {});
    }
    if (p === "/api/machines") return { machines: api.listMachines() };
    if (p === "/api/update") return updateStatus();
    if (p === "/api/everywhere/status") return everywhereStatus();
    if (p === "/api/machines/peers") return api.machinePeers();
    if (p === "/api/pair/status") return pairStatus(url.searchParams.get("job") ?? "");
    if (p === "/api/share") return { ...(await api.shareStatus()), suggestions: api.shareSuggestions() };
    if (p === "/api/machines/setup") return api.machineSetup(url.searchParams.get("name") ?? "");
    if (p === "/api/machines/fs") return api.browseOnMachine(url.searchParams.get("name") ?? "", url.searchParams.get("path") ?? undefined);
    if (p === "/api/vuln") return api.getVulnerability(url.searchParams.get("id") ?? "");
    if (p === "/api/packages") return { packages: api.getPackagesOverview() };
    if (p === "/api/sources") return api.getSources();
    if (p === "/api/repo/sources") return { sources: api.getRepoSources(url.searchParams.get("key") ?? "") };
    if (p === "/api/folders") return api.getFolders();
    if (p === "/api/fs") return api.listDirectories(url.searchParams.get("path") ?? undefined);
  }
  if (method === "POST") {
    const body = await readBody(req);
    if (p === "/api/scan") {
      const machine = machineOf(body);
      return machine ? api.scanRemote(machine, str(body, "path")) : api.scanPath(trackedPath(body), { notify: false });
    }
    if (p === "/api/sync") {
      const { outcomes: _o, ...r } = await api.sync({ notify: true });
      try {
        updateWatcher(api.watchTargets());
      } catch {
        /* watcher is best effort */
      }
      return r;
    }
    if (p === "/api/forget") {
      const machine = machineOf(body);
      return machine ? api.excludeOnMachine(machine, str(body, "path")) : api.forget(trackedPath(body), { exclude: true });
    }
    if (p === "/api/machines/test") return api.testMachine(str(body, "host"));
    if (p === "/api/pair/start") {
      const replace = typeof body.replace === "string" ? body.replace : undefined;
      const name = typeof body.name === "string" && body.name ? body.name : undefined;
      const start = replace ? await api.migrateToShare(replace) : await api.startPairing(str(body, "peer"), { name });
      return startPairJob(start, { replace, name });
    }
    if (p === "/api/pair/cancel") {
      const job = pairJobs.get(str(body, "job"));
      if (job) job.cancelled = true;
      return { cancelled: Boolean(job) };
    }
    if (p === "/api/share") {
      const patch: { enabled?: boolean; allowOtherUsers?: boolean } = {};
      if (typeof body.enabled === "boolean") patch.enabled = body.enabled;
      if (typeof body.allowOtherUsers === "boolean") patch.allowOtherUsers = body.allowOtherUsers;
      return api.setShare(patch);
    }
    if (p === "/api/share/approve") {
      const roots = Array.isArray(body.roots)
        ? body.roots.filter((r): r is { path: string; depth: number } => isObject(r) && typeof r.path === "string" && typeof r.depth === "number")
        : [];
      return api.approveShareRequest(str(body, "id"), { scope: typeof body.scope === "string" ? body.scope : "~", roots });
    }
    if (p === "/api/share/reject") return api.rejectShareRequest(str(body, "id"));
    if (p === "/api/share/revoke") return api.revokeShareGrant(str(body, "id"));
    if (p === "/api/machines/add") {
      const host = str(body, "host");
      const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : api.suggestName(host);
      const port = body.port === undefined || body.port === "" ? undefined : Number(body.port);
      const r = await api.addMachine(name, host, {
        mode: body.mode === "ssh" ? "ssh" : "restricted",
        port,
        scope: typeof body.scope === "string" && body.scope.trim() ? body.scope.trim() : undefined,
        install: body.install !== false,
      });
      refreshRemoteAgent();
      return r;
    }
    if (p === "/api/machines/install") return api.installMachine(str(body, "name"));
    if (p === "/api/machines/verify") return api.verifyMachine(str(body, "name"));
    if (p === "/api/machines/remove") {
      const r = await api.removeMachine(str(body, "name"), { revoke: body.revoke !== false });
      refreshRemoteAgent();
      return r;
    }
    if (p === "/api/machines/roots/add") return api.addMachineRoot(str(body, "name"), str(body, "path"), depthOf(body));
    if (p === "/api/machines/roots/remove") return api.removeMachineRoot(str(body, "name"), str(body, "path"));
    if (p === "/api/machines/unexclude") return { removed: api.unexcludeOnMachine(str(body, "name"), str(body, "path")) };
    if (p === "/api/machines/sync") {
      const name = typeof body.name === "string" ? body.name : undefined;
      return api.checkMachines({ notify: true, only: name ? [name] : undefined });
    }
    if (p === "/api/settings") {
      const r = api.updateSettings({ remind: body.remind, activeDays: body.activeDays, autoDiscover: body.autoDiscover });
      if (body.autoDiscover !== undefined) {
        try {
          updateDiscoverAgent(r.autoDiscover);
        } catch {
          /* best effort */
        }
      }
      return r;
    }
    if (p === "/api/remind") return { sent: await maybeRemind(api.getAttention, { force: true }) };
    if (p === "/api/folders/add") {
      const depth = body.depth === undefined ? undefined : Number(body.depth);
      if (depth !== undefined && !Number.isInteger(depth)) throw new api.ApiError("invalid", "depth must be an integer");
      return api.addRoot(str(body, "path"), depth);
    }
    if (p === "/api/folders/remove") return api.removeRoot(str(body, "path"));
    if (p === "/api/repo/dismiss") return api.dismissRepo(str(body, "key"));
    if (p === "/api/repo/undismiss") return api.undismissRepo(str(body, "key"));
    if (p === "/api/unexclude") {
      const path = str(body, "path");
      if (!api.listRoots().exclude.includes(path)) throw new api.ApiError("not_found", "that path is not excluded");
      return api.unexclude(path);
    }
    if (p === "/api/discover") return api.discoverNew({ dryRun: body.dryRun === true });
    if (p === "/api/everywhere/start") return startEverywhere();
    if (p === "/api/update/check") {
      await checkForUpdate({ force: true });
      return updateStatus();
    }
    if (p === "/api/restart") {
      if (!ctx.restart) throw new api.ApiError("unsupported", "this dashboard can't restart itself; run selfguard ui again");
      ctx.restart();
      return { restarting: true };
    }
    if (p === "/api/everywhere/cancel") {
      if (everywhere.running) everywhere.cancelled = true;
      return everywhereStatus();
    }
    if (p === "/api/everywhere/apply") {
      const watch = Array.isArray(body.watch) ? body.watch : [];
      const ignore = Array.isArray(body.ignore) ? body.ignore.filter((x): x is string => typeof x === "string") : [];
      const places = everywhere.result?.places ?? [];
      // Only places from the last search can be applied (never arbitrary paths).
      const chosen = watch
        .filter((w): w is string => typeof w === "string")
        .map((path) => places.find((pl) => pl.path === path))
        .filter((pl): pl is NonNullable<typeof pl> => Boolean(pl))
        .map((pl) => ({ path: pl.path, depth: pl.depth }));
      const rejected = ignore.filter((path) => places.some((pl) => pl.path === path));
      const r = await api.applyPlaces(chosen, rejected);
      try {
        updateWatcher(api.watchTargets());
      } catch {
        /* watcher is best effort */
      }
      return r;
    }
    if (p === "/api/schedule") {
      if (process.platform !== "darwin") throw new api.ApiError("unsupported", "background watching is macOS-only for now");
      if (body.enabled === true) scheduleOn(6 * 3600, api.watchTargets(), { machines: api.hasMachines(), autoDiscover: api.getSettings().autoDiscover });
      else if (body.enabled === false) scheduleOff();
      else throw new api.ApiError("invalid", "enabled must be true or false");
      return getOverview().schedule;
    }
    if (p === "/api/app") {
      if (process.platform !== "darwin") throw new api.ApiError("unsupported", "the launcher app is macOS-only");
      if (body.installed === true) installApp();
      else if (body.installed === false) uninstallApp();
      else throw new api.ApiError("invalid", "installed must be true or false");
      return getOverview().app;
    }
  }
  throw new api.ApiError("not_found", "no such endpoint");
}
