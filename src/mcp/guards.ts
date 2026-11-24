/**
 * What MCP tools refuse on their own: an agent may be following text from the repo or host it is
 * warned about (prompt injection), so it can't silence what looks like an attack.
 */
import { lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import * as api from "../api.ts";
import { expandHome, isExcluded, normalizeDir } from "../config.ts";
import { listSources } from "../sources/store.ts";
import { warningId, warningKey } from "../sources/warnings.ts";

/** Makes selfguard watch or alert less: clients ask the user first. */
export const REDUCES = { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false };

/** Urgent warnings look like an attack: only the user dismisses them. */
export function notUrgent(target: string): string {
  const t = target.trim();
  const urgent = listSources().flatMap((rec) => rec.warnings.filter((w) => w.urgent === true).map((w) => warningKey(rec.kind, w)));
  if (!urgent.some((k) => k === t || warningId(k) === t)) return target;
  throw new api.ApiError("invalid", "this warning is urgent (it looks like an attack): the user must review and dismiss it in the selfguard app or with `selfguard dismiss --warning <id>`");
}

/** Forgetting a repo drops its warnings too: not over MCP while it (or a repo inside) has an urgent one. */
export function noUrgentRepo(path: string): string {
  const abs = normalizeDir(path) ?? resolve(path);
  const near = (p: string): boolean => isExcluded(p, [abs]) || isExcluded(abs, [p]);
  if (!listSources({ scope: "repo" }).some((rec) => near(rec.path) && rec.warnings.some((w) => w.urgent === true))) return path;
  throw new api.ApiError("invalid", "this repo has an urgent warning (it looks like an attack): the user must review it and forget it in the selfguard app or with `selfguard forget`");
}

const CONTROL = /[\u0000-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩]/;

/** A path argument with no control or bidi characters (nothing to hide in a prompt or a log). */
export function plainPath(path: string): string {
  if (CONTROL.test(path)) throw new api.ApiError("invalid", "the path has control characters");
  return path;
}

/**
 * Watching a folder makes selfguard read (never run) everything below it: an agent may only
 * add a real directory inside the user's home, never a symlink, the home folder or `/`.
 */
export function watchableRoot(path: string): string {
  plainPath(path);
  const abs = resolve(expandHome(path));
  let real: string;
  let home: string;
  try {
    if (lstatSync(abs).isSymbolicLink()) throw new api.ApiError("invalid", `${path} is a symlink: add the real folder`);
    real = realpathSync(abs);
    home = realpathSync(homedir());
  } catch (e) {
    if (e instanceof api.ApiError) throw e;
    throw new api.ApiError("not_found", `not a directory: ${path}`);
  }
  if (real === "/" || real === home) throw new api.ApiError("invalid", "refusing to watch / or the home folder: pick a folder inside it");
  if (!isExcluded(real, [home])) throw new api.ApiError("invalid", "only folders inside the home folder can be added over MCP: the user adds others in the selfguard app or with `selfguard roots add`");
  return path;
}
