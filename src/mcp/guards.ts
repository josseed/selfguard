/**
 * What MCP tools refuse on their own: an agent may be following text from the repo or host it is
 * warned about (prompt injection), so it can't silence what looks like an attack.
 */
import { resolve } from "node:path";
import * as api from "../api.ts";
import { isExcluded, normalizeDir } from "../config.ts";
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
