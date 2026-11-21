/**
 * `include.path` and `includeIf.<condition>.path`: git reads more settings from another file.
 * Usual: a file under your home folder (a work or personal profile). Odd: a file in a temporary
 * or shared folder or another user's folder, or (for a repo) outside the repo. The path itself
 * is never printed, only the file's sanitized name.
 */
import { homedir } from "node:os";
import { basename } from "node:path";
import type { SourceWarning } from "../types.ts";
import { resolveConfigPath, within, type GitEntry } from "./git-config.ts";

type Warn = Omit<SourceWarning, "file">;

const TEMP_PATH = /^(?:\/private)?\/(?:tmp|var\/tmp)\/|^\/dev\/shm\/|^\/Users\/Shared\/|\/Downloads\//;

/** A file name for messages: a plain one (dotfiles included) or a fixed phrase. */
const shownFile = (n: string): string => (/^[A-Za-z0-9._][A-Za-z0-9._+-]{0,39}$/.test(n) ? n : "a file with an unusual name");

export const isIncludeEntry = (e: GitEntry): boolean => e.key === "path" && (e.section === "include" || e.section === "includeif");

interface Where {
  /** Folder relative paths are resolved against (the config file's own folder). */
  base: string;
  /** Message wording: "global git config", ".git/config". */
  label: string;
  /** Repo scope: the git folders (quiet) and the work tree (low). Machine scope: absent. */
  repo?: { gitDirs: string[]; root: string };
}

export function includeWarning(e: GitEntry, w: Where): Warn | null {
  const path = resolveConfigPath(e.value, w.base);
  if (!path) return null;
  // A path in the repo or the home folder is judged by where it sits there, even when that folder
  // itself is in a temporary one (a clone in /tmp, a test home).
  const inside = within(path, w.repo ? w.repo.root : homedir());
  const temp = !inside && !within(path, homedir()) && TEMP_PATH.test(path);
  const name = shownFile(basename(path));
  const setting = e.section === "include" ? "include.path" : "includeIf.path";
  const common = { rule: "git-config-include", key: `${setting} ${name}`, line: e.line };
  if (w.repo) {
    if (w.repo.gitDirs.some((d) => within(path, d))) return null;
    if (inside) {
      return { ...common, severity: "low", message: `${setting} in ${w.label} loads settings from a file inside the repo (${name}). Its commands run on your git use: review that file.` };
    }
  } else if (inside) return null;
  const place = temp ? "a temporary or shared folder" : w.repo ? "outside the repo" : "outside your home folder";
  return {
    ...common,
    severity: "moderate",
    notify: true,
    message: `${setting} in ${w.label} loads settings from ${place} (${name}). Whatever that file sets applies to your git use: remove it unless you put it there.`,
  };
}
