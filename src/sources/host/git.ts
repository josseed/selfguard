/**
 * Git config and hooks (module "git config and hooks", kind "host"), repo scope: a repo's
 * `.git/config`, its hooks and `.gitmodules` (see git-repo.ts and git-hooks.ts; docs/host.md).
 * The machine's global git config is read by config.ts through git-machine.ts. Nothing is run:
 * git folders are found by reading `.git` as data (git-dirs.ts), and listing is bounded, one
 * level, with no walks.
 */
import { realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ExtractResult, SourceExtractor, SourceTarget } from "../types.ts";
import { exists, NONE } from "./fs.ts";
import { configFiles, gitDirs, hookDirs, hookLinks, insideRepo } from "./git-dirs.ts";
import { extractHook, hookFiles } from "./git-hooks.ts";
import { extractRepoConfig, extractSubmodules } from "./git-repo.ts";

const modules = (root: string): string => join(root, ".gitmodules");

function files(target: SourceTarget): string[] {
  if (target.scope !== "repo") return [];
  const d = gitDirs(target.root);
  // A hooks folder that leads outside the repo is listed too: the core records the link itself,
  // so retargeting it is noticed (see linkOut) and `.git/hooks` -> elsewhere is reported.
  return d ? [...configFiles(d), modules(target.root), ...hookFiles(target.root), ...hookLinks(target.root, d).map((l) => l.dir)] : [];
}

/** A file (or folder) of the repo that is a link out of it: never opened, only reported. */
function linkOut(file: string, target: SourceTarget): boolean {
  const d = target.scope === "repo" ? gitDirs(target.root) : null;
  if (!d) return false;
  try {
    realpathSync(file);
  } catch {
    return false;
  }
  return insideRepo(file, target.root, d) === null;
}

const warnLink = (rule: string, key: string, message: string, urgent = false): ExtractResult => ({
  refs: [],
  warnings: [{ rule, severity: "high", notify: true, ...(urgent ? { urgent: true } : {}), key, line: 0, message }],
  skipped: 0,
});

/** Paths whose mtime changes when files() would find another file: no folder that git itself touches on every command. */
function markers(target: SourceTarget): string[] {
  if (target.scope !== "repo") return [];
  const d = gitDirs(target.root);
  if (!d) return [join(target.root, ".git")];
  return [...new Set([join(target.root, ".git"), ...configFiles(d), modules(target.root), join(d.commondir, "hooks"), ...hookDirs(target.root, d)])].filter(
    (p) => p !== d.gitdir && p !== d.commondir,
  );
}

export const GIT_CONFIG_AND_HOOKS: SourceExtractor = {
  id: "git-config-and-hooks",
  kind: "host",
  files,
  markers,
  probe: (target) => (target.scope === "repo" ? [join(target.root, ".git", "config"), modules(target.root)] : []),
  watch: (target) => markers(target).filter(exists),
  linkOut,
  extract(file, text, target) {
    if (target.scope !== "repo") return NONE;
    const name = file.slice(dirname(file).length + 1);
    const d = gitDirs(target.root);
    const folder = d ? hookLinks(target.root, d).find((l) => l.dir === file) : undefined;
    // `.git/hooks` replaced by a link out of the repo; a core.hooksPath one is reported with the config.
    if (folder) {
      return folder.via === "hooks"
        ? warnLink("suspicious-git-hook", "hooks", "The .git/hooks folder is a link to a folder outside the repo: whatever is in there runs on every commit, checkout or push here. Replace it with a real folder and check what planted it.", true)
        : NONE;
    }
    if (name === ".gitmodules") {
      if (dirname(file) !== target.root) return NONE;
      return linkOut(file, target)
        ? warnLink("suspicious-submodule", ".gitmodules:link", ".gitmodules is a link to a file outside the repo, so it was not read. Don't update submodules of this repo until you know where it points.")
        : extractSubmodules(text);
    }
    if (d && configFiles(d).includes(file)) {
      return linkOut(file, target)
        ? warnLink("git-config-command", `${name}:link`, `${name === "config" ? ".git/config" : ".git/config.worktree"} is a link to a file outside the repo, so it was not read: settings there can run programs on normal git use. Remove the link unless you made it.`)
        : extractRepoConfig(file, text, target.root);
    }
    return extractHook(file, text, target.root);
  },
};
