/**
 * Git config and hooks (module "git config and hooks", kind "host"), repo scope: a repo's
 * `.git/config`, its hooks and `.gitmodules` (see git-repo.ts and git-hooks.ts; docs/host.md).
 * The machine's global git config is read by config.ts through git-machine.ts. Nothing is run:
 * git folders are found by reading `.git` as data (git-dirs.ts), and listing is bounded, one
 * level, with no walks.
 */
import { dirname, join } from "node:path";
import type { SourceExtractor, SourceTarget } from "../types.ts";
import { exists, NONE } from "./fs.ts";
import { configFiles, gitDirs, hookDirs } from "./git-dirs.ts";
import { extractHook, hookFiles } from "./git-hooks.ts";
import { extractRepoConfig, extractSubmodules } from "./git-repo.ts";

const modules = (root: string): string => join(root, ".gitmodules");

function files(target: SourceTarget): string[] {
  if (target.scope !== "repo") return [];
  const d = gitDirs(target.root);
  return d ? [...configFiles(d), modules(target.root), ...hookFiles(target.root)] : [];
}

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
  extract(file, text, target) {
    if (target.scope !== "repo") return NONE;
    const name = file.slice(dirname(file).length + 1);
    if (name === ".gitmodules") return dirname(file) === target.root ? extractSubmodules(text) : NONE;
    const d = gitDirs(target.root);
    if (d && configFiles(d).includes(file)) return extractRepoConfig(file, text, target.root);
    return extractHook(file, text, target.root);
  },
};
