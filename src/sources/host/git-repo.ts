/**
 * A repo's `.git/config` (and a worktree's `config.worktree`) and its `.gitmodules`.
 *
 * - `.git/config` can't be shipped by a clone, so a key that runs a program there was written by
 *   something running on this machine (a postinstall, a stealer) or by a tool: git-config-command.
 * - `.gitmodules` is part of the repo, so a malicious one arrives with a clone (the
 *   CVE-2024-32002 family): suspicious-submodule.
 * Messages carry keys and sanitized names only, never URLs or commands.
 */
import { basename } from "node:path";
import type { ExtractResult, SourceWarning } from "../types.ts";
import { commandWarning, safeName } from "./git-commands.ts";
import { parseGitConfig, resolveConfigPath } from "./git-config.ts";
import { gitDirs, leavesRepo } from "./git-dirs.ts";
import { includeWarning, isIncludeEntry } from "./git-include.ts";
import { NONE } from "./fs.ts";

type Warn = Omit<SourceWarning, "file">;

export function extractRepoConfig(file: string, text: string, root: string): ExtractResult {
  const d = gitDirs(root);
  if (!d) return NONE;
  const label = basename(file) === "config.worktree" ? ".git/config.worktree" : ".git/config";
  const out: Warn[] = [];
  for (const e of parseGitConfig(text)) {
    if (out.length >= 30) break;
    if (isIncludeEntry(e)) {
      const w = includeWarning(e, { base: d.commondir, label, repo: { gitDirs: [d.gitdir, d.commondir], root } });
      if (w) out.push(w);
    } else if (e.section === "core" && e.key === "hookspath" && e.value) {
      // Inside the repo it is what husky and friends set: the hooks themselves are checked. A
      // tracked link that leads outside (.githooks -> /tmp/payload) is outside.
      if (leavesRepo(resolveConfigPath(e.value, root), root, d)) {
        out.push({
          rule: "git-hooks-path",
          severity: "moderate",
          notify: true,
          key: "core.hooksPath",
          line: e.line,
          message: `core.hooksPath in ${label} points outside the repo (or to a link that leaves it): whatever is in that folder runs on every commit, checkout or push here. Remove it unless you put it there.`,
        });
      }
    } else {
      const w = commandWarning(e, "repo", label);
      if (w) out.push(w);
    }
  }
  return { refs: [], warnings: out, skipped: 0 };
}

/** A path or name that escapes the checkout or reaches into `.git` (NTFS and HFS+ spellings included). */
function badPath(p: string): string | null {
  const parts = p.split(/[\\/]+/);
  if (p.startsWith("-")) return "starts with a dash";
  if (parts.includes("..")) return "contains ..";
  if (/^(?:\/|[A-Za-z]:)/.test(p)) return "is an absolute path";
  if (parts.some((s) => /^\.git(?:~\d+)?[. ]*$/i.test(s.replace(/[‌-‏‪-‮⁠-⁯﻿]/g, "")))) return "points into .git";
  return null;
}

export function extractSubmodules(text: string): ExtractResult {
  const out: Warn[] = [];
  const checked = new Set<string>();
  for (const e of parseGitConfig(text)) {
    if (out.length >= 30) break;
    if (e.section !== "submodule" || e.sub === null) continue;
    const name = safeName(e.sub);
    const key = `${name}:${e.key}`;
    const base = { rule: "suspicious-submodule", severity: "high" as const, notify: true, key, line: e.line };
    const subject = name === "<name>" ? "a submodule with an unusual name" : `submodule "${name}"`;
    if (e.key === "url") {
      const v = e.value.trimStart();
      if (/^(?:ext|fd)::/i.test(v)) {
        out.push({ ...base, urgent: true, message: `${subject} in .gitmodules uses a transport (ext:: or fd::) that runs a command when git clones it (CVE-2024-32002 style). Don't update submodules of this repo.` });
      } else if (v.startsWith("-")) {
        out.push({ ...base, urgent: true, message: `${subject} in .gitmodules has a URL starting with a dash: git can read it as an option and run a command. Don't update submodules of this repo.` });
      } else if (/^[A-Za-z][A-Za-z0-9+.-]*::/.test(v)) {
        out.push({ ...base, message: `${subject} in .gitmodules uses a remote helper transport (name::), which runs a program named git-remote-<name>. Check it before updating submodules.` });
      }
    } else if (e.key === "path") {
      const why = badPath(e.value);
      if (why) out.push({ ...base, message: `${subject} in .gitmodules has a path that ${why}: submodule paths that leave the checkout or reach into .git are how repos plant hooks. Don't update submodules of this repo.` });
    }
    const nameWhy = checked.has(e.sub) ? null : badPath(e.sub);
    checked.add(e.sub);
    if (nameWhy) {
      out.push({ ...base, key: `${name}:name`, message: `${subject} in .gitmodules has a name that ${nameWhy}: git builds .git/modules/<name> from it (CVE-2024-32002 style). Don't update submodules of this repo.` });
    }
  }
  return { refs: [], warnings: out, skipped: 0 };
}
