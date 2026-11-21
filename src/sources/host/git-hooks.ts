/**
 * Git hooks of a repo: executable scripts in `.git/hooks` (and in a `core.hooksPath` folder that
 * is inside the repo, like `.husky`) that git runs on commit, checkout, push… A clone can't ship
 * `.git/hooks`, so a new one is news (low, announced once after the baseline: husky, lefthook and
 * pre-commit install theirs on setup), and one that fetches or decodes code is an attack (high,
 * urgent). Only known hook names are read, one level, regular files; content is read as text
 * with a size cap and is never put in a message.
 */
import { lstatSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { readRegularFile } from "../../fsutil.ts";
import type { ExtractResult } from "../types.ts";
import { names, NONE } from "./fs.ts";
import { gitDirs, hookDirs, insideRepo } from "./git-dirs.ts";
import { FETCH_EXEC } from "./shell.ts";

const HOOKS = new Set(
  `applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg commit-msg post-commit pre-rebase post-checkout post-merge pre-push
pre-receive update proc-receive post-receive post-update reference-transaction push-to-checkout pre-auto-gc post-rewrite sendemail-validate fsmonitor-watchman
post-index-change p4-changelist p4-prepare-changelist p4-post-changelist p4-pre-submit`.split(/\s+/),
);
/** Hook names are validated twice: a known name, and a plain shape (they reach messages). */
const HOOK_NAME = /^[a-z][a-z0-9-]{1,30}$/;
export const isHookName = (n: string): boolean => HOOK_NAME.test(n) && HOOKS.has(n);

const MAX_TEXT = 256 * 1024;
const MAX_LINE = 4000;
/** A payload fetched, decoded or run from a temporary folder: shapes no hook script needs. */
const SUSPICIOUS: RegExp[] = [
  ...FETCH_EXEC,
  /\bbase64\s+(?:-d|-D|--decode)\b/,
  /\b(?:exec|eval)\s*\(\s*(?:__import__|base64|zlib)|\bb64decode\b/,
  /\/dev\/(?:tcp|udp)\//,
  /^\s*(?:exec\s+|nohup\s+)?(?:\/private)?\/(?:tmp|var\/tmp|dev\/shm)\/\S+/,
];

/** The hook files to read: known names in each hooks folder, files or links, one level. */
export function hookFiles(root: string): string[] {
  const d = gitDirs(root);
  if (!d) return [];
  const out: string[] = [];
  for (const dir of hookDirs(root, d)) {
    for (const n of names(dir, 100).filter(isHookName)) {
      try {
        const st = lstatSync(join(dir, n));
        if (st.isFile() || st.isSymbolicLink()) out.push(join(dir, n));
      } catch {
        /* gone */
      }
    }
  }
  return out;
}

const isBinary = (text: string): boolean => text.slice(0, 8000).includes("\0");

/** Do the other hooks of the folder start with a `#!` line (so a binary among them stands out)? */
function peersAreScripts(file: string): boolean {
  const dir = dirname(file);
  return names(dir, 100)
    .filter((n) => isHookName(n) && join(dir, n) !== file)
    .some((n) => readRegularFile(join(dir, n), 2, { nofollow: true, truncate: true })?.data.toString("latin1") === "#!");
}

/** Line (1-based) of the first line that fetches, decodes or runs a dropped payload; 0 for none. */
function suspiciousLine(text: string): number {
  const lines = text.slice(0, MAX_TEXT).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.length > MAX_LINE || (!l.trimStart().startsWith("#") && SUSPICIOUS.some((re) => re.test(l)))) return i + 1;
  }
  return 0;
}

export function extractHook(file: string, text: string, root: string): ExtractResult {
  const name = basename(file);
  const d = gitDirs(root);
  if (!d || !isHookName(name)) return NONE;
  const where = dirname(file) === join(d.commondir, "hooks") ? "in .git/hooks" : "in the core.hooksPath folder";
  const warn = (w: ExtractResult["warnings"][number]): ExtractResult => ({ refs: [], warnings: [w], skipped: 0 });
  let escapes = false;
  try {
    escapes = lstatSync(file).isSymbolicLink() && insideRepo(realpathSync(file), root, d) === null;
  } catch {
    return NONE;
  }
  if (escapes) {
    // A link out of the repo (to a temp folder, a download…): its content isn't ours to read.
    return warn({ rule: "git-hook", severity: "low", notify: true, key: name, line: 0, message: `Git hook "${name}" ${where} is a link to a file outside the repo. It runs on that git event: make sure you know where it points.` });
  }
  const binary = isBinary(text);
  const line = binary ? 0 : suspiciousLine(text);
  if (line > 0 || (binary && peersAreScripts(file))) {
    return warn({
      rule: "suspicious-git-hook",
      severity: "high",
      notify: true,
      urgent: true,
      key: name,
      line,
      message:
        line > 0
          ? `Git hook "${name}" ${where} downloads, decodes or runs hidden code (line ${line}). Malware plants hooks to run again on every git use: delete it and check what installed it.`
          : `Git hook "${name}" ${where} is a compiled program while the other hooks here are scripts. Malware plants hooks to run again on every git use: delete it unless you installed it.`,
    });
  }
  let runnable = false;
  try {
    runnable = (statSync(file).mode & 0o111) !== 0;
  } catch {
    /* gone */
  }
  if (!runnable) return NONE; // git skips a hook that isn't executable
  return warn({
    rule: "git-hook",
    severity: "low",
    notify: true,
    key: name,
    line: 0,
    message: `Git hook "${name}" ${where} runs on that git event${binary ? " (a compiled program)" : ""}. Tools such as husky, lefthook and pre-commit install hooks; remove it if you didn't set it up.`,
  });
}
