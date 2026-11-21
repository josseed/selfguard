/**
 * Hidden Unicode in an installed editor extension's entry point (GlassWorm hides its loader in
 * runs of invisible characters). Only the `main` and `browser` files named by package.json are
 * read, as data, and only if they resolve inside the extension's own folder (no `..`, no symlink
 * leading out, regular files, size caps). Reuses the detector of agentguard/unicode.ts.
 */
import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import { isObject, readRegularFile } from "../../fsutil.ts";
import { hiddenUnicode } from "../agentguard/unicode.ts";

export const MAX_PACKAGE_JSON = 1024 * 1024;
/** Bytes read from the start of an entry point (bundles are 100 KB to a few MB), and from its end if larger. */
export const MAX_ENTRY_BYTES = 5 * 1024 * 1024;
export const TAIL_BYTES = 1024 * 1024;
/** Characters the detector looks for; a file without any skips the (memory-hungry) detector. */
const SUSPECT = /[​-‍⁠﻿‪-‮⁦-⁩︀-️\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/u;

/** A folder name directly inside `root`, from untrusted data: one plain segment. */
export function extensionFolder(root: string, name: unknown): string | null {
  if (typeof name !== "string" || !name || name.length > 200 || /[\\/\0]/.test(name) || name.startsWith(".")) return null;
  return join(root, name);
}

const inside = (base: string, path: string): boolean => {
  const rel = relative(base, path);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel) && !rel.split(sep).includes("..");
};

/** The entry file `spec` names, if it is a regular file inside the realpath `base`; else null. */
function entryFile(base: string, spec: unknown): string | null {
  if (typeof spec !== "string" || !spec || spec.length > 300 || spec.includes("\0") || isAbsolute(spec)) return null;
  for (const candidate of [spec, `${spec}.js`]) {
    const path = join(base, candidate);
    if (!inside(base, path)) return null;
    try {
      const real = realpathSync(path);
      if (inside(base, real) && lstatSync(real).isFile()) return real;
    } catch {
      // missing: try the next candidate
    }
  }
  return null;
}

/** How a scan of one extension ended: what was found and how many bytes were read. */
export interface CodeScan {
  /** Plain descriptions of the problems (empty: clean or unreadable). */
  problems: string[];
  bytes: number;
}

const WHAT: Record<string, string> = {
  tags: "invisible Unicode tag characters",
  bidi: "bidirectional control characters",
  invisible: "invisible characters (zero-width or variation selectors) in long runs or encoding hidden text",
};

/**
 * What to read of a file of `size` bytes with `allow` bytes to spend: all of it when it fits,
 * else its start and its end (padding a file past the limit can't hide a payload at either).
 */
export function readPlan(size: number, allow: number): { head: number; tail: number } {
  if (size <= Math.min(MAX_ENTRY_BYTES, allow)) return { head: size, tail: 0 };
  const tail = Math.min(TAIL_BYTES, Math.floor(allow / 4), size);
  const head = Math.min(MAX_ENTRY_BYTES, allow - tail, size - tail);
  return { head, tail };
}

function problemsIn(text: string, out: CodeScan): void {
  if (!SUSPECT.test(text)) return;
  for (const w of hiddenUnicode(text)) {
    // Only what looks deliberate (the detector's "high"): tags, bidi, long or decoding runs.
    const what = w.severity === "high" ? WHAT[w.key ?? ""] : undefined;
    if (what && !out.problems.includes(what)) out.problems.push(what);
  }
}

/** Scan the entry points of the extension in `dir`, spending at most about `budget` bytes. Never throws. */
export function scanExtensionCode(dir: string, budget: number): CodeScan {
  const out: CodeScan = { problems: [], bytes: 0 };
  try {
    if (!lstatSync(dir).isDirectory()) return out;
    const base = realpathSync(dir);
    const pkg = readRegularFile(join(base, "package.json"), MAX_PACKAGE_JSON, { nofollow: true });
    if (!pkg) return out;
    const json: unknown = JSON.parse(pkg.data.toString("utf8"));
    if (!isObject(json)) return out;
    const files = new Set([entryFile(base, json.main), entryFile(base, json.browser)]);
    for (const file of files) {
      const allow = budget - out.bytes;
      if (!file || allow <= 0) continue;
      const size = lstatSync(file).size;
      const plan = readPlan(size, allow);
      const head = readRegularFile(file, plan.head, { nofollow: true, truncate: true });
      if (!head) continue;
      out.bytes += head.data.length;
      problemsIn(head.data.toString("utf8"), out);
      if (plan.tail > 0) {
        const tail = readRegularFile(file, plan.tail, { nofollow: true, truncate: true, fromEnd: true });
        if (tail) (out.bytes += tail.data.length, problemsIn(tail.data.toString("utf8"), out));
      }
    }
  } catch {
    // unreadable or malformed: nothing to report
  }
  return out;
}
