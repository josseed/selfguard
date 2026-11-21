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
/** One entry point larger than this is skipped (bundles are 100 KB to a few MB). */
export const MAX_ENTRY_BYTES = 5 * 1024 * 1024;
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

/** Scan the entry points of the extension in `dir`. Never throws. */
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
      if (!file || out.bytes >= budget) continue;
      const raw = readRegularFile(file, MAX_ENTRY_BYTES, { nofollow: true });
      if (!raw) continue;
      out.bytes += raw.data.length;
      const text = raw.data.toString("utf8");
      if (!SUSPECT.test(text)) continue;
      for (const w of hiddenUnicode(text)) {
        // Only what looks deliberate (the detector's "high"): tags, bidi, long or decoding runs.
        const what = w.severity === "high" ? WHAT[w.key ?? ""] : undefined;
        if (what && !out.problems.includes(what)) out.problems.push(what);
      }
    }
  } catch {
    // unreadable or malformed: nothing to report
  }
  return out;
}
