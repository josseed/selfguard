/** Which files each source reads, and whether they changed since the last scan. */
import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { sha256 } from "../fsutil.ts";
import { activeKinds, sourceExtractors } from "./registry.ts";
import { loadSource } from "./store.ts";
import type { SourceExtractor, SourceFileState, SourceKind, SourceRecord, SourceTarget } from "./types.ts";

export const MAX_SOURCE_FILES = 200;
/** Agent configs such as ~/.claude.json grow with history: allow a few MB. */
export const MAX_SOURCE_BYTES = 16 * 1024 * 1024;

export interface SourceInput {
  kind: SourceKind;
  target: SourceTarget;
}

export const machineTarget = (): SourceTarget => ({ scope: "machine", root: homedir() });
export const repoTarget = (root: string): SourceTarget => ({ scope: "repo", root });

/** The git root around a folder (the folder holding `.git`, a directory or a worktree pointer). */
export function gitRootOf(dir: string): string | null {
  const home = homedir();
  let cur = resolve(dir);
  for (let i = 0; i < 40; i++) {
    try {
      statSync(join(cur, ".git"));
      return cur;
    } catch {
      /* not here */
    }
    const parent = dirname(cur);
    if (parent === cur || cur === home) return null;
    cur = parent;
  }
  return null;
}

function isFile(path: string): boolean {
  try {
    const st = statSync(path);
    return st.isFile() && st.size <= MAX_SOURCE_BYTES;
  } catch {
    return false;
  }
}

function safeList(fn: () => string[]): string[] {
  try {
    const list = fn();
    return Array.isArray(list) ? list.filter((p): p is string => typeof p === "string" && isAbsolute(p)) : [];
  } catch {
    return [];
  }
}

/** Existing files of a kind for a target, and which extractors read each one. */
export function filesFor(kind: SourceKind, target: SourceTarget): Map<string, SourceExtractor[]> {
  const out = new Map<string, SourceExtractor[]>();
  for (const ex of sourceExtractors(kind)) {
    for (const f of safeList(() => ex.files(target))) {
      if (out.size >= MAX_SOURCE_FILES && !out.has(f)) break;
      if (!out.has(f) && !isFile(f)) continue;
      out.set(f, [...(out.get(f) ?? []), ex]);
    }
  }
  return out;
}

/** Paths for the background watcher: each extractor's watch() (default: its existing files). */
export function watchPathsFor(target: SourceTarget): string[] {
  const out = new Set<string>();
  for (const ex of sourceExtractors()) {
    const list = ex.watch ? safeList(() => ex.watch!(target)) : safeList(() => ex.files(target)).filter(isFile);
    for (const p of list) out.add(p);
  }
  return [...out];
}

export function fileState(path: string): { state: SourceFileState; text: string } | null {
  try {
    const st = statSync(path);
    if (!st.isFile() || st.size > MAX_SOURCE_BYTES) return null;
    const buf = readFileSync(path);
    return { state: { path, size: st.size, mtimeMs: st.mtimeMs, hash: sha256(buf) }, text: buf.toString("utf8") };
  } catch {
    return null;
  }
}

/** Cheap check first (file set, mtime and size), hash only when those changed. */
export function sourceChanged(rec: SourceRecord | null, files: string[]): boolean {
  if (!rec) return files.length > 0;
  if (rec.files.length !== files.length) return true;
  const known = new Map(rec.files.map((f) => [f.path, f]));
  for (const path of files) {
    const prev = known.get(path);
    if (!prev) return true;
    try {
      const st = statSync(path);
      if (st.mtimeMs === prev.mtimeMs && st.size === prev.size) continue;
    } catch {
      return true;
    }
    if (fileState(path)?.state.hash !== prev.hash) return true;
  }
  return false;
}

/**
 * Sources to scan for these git roots (and the machine-wide config when `machine`): those
 * with files, or with a record from before (their files may have gone). `onlyChanged` keeps
 * the ones whose files changed. Empty when no extractor is registered.
 */
export function sourceInputs(roots: string[], opts: { machine?: boolean; onlyChanged?: boolean } = {}): SourceInput[] {
  const targets = [...new Set(roots)].map(repoTarget);
  if (opts.machine) targets.push(machineTarget());
  const out: SourceInput[] = [];
  for (const kind of activeKinds()) {
    for (const target of targets) {
      const files = [...filesFor(kind, target).keys()];
      const rec = loadSource(kind, target.scope, target.root);
      if (files.length === 0 && !rec) continue;
      if (opts.onlyChanged && !sourceChanged(rec, files)) continue;
      out.push({ kind, target });
    }
  }
  return out;
}
