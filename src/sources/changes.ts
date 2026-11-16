/**
 * Which sources changed, for `check` (run by the watcher on every lockfile change): no tree
 * walks. A source with a record is checked with what the record holds: the size and mtime of
 * each file (hash when they changed) and the mtime of each marker (the folders new files appear
 * in). Only a changed marker runs that target's files() again. A target without a record is
 * probed with a few stats (its workflow files, the agent config paths); everything else is
 * discovered by sync and scan.
 */
import { activeKinds, sourceExtractors } from "./registry.ts";
import { loadSource, saveSource } from "./store.ts";
import {
  filesFor,
  isFile,
  machineTarget,
  markerStates,
  mtimeOf,
  repoTarget,
  safeList,
  sourceChanged,
  type SourceInput,
} from "./targets.ts";
import type { SourceExtractor, SourceKind, SourceRecord, SourceTarget } from "./types.ts";

/** A marker whose mtime (or existence) differs from the record's; no markers: always. */
export function markersChanged(rec: SourceRecord): boolean {
  if (!Array.isArray(rec.markers)) return true;
  for (const m of rec.markers) {
    if (!m || typeof m.path !== "string") return true;
    if (mtimeOf(m.path) !== (typeof m.mtimeMs === "number" ? m.mtimeMs : null)) return true;
  }
  return false;
}

/** The record's files and the extractors that read each one (all of the kind if unknown). */
function recordedFiles(rec: SourceRecord, extractors: SourceExtractor[]): Map<string, SourceExtractor[]> {
  const out = new Map<string, SourceExtractor[]>();
  for (const f of rec.files) {
    const by = Array.isArray(f.by) ? extractors.filter((ex) => f.by!.includes(ex.id)) : [];
    out.set(f.path, by.length ? by : extractors);
  }
  return out;
}

function changedInput(kind: SourceKind, target: SourceTarget): SourceInput | null {
  const extractors = sourceExtractors(kind);
  const rec = loadSource(kind, target.scope, target.root);
  if (extractors.some((ex) => typeof ex.markers !== "function")) {
    // An extractor without markers: list its files every time, as before markers existed.
    const found = filesFor(kind, target);
    const files = [...found.keys()];
    if (files.length === 0 && !rec) return null;
    return sourceChanged(rec, files) ? { kind, target, files: found } : null;
  }
  if (!rec) {
    const probed = extractors.some((ex) => safeList(() => ex.probe?.(target) ?? []).some(isFile));
    if (!probed) return null;
    const found = filesFor(kind, target);
    return found.size > 0 ? { kind, target, files: found } : null;
  }
  if (!markersChanged(rec)) {
    return sourceChanged(rec, rec.files.map((f) => f.path)) ? { kind, target, files: recordedFiles(rec, extractors) } : null;
  }
  // A file may have appeared or gone: list them again (this target only).
  const found = filesFor(kind, target);
  const files = [...found.keys()];
  if (sourceChanged(rec, files)) return { kind, target, files: found };
  // Same files: remember the markers' new mtimes so the next check doesn't list them again.
  saveSource({ ...rec, markers: markerStates(kind, target, files) });
  return null;
}

/**
 * Sources whose files changed, for these git roots (and this machine's agent configs with
 * `machine`). Records whose markers moved without a file change get their markers updated.
 */
export function changedSourceInputs(roots: string[], opts: { machine?: boolean } = {}): SourceInput[] {
  const targets = [...new Set(roots)].map(repoTarget);
  if (opts.machine) targets.push(machineTarget());
  const out: SourceInput[] = [];
  for (const kind of activeKinds()) {
    for (const target of targets) {
      const input = changedInput(kind, target);
      if (input) out.push(input);
    }
  }
  return out;
}
