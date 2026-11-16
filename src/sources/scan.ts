/**
 * Scan CI workflows and agent configs: extract references (files read as data), ask OSV in
 * the same deduplicated batch as lockfiles, evaluate locally, keep warnings apart.
 */
import { SUPPORTED_ECOSYSTEMS } from "../lockfile/types.ts";
import type { PackageQuery } from "../osv.ts";
import { clean } from "../sanitize.ts";
import { lookup, type Lookup } from "../scan/lookup.ts";
import { updateSeen } from "../scan.ts";
import { findingKey } from "../store.ts";
import { buildSourceFindings, queryFor } from "./findings.ts";
import { loadSource } from "./store.ts";
import { fileState, filesFor, type SourceInput } from "./targets.ts";
import type { ExtractResult, SourceFinding, SourceRecord, SourceRef, SourceWarning } from "./types.ts";

export interface SourceOutcome {
  record: SourceRecord;
  newFindings: SourceFinding[];
  resolvedFindings: SourceFinding[];
  firstScan: boolean;
}

export interface SourceInventory {
  record: SourceRecord;
  previous: SourceRecord | null;
}

const MAX_REFS = 5000;
const MAX_WARNINGS = 1000;
const SEVERITIES = new Set(["high", "moderate", "low"]);
const VERSION_KINDS = new Set(["exact", "line", "unknown"]);

const opt = (v: unknown, n: number): string | undefined => (typeof v === "string" && v.trim() ? clean(v, n) : undefined);
const lineOf = (v: unknown): number => (typeof v === "number" && Number.isSafeInteger(v) && v > 0 ? v : 0);

/** Extractor output is checked and sanitized: it comes from files anyone could have written. */
function cleanRef(r: ExtractResult["refs"][number], file: string): SourceRef | null {
  if (!r || !(SUPPORTED_ECOSYSTEMS as readonly unknown[]).includes(r.ecosystem) || !VERSION_KINDS.has(r.versionKind)) return null;
  const name = opt(r.name, 214);
  if (!name) return null;
  const raw = r.versionKind === "exact" ? (opt(r.version, 64) ?? null) : null;
  // Action tags are written "v4.1.0"; OSV ranges and our keys use "4.1.0".
  const version = raw && r.ecosystem === "GitHub Actions" ? raw.replace(/^v(?=\d)/, "") : raw;
  const lineOfRef = r.versionKind === "line" && typeof r.lineOf === "string" && /^v?\d+(\.\d+)?$/.test(r.lineOf) ? r.lineOf.replace(/^v/, "") : undefined;
  const ref: SourceRef = {
    ecosystem: r.ecosystem,
    name,
    version,
    versionKind: r.versionKind === "exact" && !version ? "unknown" : r.versionKind === "line" && !lineOfRef ? "unknown" : r.versionKind,
    file,
    line: lineOf(r.line),
  };
  if (lineOfRef && ref.versionKind === "line") ref.lineOf = lineOfRef;
  for (const [k, n] of [["pin", 64], ["agent", 64], ["server", 120], ["launcher", 32]] as const) {
    const v = opt(r[k], n);
    if (v) ref[k] = v;
  }
  return ref;
}

function cleanWarning(w: ExtractResult["warnings"][number], file: string): SourceWarning | null {
  const rule = opt(w?.rule, 64);
  const message = opt(w?.message, 300);
  if (!rule || !message) return null;
  return { rule, message, file, line: lineOf(w.line), severity: SEVERITIES.has(w.severity) ? w.severity : "low" };
}

function inventory(input: SourceInput, now: string): SourceInventory {
  const { kind, target } = input;
  const previous = loadSource(kind, target.scope, target.root);
  const record: SourceRecord = {
    schema: 1,
    kind,
    scope: target.scope,
    path: target.root,
    registeredAt: previous?.registeredAt ?? now,
    scannedAt: null,
    files: [],
    refs: [],
    findings: [],
    warnings: [],
    skipped: 0,
  };
  for (const [file, extractors] of filesFor(kind, target)) {
    const read = fileState(file);
    if (!read) continue;
    record.files.push(read.state);
    for (const ex of extractors) {
      let res: ExtractResult;
      try {
        res = ex.extract(file, read.text, target);
      } catch (err) {
        record.warnings.push({ rule: "unreadable", message: `could not read: ${clean((err as Error).message, 200)}`, file, line: 0, severity: "low" });
        continue;
      }
      for (const r of Array.isArray(res?.refs) ? res.refs : []) {
        const ref = cleanRef(r, file);
        if (ref && record.refs.length < MAX_REFS) record.refs.push(ref);
      }
      for (const w of Array.isArray(res?.warnings) ? res.warnings : []) {
        const warning = cleanWarning(w, file);
        if (warning && record.warnings.length < MAX_WARNINGS) record.warnings.push(warning);
      }
      if (typeof res?.skipped === "number" && Number.isSafeInteger(res.skipped) && res.skipped > 0) record.skipped += res.skipped;
    }
  }
  return { record, previous };
}

/** Read the sources and list what to ask OSV (to batch with lockfiles). */
export function prepareSources(inputs: SourceInput[], now = new Date().toISOString()): { inventories: SourceInventory[]; queries: PackageQuery[] } {
  const inventories = inputs.map((i) => inventory(i, now));
  return { inventories, queries: inventories.flatMap((i) => i.record.refs.map(queryFor)) };
}

export function finishSources(inventories: SourceInventory[], found: Lookup, now = new Date().toISOString()): SourceOutcome[] {
  return inventories.map(({ record, previous }) => {
    if (found.error && record.refs.length > 0) {
      // Keep the last known findings rather than pretending everything is fine.
      record.error = found.error;
      record.findings = previous?.findings ?? [];
      record.scannedAt = previous?.scannedAt ?? null;
      record.seen = previous?.seen ?? {};
      return { record, newFindings: [], resolvedFindings: [], firstScan: previous === null };
    }
    record.findings = buildSourceFindings(record.refs, found, previous, now);
    record.scannedAt = now;
    const before = new Set((previous?.findings ?? []).map(findingKey));
    const history = previous?.seen ?? {};
    const newFindings = record.findings.filter((f) => !before.has(findingKey(f)) && !Object.hasOwn(history, findingKey(f)));
    const after = new Set(record.findings.map(findingKey));
    const resolvedFindings = previous ? previous.findings.filter((f) => !after.has(findingKey(f))) : [];
    record.seen = updateSeen(previous, record.findings, now);
    return { record, newFindings, resolvedFindings, firstScan: previous === null };
  });
}

/** Scan sources on their own (one OSV batch). Records are returned, not saved. */
export async function scanSources(inputs: SourceInput[]): Promise<SourceOutcome[]> {
  const { inventories, queries } = prepareSources(inputs);
  return finishSources(inventories, await lookup(queries));
}
