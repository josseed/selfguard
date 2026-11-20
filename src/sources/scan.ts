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
import { buildSourceFindings, queryFor, refVersion } from "./findings.ts";
import { loadSource } from "./store.ts";
import { diffWarnings } from "./warnings.ts";
import { VERSION } from "../version.ts";
import { fileState, filesFor, markerStates, type SourceInput } from "./targets.ts";
import type { ExtractResult, SourceFinding, SourceRecord, SourceRef, SourceWarning, UnknownKind } from "./types.ts";

export interface SourceOutcome {
  record: SourceRecord;
  newFindings: SourceFinding[];
  resolvedFindings: SourceFinding[];
  /** Warnings that appeared since the last scan (never on a first scan; see sources/warnings.ts). */
  newWarnings: SourceWarning[];
  resolvedWarnings: SourceWarning[];
  firstScan: boolean;
}

export interface SourceInventory {
  record: SourceRecord;
  previous: SourceRecord | null;
  /** Same references as the last (recent, successful) scan: no OSV query, findings kept. */
  reuse?: boolean;
}

/** How long a successful scan is reused while the references don't change. */
export const REUSE_MS = 24 * 60 * 60 * 1000;

const MAX_REFS = 5000;
const MAX_WARNINGS = 1000;
const SEVERITIES = new Set(["high", "moderate", "low"]);
const VERSION_KINDS = new Set(["exact", "line", "unknown"]);
const UNKNOWN_KINDS = new Set(["tracks-latest", "fixed-unknown"]);
const RELEASE = /^\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.+-]+)?$/;

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
  if (ref.versionKind === "unknown") {
    if (UNKNOWN_KINDS.has(r.unknownKind as string)) ref.unknownKind = r.unknownKind as UnknownKind;
    const lastRun = opt(r.lastRun, 64);
    if (lastRun && RELEASE.test(lastRun)) ref.lastRun = lastRun;
  }
  return ref;
}

function cleanWarning(w: ExtractResult["warnings"][number], file: string): SourceWarning | null {
  const rule = opt(w?.rule, 64);
  const message = opt(w?.message, 300);
  if (!rule || !message) return null;
  const out: SourceWarning = { rule, message, file, line: lineOf(w.line), severity: SEVERITIES.has(w.severity) ? w.severity : "low" };
  const key = opt(w.key, 120);
  if (key) out.key = key;
  if (w.notify === true) out.notify = true;
  return out;
}

/** What a scan depends on: each reference's package and version, not where it is written. */
export function refsSignature(refs: SourceRef[]): string {
  const keys = refs.map((r) => [r.ecosystem, r.name, r.versionKind, r.version ?? "", r.lineOf ?? "", r.pin ?? "", r.unknownKind ?? "", r.lastRun ?? ""].join("|"));
  return JSON.stringify([...new Set(keys)].sort());
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
  for (const [file, extractors] of input.files ?? filesFor(kind, target)) {
    const read = fileState(file);
    if (!read) continue;
    record.files.push({ ...read.state, by: extractors.map((ex) => ex.id) });
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
  const markers = markerStates(kind, target, record.files.map((f) => f.path));
  if (markers) record.markers = markers;
  return { record, previous };
}

/**
 * Read the sources and list what to ask OSV (to batch with lockfiles). With `reuseRecent`
 * (the watcher's check), a source whose references are those of its last successful scan,
 * less than REUSE_MS ago, isn't queried: its findings are kept, its file states updated.
 */
export function prepareSources(
  inputs: SourceInput[],
  now = new Date().toISOString(),
  opts: { reuseRecent?: boolean } = {},
): { inventories: SourceInventory[]; queries: PackageQuery[] } {
  const inventories = inputs.map((i) => inventory(i, now));
  for (const inv of inventories) {
    const p = inv.previous;
    if (!opts.reuseRecent || !p?.scannedAt || p.error) continue;
    const age = Date.parse(now) - Date.parse(p.scannedAt);
    if (age >= 0 && age < REUSE_MS && refsSignature(p.refs) === refsSignature(inv.record.refs)) inv.reuse = true;
  }
  return { inventories, queries: inventories.filter((i) => !i.reuse).flatMap((i) => i.record.refs.map(queryFor)) };
}

/** Previous findings, located with the current references (lines may have moved). */
function relocate(findings: SourceFinding[], refs: SourceRef[]): SourceFinding[] {
  return findings.map((f) => {
    const locations = refs
      .filter((r) => r.name === f.name && r.ecosystem === (f.ecosystem ?? "npm") && refVersion(r) === f.version)
      .map((r) => ({ file: r.file, line: r.line }));
    return locations.length ? { ...f, locations: locations.slice(0, 50) } : f;
  });
}

export function finishSources(inventories: SourceInventory[], found: Lookup, now = new Date().toISOString()): SourceOutcome[] {
  return inventories.map(({ record, previous, reuse }) => {
    // Warnings come from the files just read, whatever happens with OSV below.
    const { newWarnings, resolvedWarnings, warningSeen } = diffWarnings(record, previous, now);
    record.warningSeen = warningSeen;
    record.warningsBy = VERSION;
    const warned = { newWarnings, resolvedWarnings };
    if (reuse && previous) {
      record.findings = relocate(previous.findings, record.refs);
      record.scannedAt = previous.scannedAt;
      record.seen = previous.seen ?? {};
      return { record, newFindings: [], resolvedFindings: [], ...warned, firstScan: false };
    }
    const actions = record.refs.some((r) => r.ecosystem === "GitHub Actions");
    const error = found.error ?? (actions ? found.ghaError : undefined);
    if (error && record.refs.length > 0) {
      // Keep the last known findings rather than pretending everything is fine, and the last
      // file states so that the next check retries.
      record.error = error;
      record.files = previous?.files ?? [];
      if (previous?.markers) record.markers = previous.markers;
      else delete record.markers;
      record.findings = previous?.findings ?? [];
      record.scannedAt = previous?.scannedAt ?? null;
      record.seen = previous?.seen ?? {};
      return { record, newFindings: [], resolvedFindings: [], ...warned, firstScan: previous === null };
    }
    record.findings = buildSourceFindings(record.refs, found, previous, now);
    record.scannedAt = now;
    const before = new Set((previous?.findings ?? []).map(findingKey));
    const history = previous?.seen ?? {};
    // A first scan is a baseline, like a machine's first sync: only malicious findings are news.
    const newFindings = record.findings.filter(
      (f) => !before.has(findingKey(f)) && !Object.hasOwn(history, findingKey(f)) && (previous !== null || f.severity === "malicious"),
    );
    const after = new Set(record.findings.map(findingKey));
    const resolvedFindings = previous ? previous.findings.filter((f) => !after.has(findingKey(f))) : [];
    record.seen = updateSeen(previous, record.findings, now);
    return { record, newFindings, resolvedFindings, ...warned, firstScan: previous === null };
  });
}

/** Scan sources on their own (one OSV batch). Records are returned, not saved. */
export async function scanSources(inputs: SourceInput[], opts: { reuseRecent?: boolean } = {}): Promise<SourceOutcome[]> {
  const { inventories, queries } = prepareSources(inputs, new Date().toISOString(), opts);
  return finishSources(inventories, await lookup(queries));
}
