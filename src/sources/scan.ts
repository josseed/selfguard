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
import { fileState, FileSet, filesFor, linksOut, markerStates, MAX_SOURCE_FILES, type SourceInput } from "./targets.ts";
import { sourceExtractors } from "./registry.ts";
import { SNAPSHOT_FILE, TRUNCATED_FILE, type ExtractResult, type SourceFinding, type SourceRecord, type SourceRef, type SourceWarning, type UnknownKind } from "./types.ts";

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
  const message = opt(w?.message, 600);
  if (!rule || !message) return null;
  const out: SourceWarning = { rule, message, file, line: lineOf(w.line), severity: SEVERITIES.has(w.severity) ? w.severity : "low" };
  const key = opt(w.key, 120);
  if (key) out.key = key;
  if (w.notify === true) out.notify = true;
  if (w.urgent === true) out.urgent = out.notify = true;
  return out;
}

/** What a scan depends on: each reference's package and version, not where it is written. */
export function refsSignature(refs: SourceRef[]): string {
  const keys = refs.map((r) => [r.ecosystem, r.name, r.versionKind, r.version ?? "", r.lineOf ?? "", r.pin ?? "", r.unknownKind ?? "", r.lastRun ?? ""].join("|"));
  return JSON.stringify([...new Set(keys)].sort());
}

/** How long the last snapshot's warnings are kept when a new one can't be taken. */
export const SNAPSHOT_KEEP_MS = 7 * 24 * 60 * 60 * 1000;

type Add = (w: SourceWarning) => void;

/**
 * Live state (SourceExtractor.snapshot): taken when the input asks for it (sync, scan). On
 * `check`, or when a snapshot fails, the last snapshot's warnings are kept (on a failure only
 * for SNAPSHOT_KEEP_MS since the last good one), so a partial re-read never "resolves" them
 * and a permanently broken reader doesn't leave stale warnings forever. An extractor that
 * returns nothing (disabled, unsupported) is a good snapshot: its warnings resolve.
 */
function addSnapshots(record: SourceRecord, previous: SourceRecord | null, input: SourceInput, now: string, add: Add): void {
  let kept = false;
  const keep = (): void => {
    if (kept) return;
    kept = true;
    const have = new Set(record.warnings.map((w) => `${w.rule}|${w.key ?? ""}|${w.file}`));
    for (const w of previous?.warnings ?? []) if (w.file === SNAPSHOT_FILE && !have.has(`${w.rule}|${w.key ?? ""}|${w.file}`)) add(w);
  };
  const last = previous?.snapshotAt;
  if (last) record.snapshotAt = last;
  if (!input.snapshot) return keep();
  for (const ex of sourceExtractors(input.kind)) {
    if (typeof ex.snapshot !== "function") continue;
    try {
      const res = ex.snapshot(input.target);
      for (const w of res?.warnings ?? []) {
        const warning = cleanWarning(w, SNAPSHOT_FILE);
        if (warning) add(warning);
      }
      record.snapshotAt = now;
    } catch {
      const age = Date.parse(now) - Date.parse(last ?? previous?.scannedAt ?? "");
      if (!Number.isFinite(age) || age < SNAPSHOT_KEEP_MS) keep();
    }
  }
}

const rank = (w: SourceWarning): number => (w.urgent ? 0 : w.severity === "high" ? 1 : w.severity === "moderate" ? 2 : 3);

/** At most MAX_WARNINGS: urgent first, then by severity; one `truncated` warning says how many went. */
function capWarnings(record: SourceRecord, overflow: number): void {
  const list = record.warnings;
  if (list.length + overflow <= MAX_WARNINGS) return;
  const kept = list
    .map((w, i) => ({ i, r: rank(w) }))
    .sort((a, b) => a.r - b.r || a.i - b.i)
    .slice(0, MAX_WARNINGS - 1)
    .map((x) => x.i)
    .sort((a, b) => a - b);
  const dropped = list.length - kept.length + overflow;
  record.warnings = [
    ...kept.map((i) => list[i]!),
    { rule: "truncated", key: "warnings", severity: "low", file: TRUNCATED_FILE, line: 0, message: `${dropped} more warnings were not kept (limit ${MAX_WARNINGS} per source). The urgent and most severe ones are listed first.` },
  ];
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
  // Warnings are collected past the limit and cut by importance at the end, not in file order.
  let overflow = 0;
  const add: Add = (w) => {
    if (record.warnings.length < MAX_WARNINGS * 10) record.warnings.push(w);
    else overflow++;
  };
  const files = input.files ?? filesFor(kind, target);
  for (const [file, extractors] of files) {
    const read = fileState(file, linksOut(file, target, extractors));
    if (!read) continue;
    record.files.push({ ...read.state, by: extractors.map((ex) => ex.id) });
    for (const ex of extractors) {
      let res: ExtractResult;
      try {
        res = ex.extract(file, read.text, target);
      } catch (err) {
        add({ rule: "unreadable", message: `could not read: ${clean((err as Error).message, 200)}`, file, line: 0, severity: "low" });
        continue;
      }
      for (const r of Array.isArray(res?.refs) ? res.refs : []) {
        const ref = cleanRef(r, file);
        if (ref && record.refs.length < MAX_REFS) record.refs.push(ref);
      }
      for (const w of Array.isArray(res?.warnings) ? res.warnings : []) {
        const warning = cleanWarning(w, file);
        if (warning) add(warning);
      }
      if (typeof res?.skipped === "number" && Number.isSafeInteger(res.skipped) && res.skipped > 0) record.skipped += res.skipped;
    }
  }
  // Files over the cap: say so. A caller that doesn't know (`check` with the recorded files) keeps the old notice.
  const tooMany = files instanceof FileSet ? files.dropped : previous?.warnings.find((w) => w.rule === "truncated" && w.key === "files");
  const notice = (message: string): SourceWarning => ({ rule: "truncated", key: "files", severity: "low", file: TRUNCATED_FILE, line: 0, message });
  if (typeof tooMany === "number" && tooMany > 0) add(notice(`${tooMany} files were not read (limit ${MAX_SOURCE_FILES} per source, shared fairly between checks).`));
  else if (typeof tooMany === "object") add(tooMany);
  addSnapshots(record, previous, input, now, add);
  capWarnings(record, overflow);
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
