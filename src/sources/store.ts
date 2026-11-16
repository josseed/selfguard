/** Source records on disk (~/.selfguard/sources), same atomic writes and checks as store.ts. */
import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite, isObject, readJsonFile, sha256 } from "../fsutil.ts";
import { sourcesDir } from "../paths.ts";
import { SOURCE_KINDS, type SourceKind, type SourceRecord, type SourceScope } from "./types.ts";

function recordFile(kind: SourceKind, scope: SourceScope, path: string): string {
  return join(sourcesDir(), `${sha256(`${kind}|${scope}|${path}`).slice(0, 40)}.json`);
}

function valid(rec: unknown): rec is SourceRecord {
  if (!isObject(rec) || rec.schema !== 1 || typeof rec.path !== "string") return false;
  if (!(SOURCE_KINDS as readonly unknown[]).includes(rec.kind) || (rec.scope !== "repo" && rec.scope !== "machine")) return false;
  return (
    Array.isArray(rec.files) &&
    Array.isArray(rec.refs) &&
    Array.isArray(rec.findings) &&
    Array.isArray(rec.warnings) &&
    typeof rec.skipped === "number" &&
    (rec.scannedAt === null || typeof rec.scannedAt === "string")
  );
}

export function loadSource(kind: SourceKind, scope: SourceScope, path: string): SourceRecord | null {
  const rec = readJsonFile<unknown>(recordFile(kind, scope, path));
  return valid(rec) && rec.kind === kind && rec.scope === scope && rec.path === path ? rec : null;
}

export function saveSource(rec: SourceRecord): void {
  atomicWrite(recordFile(rec.kind, rec.scope, rec.path), JSON.stringify(rec));
}

export function forgetSource(kind: SourceKind, scope: SourceScope, path: string): boolean {
  const existed = loadSource(kind, scope, path) !== null;
  rmSync(recordFile(kind, scope, path), { force: true });
  return existed;
}

/** Every source record, optionally of one kind / scope / path; sorted by path then kind. */
export function listSources(filter: { kind?: SourceKind; scope?: SourceScope; path?: string } = {}): SourceRecord[] {
  let files: string[];
  try {
    files = readdirSync(sourcesDir()).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
  const out: SourceRecord[] = [];
  for (const f of files) {
    const rec = readJsonFile<unknown>(join(sourcesDir(), f));
    if (!valid(rec)) continue;
    if (filter.kind && rec.kind !== filter.kind) continue;
    if (filter.scope && rec.scope !== filter.scope) continue;
    if (filter.path !== undefined && rec.path !== filter.path) continue;
    out.push(rec);
  }
  return out.sort((a, b) => a.path.localeCompare(b.path) || a.kind.localeCompare(b.kind));
}
