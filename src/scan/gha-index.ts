/**
 * A local index of every GitHub Actions advisory. GitHub owner/repo names are
 * case-insensitive but OSV matches package names case-sensitively, so actions are never sent
 * to querybatch: the whole (small) ecosystem is listed from OSV's public bucket
 * (`modified_id.csv`), details come through the advisory cache (only changed ones are
 * downloaded) and names are matched here, lowercased. Action names never leave the machine.
 */
import { atomicWrite, isObject, readJsonFile } from "../fsutil.ts";
import { readCapped } from "../net.ts";
import { urlOverride } from "../overrides.ts";
import { getCachedVuln, getVulns, ID_RE, type OsvVuln, type VulnRef } from "../osv.ts";
import { ghaIndexFile } from "../paths.ts";
import { clean } from "../sanitize.ts";
import { VERSION } from "../version.ts";

export const GHA = "GitHub Actions";
/** How long an index is used before it is refreshed. */
export const INDEX_TTL_MS = 6 * 60 * 60 * 1000;
const TIMEOUT_MS = 30_000;
const MAX_CSV_BYTES = 1024 * 1024;
const MAX_LINES = 10_000;
const MODIFIED_RE = /^\d{4}-\d{2}-\d{2}T[0-9:.]{1,40}Z$/;

const bucket = (): string => urlOverride("SELFGUARD_OSV_BUCKET", "https://osv-vulnerabilities.storage.googleapis.com");

export interface GhaIndexEntry {
  id: string;
  /** `modified` as listed in the CSV (equal to the advisory's own, so the cache matches it). */
  modified: string;
  /** Lowercased names of the affected actions. */
  names: string[];
}

export interface GhaIndex {
  schema: 1;
  fetchedAt: string;
  entries: GhaIndexEntry[];
}

function validIndex(v: unknown): v is GhaIndex {
  return isObject(v) && v.schema === 1 && typeof v.fetchedAt === "string" && Array.isArray(v.entries);
}

export function loadGhaIndex(): GhaIndex | null {
  const v = readJsonFile<unknown>(ghaIndexFile());
  if (!validIndex(v)) return null;
  const entries = v.entries.filter(
    (e): e is GhaIndexEntry =>
      isObject(e) && typeof e.id === "string" && ID_RE.test(e.id) && typeof e.modified === "string" && Array.isArray(e.names) && e.names.every((n) => typeof n === "string"),
  );
  return { schema: 1, fetchedAt: v.fetchedAt, entries };
}

/** `modified,id` lines -> refs. Junk lines are ignored; too many lines is an error. */
export function parseModifiedCsv(text: string): VulnRef[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  if (lines.length > MAX_LINES) throw new Error("advisory list too long");
  const out: VulnRef[] = [];
  for (const line of lines) {
    const [modified, id, ...rest] = line.split(",").map((s) => s.trim());
    if (rest.length || !modified || !id || !MODIFIED_RE.test(modified) || !ID_RE.test(id)) continue;
    out.push({ id, modified });
  }
  return out;
}

async function fetchCsv(): Promise<string> {
  const res = await fetch(`${bucket()}/${encodeURIComponent(GHA)}/modified_id.csv`, {
    headers: { "user-agent": `selfguard/${VERSION}`, accept: "text/csv, text/plain" },
    signal: AbortSignal.timeout(TIMEOUT_MS),
    redirect: "error",
  });
  if (!res.ok) throw new Error(`OSV bucket ${res.status}`);
  const text = await readCapped(res, MAX_CSV_BYTES);
  if (text === null) throw new Error("advisory list too large");
  return text;
}

/** Lowercased names of the GitHub Actions an advisory affects. */
export function actionNames(vuln: OsvVuln): string[] {
  const names = new Set<string>();
  for (const a of vuln.affected ?? []) {
    if (a.package?.ecosystem === GHA && typeof a.package.name === "string" && a.package.name) names.add(a.package.name.toLowerCase());
  }
  return [...names];
}

/** RFC 3339 UTC timestamps equal up to trailing zeros of the fraction. */
export function sameInstant(a: string, b: string): boolean {
  const norm = (s: string) => s.replace(/(\.\d*?)0+Z$/, "$1Z").replace(/\.Z$/, "Z");
  return norm(a) === norm(b);
}

/** Download the list, fetch new or changed advisories (cache otherwise), save the index. */
export async function refreshGhaIndex(previous: GhaIndex | null, now = new Date()): Promise<GhaIndex> {
  // The list writes "…04.76005653Z" where the advisory says "…04.760056530Z": same instant,
  // so the cached copy is reused (getVulns compares the strings).
  const refs = parseModifiedCsv(await fetchCsv()).map((r) => {
    const cached = getCachedVuln(r.id)?.modified;
    return cached && sameInstant(cached, r.modified) ? { id: r.id, modified: cached } : r;
  });
  const vulns = await getVulns(refs);
  const before = new Map((previous?.entries ?? []).map((e) => [e.id, e]));
  const entries: GhaIndexEntry[] = [];
  for (const ref of refs) {
    const v = vulns.get(ref.id);
    if (v) entries.push({ id: ref.id, modified: v.modified ?? ref.modified, names: actionNames(v) });
    else if (before.has(ref.id)) entries.push(before.get(ref.id)!); // couldn't fetch: keep what we knew
  }
  const index: GhaIndex = { schema: 1, fetchedAt: now.toISOString(), entries };
  atomicWrite(ghaIndexFile(), JSON.stringify(index));
  return index;
}

export interface GhaLookup {
  /** Lowercased action name -> advisory ids. */
  byName: Map<string, string[]>;
  vulns: Map<string, OsvVuln>;
  /** Set only when there is no index at all (never treated as clean). */
  error?: string;
}

/**
 * Advisories of these actions (names compared lowercased). Refreshes the index when older
 * than INDEX_TTL_MS; offline, the cached index is used.
 */
export async function ghaLookup(names: string[], now = new Date()): Promise<GhaLookup> {
  let index = loadGhaIndex();
  const age = index ? now.getTime() - Date.parse(index.fetchedAt) : Infinity;
  if (!index || !(age >= 0 && age < INDEX_TTL_MS)) {
    try {
      index = await refreshGhaIndex(index, now);
    } catch (err) {
      if (!index) return { byName: new Map(), vulns: new Map(), error: `could not refresh the GitHub Actions advisory index: ${clean((err as Error).message, 200)}` };
    }
  }
  const wanted = new Set(names.map((n) => n.toLowerCase()));
  const byName = new Map<string, string[]>();
  const refs: VulnRef[] = [];
  for (const e of index!.entries) {
    const hit = e.names.filter((n) => wanted.has(n));
    if (hit.length === 0) continue;
    refs.push({ id: e.id, modified: e.modified });
    for (const n of hit) byName.set(n, [...(byName.get(n) ?? []), e.id]);
  }
  // Cached details are reused when `modified` matches: no network on a fresh index.
  return { byName, vulns: await getVulns(refs) };
}
