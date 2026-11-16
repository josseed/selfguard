/**
 * Client for the OSV.dev API (https://google.github.io/osv.dev/api/).
 * Only package names + versions are sent; nothing about your files or paths.
 */
import { join } from "node:path";
import { atomicWrite, isObject, readJsonFile } from "./fsutil.ts";
import type { Ecosystem } from "./lockfile/types.ts";
import { vulnCacheDir } from "./paths.ts";
import { normalizeName } from "./versions.ts";
import { VERSION } from "./version.ts";

const API = process.env.SELFGUARD_OSV_API ?? "https://api.osv.dev/v1";
const BATCH_SIZE = 1000; // documented max queries per querybatch request
const TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const DETAIL_CONCURRENCY = 8;
export const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvRange {
  type: string;
  events: OsvEvent[];
}

export interface OsvSeverity {
  type: string;
  score: string;
}

export interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  severity?: OsvSeverity[];
  ranges?: OsvRange[];
  versions?: string[];
  database_specific?: Record<string, unknown>;
}

export interface OsvVuln {
  id: string;
  modified?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  database_specific?: Record<string, unknown>;
  withdrawn?: string;
}

export interface PackageQuery {
  name: string;
  /**
   * Absent: a name-only query (OSV returns every advisory of the package, to be evaluated
   * locally). Used when the version is unknown. GitHub Actions are never sent: they are matched
   * in a local index (scan/gha-index.ts).
   */
  version?: string;
  /** Default npm. */
  ecosystem?: Ecosystem;
}

/** Name as OSV indexes it (PyPI names PEP 503-normalized). */
const queryName = (q: PackageQuery): string => normalizeName(q.ecosystem ?? "npm", q.name);

/** A vulnerability id reported for a query, with its last-modified timestamp. */
export interface VulnRef {
  id: string;
  modified: string;
}

async function request(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
  const init: RequestInit = {
    method,
    headers: { "user-agent": `selfguard/${VERSION}`, accept: "application/json" },
    signal: AbortSignal.timeout(TIMEOUT_MS),
    redirect: "error",
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
    (init.headers as Record<string, string>)["content-type"] = "application/json";
  }
  let lastErr: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(`${API}${path}`, init);
      if (res.status === 429 || res.status >= 500) throw new Error(`OSV API ${res.status}`);
      if (!res.ok) throw Object.assign(new Error(`OSV API ${res.status}`), { fatal: true });
      const len = Number(res.headers.get("content-length") ?? 0);
      if (len > MAX_RESPONSE_BYTES) throw Object.assign(new Error("OSV response too large"), { fatal: true });
      const text = await res.text();
      if (text.length > MAX_RESPONSE_BYTES) throw Object.assign(new Error("OSV response too large"), { fatal: true });
      return JSON.parse(text);
    } catch (err) {
      lastErr = err;
      if ((err as { fatal?: boolean }).fatal) break;
      await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
      init.signal = AbortSignal.timeout(TIMEOUT_MS);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

function readRefs(result: unknown): { refs: VulnRef[]; next?: string } {
  if (!isObject(result)) return { refs: [] };
  const refs: VulnRef[] = [];
  if (Array.isArray(result.vulns)) {
    for (const v of result.vulns) {
      if (isObject(v) && typeof v.id === "string" && ID_RE.test(v.id)) {
        refs.push({ id: v.id, modified: typeof v.modified === "string" ? v.modified : "" });
      }
    }
  }
  const next = typeof result.next_page_token === "string" && result.next_page_token ? result.next_page_token : undefined;
  return next ? { refs, next } : { refs };
}

/** Returns, for each input package (same order), the vulnerability ids OSV says affect it. */
export async function queryBatch(pkgs: PackageQuery[]): Promise<VulnRef[][]> {
  const out: VulnRef[][] = pkgs.map(() => []);
  for (let start = 0; start < pkgs.length; start += BATCH_SIZE) {
    // indexes into `pkgs` still to query, with optional page tokens
    let pending: Array<{ i: number; token?: string }> = [];
    for (let i = start; i < Math.min(start + BATCH_SIZE, pkgs.length); i++) pending.push({ i });

    for (let page = 0; pending.length > 0 && page < 20; page++) {
      const queries = pending.map(({ i, token }) => ({
        package: { ecosystem: pkgs[i]!.ecosystem ?? "npm", name: queryName(pkgs[i]!) },
        ...(pkgs[i]!.version !== undefined ? { version: pkgs[i]!.version } : {}),
        ...(token ? { page_token: token } : {}),
      }));
      const res = await request("POST", "/querybatch", { queries });
      const results = isObject(res) && Array.isArray(res.results) ? res.results : [];
      const next: typeof pending = [];
      pending.forEach(({ i }, k) => {
        const { refs, next: token } = readRefs(results[k]);
        out[i]!.push(...refs);
        if (token) next.push({ i, token });
      });
      pending = next;
    }
  }
  return out;
}

interface CacheEntry {
  fetchedAt: string;
  vuln: OsvVuln;
}

function cachePath(id: string): string {
  return join(vulnCacheDir(), `${id}.json`);
}

function asVuln(data: unknown): OsvVuln | null {
  if (!isObject(data) || typeof data.id !== "string" || !ID_RE.test(data.id)) return null;
  return data as unknown as OsvVuln;
}

export function getCachedVuln(id: string): OsvVuln | null {
  if (!ID_RE.test(id)) return null;
  return readJsonFile<CacheEntry>(cachePath(id))?.vuln ?? null;
}

/** Fetch full advisories, reusing the local cache when `modified` hasn't changed. */
export async function getVulns(refs: VulnRef[]): Promise<Map<string, OsvVuln>> {
  const result = new Map<string, OsvVuln>();
  const toFetch: string[] = [];
  const seen = new Set<string>();
  for (const { id, modified } of refs) {
    if (seen.has(id)) continue;
    seen.add(id);
    const cached = getCachedVuln(id);
    if (cached && modified && cached.modified === modified) result.set(id, cached);
    else toFetch.push(id);
  }

  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < toFetch.length) {
      const id = toFetch[cursor++]!;
      try {
        const vuln = asVuln(await request("GET", `/vulns/${encodeURIComponent(id)}`));
        if (!vuln || vuln.id !== id) continue;
        atomicWrite(cachePath(id), JSON.stringify({ fetchedAt: new Date().toISOString(), vuln } satisfies CacheEntry));
        result.set(id, vuln);
      } catch {
        const stale = getCachedVuln(id); // offline / API hiccup: fall back to what we had
        if (stale) result.set(id, stale);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, toFetch.length) }, worker));
  return result;
}
