/**
 * One deduplicated OSV lookup shared by everything scanned together (lockfiles and the
 * references of CI workflows and agent configs).
 */
import { packageKey } from "../lockfile/types.ts";
import { getVulns, queryBatch, type OsvVuln, type PackageQuery } from "../osv.ts";
import { clean } from "../sanitize.ts";

/** Dedup key of a query: packageKey for versioned queries, "…@*" for name-only ones. */
export const queryKey = (q: PackageQuery): string =>
  q.version === undefined
    ? `${packageKey({ name: q.name, version: "", ecosystem: q.ecosystem })}*`
    : packageKey({ name: q.name, version: q.version, ecosystem: q.ecosystem });

export interface Lookup {
  /** queryKey -> advisory ids OSV returned for it. */
  refs: Map<string, string[]>;
  vulns: Map<string, OsvVuln>;
  /** Set when OSV could not be reached: callers keep their previous findings. */
  error?: string;
}

export async function lookup(queries: PackageQuery[]): Promise<Lookup> {
  const unique = new Map<string, PackageQuery>();
  for (const q of queries) unique.set(queryKey(q), q);
  const list = [...unique.values()];
  if (list.length === 0) return { refs: new Map(), vulns: new Map() };
  try {
    const refs = await queryBatch(list);
    return {
      refs: new Map(list.map((q, i) => [queryKey(q), refs[i]!.map((r) => r.id)])),
      vulns: await getVulns(refs.flat()),
    };
  } catch (err) {
    return { refs: new Map(), vulns: new Map(), error: `could not reach OSV: ${clean((err as Error).message, 200)}` };
  }
}
