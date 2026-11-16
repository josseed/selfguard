/**
 * One deduplicated OSV lookup shared by everything scanned together (lockfiles and the
 * references of CI workflows and agent configs). GitHub Actions are never sent to OSV: they
 * are matched case-insensitively against a local index of that ecosystem (gha-index.ts).
 */
import { packageKey } from "../lockfile/types.ts";
import { getVulns, queryBatch, type OsvVuln, type PackageQuery } from "../osv.ts";
import { clean } from "../sanitize.ts";
import { GHA, ghaLookup } from "./gha-index.ts";

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
  /** Set when there is no GitHub Actions index (offline on first use): callers with actions keep theirs. */
  ghaError?: string;
}

export async function lookup(queries: PackageQuery[]): Promise<Lookup> {
  const unique = new Map<string, PackageQuery>();
  const actions = new Map<string, PackageQuery>();
  for (const q of queries) (q.ecosystem === GHA ? actions : unique).set(queryKey(q), q);
  const list = [...unique.values()];
  const out: Lookup = { refs: new Map(), vulns: new Map() };
  const gha = actions.size
    ? ghaLookup([...actions.values()].map((q) => q.name)).catch((err: Error) => ({
        byName: new Map<string, string[]>(),
        vulns: new Map<string, OsvVuln>(),
        error: `could not refresh the GitHub Actions advisory index: ${clean(err.message, 200)}`,
      }))
    : null;
  if (list.length) {
    try {
      const refs = await queryBatch(list);
      list.forEach((q, i) => out.refs.set(queryKey(q), refs[i]!.map((r) => r.id)));
      out.vulns = await getVulns(refs.flat());
    } catch (err) {
      out.refs = new Map();
      out.error = `could not reach OSV: ${clean((err as Error).message, 200)}`;
    }
  }
  if (gha) {
    const g = await gha;
    if (g.error) out.ghaError = g.error;
    for (const [key, q] of actions) out.refs.set(key, g.byName.get(q.name.toLowerCase()) ?? []);
    for (const [id, v] of g.vulns) out.vulns.set(id, v);
  }
  return out;
}
