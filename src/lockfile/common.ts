/** Shared helpers for lockfile parsers. */
import { isObject } from "../fsutil.ts";
import { isValid } from "../semver.ts";
import type { Dependency, ParsedLockfile } from "./types.ts";

export class Collector {
  private map = new Map<string, Dependency>();
  skipped = 0;

  add(name: string, version: string, direct: boolean, dev: boolean): void {
    if (!name || !isValid(version)) {
      this.skipped++;
      return;
    }
    const key = `${name}@${version}`;
    const prev = this.map.get(key);
    if (prev) {
      prev.direct ||= direct;
      prev.dev &&= dev; // prod if reachable from prod anywhere
    } else {
      this.map.set(key, { name, version, direct, dev });
    }
  }

  result(): ParsedLockfile {
    const deps = [...this.map.values()].sort((a, b) =>
      a.name === b.name ? (a.version < b.version ? -1 : 1) : a.name < b.name ? -1 : 1,
    );
    return { deps, skipped: this.skipped };
  }
}

export const PROD_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies"] as const;
export const ALL_FIELDS = [...PROD_FIELDS, "devDependencies"] as const;

/** name -> spec for the given fields of a package.json-like object. */
export function depsOf(manifest: unknown, fields: readonly string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (!isObject(manifest)) return out;
  for (const field of fields) {
    const deps = manifest[field];
    if (!isObject(deps)) continue;
    for (const [name, spec] of Object.entries(deps)) if (typeof spec === "string") out.set(name, spec);
  }
  return out;
}

export function depNames(manifest: unknown, fields: readonly string[] = ALL_FIELDS): Set<string> {
  return new Set(depsOf(manifest, fields).keys());
}

/** Names that are only declared as devDependencies in the manifest. */
export function devOnlyNames(manifest: unknown): Set<string> {
  const prod = depNames(manifest, PROD_FIELDS);
  return new Set([...depNames(manifest, ["devDependencies"])].filter((n) => !prod.has(n)));
}

/** "npm:real-name@1.2.3" -> { name, version } */
export function parseAlias(spec: string): { name: string; version: string } | null {
  if (!spec.startsWith("npm:")) return null;
  return splitNameAt(spec.slice(4));
}

/** "name@rest" / "@scope/name@rest" -> { name, version: rest } */
export function splitNameAt(s: string): { name: string; version: string } | null {
  const at = s.indexOf("@", s.startsWith("@") ? 1 : 0);
  if (at <= 0) return null;
  return { name: s.slice(0, at), version: s.slice(at + 1) };
}

/** Breadth-first set of nodes reachable from `roots` (cycle-safe, bounded). */
export function reachable(roots: Iterable<string>, edges: (node: string) => Iterable<string>, limit = 1_000_000): Set<string> {
  const seen = new Set<string>();
  const queue = [...roots];
  while (queue.length > 0 && seen.size < limit) {
    const node = queue.shift()!;
    if (seen.has(node)) continue;
    seen.add(node);
    for (const next of edges(node)) if (!seen.has(next)) queue.push(next);
  }
  return seen;
}
