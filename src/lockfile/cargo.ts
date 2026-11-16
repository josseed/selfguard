/**
 * Static parser for Cargo.lock (versions 1 to 4). Pure data: never runs cargo.
 * Only crates.io packages are checked; git, path and alternate-registry crates are skipped.
 * Workspace members (no `source`) are the project itself: their dependencies are direct.
 * Cargo.lock doesn't say which crates are dev-dependencies, so none is marked dev.
 */
import { Collector } from "./common.ts";
import { parseToml } from "./toml.ts";
import type { ParsedLockfile } from "./types.ts";

const CRATES_IO = new Set(["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"]);

interface Crate {
  name: string;
  version: string;
  source: string | null;
  dependencies: string[];
}

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

export function parseCargoLockfile(text: string): ParsedLockfile {
  const doc = parseToml(text);
  if (!Array.isArray(doc.package)) {
    if (doc.version !== undefined || doc.metadata !== undefined) return { deps: [], skipped: 0 };
    throw new Error("unrecognized Cargo.lock format");
  }
  const crates: Crate[] = [];
  for (const p of doc.package as unknown[]) {
    if (typeof p !== "object" || p === null) continue;
    const e = p as Record<string, unknown>;
    const name = str(e.name);
    const version = str(e.version);
    if (!name || !version) continue;
    const deps = Array.isArray(e.dependencies) ? e.dependencies.filter((d): d is string => typeof d === "string") : [];
    crates.push({ name, version, source: str(e.source), dependencies: deps });
  }

  // "name", "name version" or "name version (source)" -> name, version
  const direct = new Set<string>();
  for (const c of crates) {
    if (c.source !== null) continue; // only workspace members declare direct deps
    for (const d of c.dependencies) {
      const [name, version] = d.split(" ");
      if (!name) continue;
      direct.add(version ? `${name}@${version}` : name);
    }
  }

  const out = new Collector("crates.io");
  for (const c of crates) {
    if (c.source === null) continue; // workspace member: your own code
    if (!CRATES_IO.has(c.source)) {
      out.skipped++; // git, path or another registry
      continue;
    }
    out.add(c.name, c.version, direct.has(c.name) || direct.has(`${c.name}@${c.version}`), false);
  }
  return out.result();
}
