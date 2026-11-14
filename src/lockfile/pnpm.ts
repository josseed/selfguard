/**
 * Static parser for pnpm-lock.yaml (lockfileVersion 5.x, 6.x and 9.x).
 * Pure data: never executes anything from the project.
 */
import { Collector, devOnlyNames, reachable, splitNameAt } from "./common.ts";
import type { ParsedLockfile } from "./types.ts";
import { isMap, parseYamlDocuments, type YamlMap } from "./yaml.ts";

const IMPORTER_PROD = ["dependencies", "optionalDependencies"];
const IMPORTER_DEV = ["devDependencies"];

/** Drop peer-dependency suffixes: "18.2.0(react@18.2.0)" (v6+) or "18.2.0_react@18.2.0" (v5). */
function stripPeers(v: string): string {
  const paren = v.indexOf("(");
  const base = paren >= 0 ? v.slice(0, paren) : v;
  const underscore = base.indexOf("_");
  return underscore >= 0 ? base.slice(0, underscore) : base;
}

/** Package key -> name/version. v9 "name@1.0.0(peers)", v6 "/name@1.0.0(peers)", v5 "/name/1.0.0_peers". */
function parseKey(key: string, major: number): { name: string; version: string } | null {
  const k = key.startsWith("/") ? key.slice(1) : key;
  if (major < 6) {
    const slash = k.lastIndexOf("/");
    if (slash <= 0) return null;
    return { name: k.slice(0, slash), version: stripPeers(k.slice(slash + 1)) };
  }
  const parsed = splitNameAt(k.split("(")[0]!);
  return parsed ? { name: parsed.name, version: stripPeers(parsed.version) } : null;
}

/** Importer entry "version" -> snapshot key, handling aliases ("left-pad@1.3.0", "/left-pad@1.3.0"). */
function importerTarget(name: string, ref: string, major: number): string | null {
  if (/^(link|file|workspace):/.test(ref)) return null;
  if (ref.startsWith("/")) return major < 6 ? ref : ref.slice(1);
  // "1.2.3(...)" is a plain version; "real@1.2.3(...)" is an alias target.
  const head = ref.split("(")[0]!;
  if (/^\d/.test(head)) return major < 6 ? `/${name}/${ref}` : `${name}@${ref}`;
  return major < 6 ? `/${ref}` : ref;
}

function refOf(entry: unknown): string | null {
  if (typeof entry === "string") return entry; // v5: name: version
  if (isMap(entry) && typeof entry.version === "string") return entry.version; // v6/v9: {specifier, version}
  return null;
}

export function parsePnpmLockfile(text: string, manifest?: unknown): ParsedLockfile {
  const docs = parseYamlDocuments(text);
  // pnpm 10 can prepend a document for config dependencies; the main one has importers/packages.
  const doc = docs.find((d) => isMap(d.importers) || isMap(d.packages)) ?? docs.find((d) => d.lockfileVersion !== undefined);
  if (!doc || doc.lockfileVersion === undefined) throw new Error("not a pnpm lockfile");
  const major = Math.trunc(Number.parseFloat(String(doc.lockfileVersion)));
  if (!Number.isFinite(major) || major < 5) throw new Error(`unsupported pnpm lockfileVersion ${String(doc.lockfileVersion)}`);

  const importers: YamlMap = isMap(doc.importers) ? doc.importers : ({ ".": doc } as YamlMap);
  const packages: YamlMap = isMap(doc.packages) ? doc.packages : (Object.create(null) as YamlMap);
  // v9 keeps the graph in "snapshots"; older versions keep it in "packages".
  const graph: YamlMap = isMap(doc.snapshots) ? doc.snapshots : packages;

  const directPkgs = new Set<string>(); // "name@version" depended on by some importer
  const prodRoots: string[] = [];
  const devOnly = devOnlyNames(manifest);
  for (const importer of Object.values(importers)) {
    if (!isMap(importer)) continue;
    for (const field of [...IMPORTER_PROD, ...IMPORTER_DEV]) {
      const deps = importer[field];
      if (!isMap(deps)) continue;
      for (const [name, entry] of Object.entries(deps)) {
        const ref = refOf(entry);
        const target = ref ? importerTarget(name, ref, major) : null;
        if (!target) continue;
        const pkg = parseKey(target, major);
        if (pkg) directPkgs.add(`${pkg.name}@${pkg.version}`);
        if (IMPORTER_PROD.includes(field) && !devOnly.has(name)) prodRoots.push(target);
      }
    }
  }

  const edges = (key: string): string[] => {
    const node = graph[key];
    if (!isMap(node)) return [];
    const out: string[] = [];
    for (const field of ["dependencies", "optionalDependencies"]) {
      const deps = node[field];
      if (!isMap(deps)) continue;
      for (const [name, ref] of Object.entries(deps)) {
        const target = typeof ref === "string" ? importerTarget(name, ref, major) : null;
        if (target) out.push(target);
      }
    }
    return out;
  };
  const prodKeys = reachable(prodRoots, edges);
  const prodPkgs = new Set([...prodKeys].map((k) => parseKey(k, major)).filter(Boolean).map((p) => `${p!.name}@${p!.version}`));

  const out = new Collector();
  // Every installed package appears in the graph (snapshots in v9, packages before).
  for (const [key, entry] of Object.entries(graph)) {
    const pkg = parseKey(key, major);
    if (!pkg) {
      out.skipped++;
      continue;
    }
    const meta = isMap(packages[key]) ? (packages[key] as YamlMap) : isMap(entry) ? entry : undefined;
    const resolution = meta && isMap(meta.resolution) ? meta.resolution : meta?.resolution;
    if (typeof resolution === "string" && /(tarball|repo|directory|commit):/.test(resolution) && !/integrity:/.test(resolution)) {
      out.skipped++; // git / tarball / local directory deps
      continue;
    }
    const legacyDev = isMap(entry) ? entry.dev : undefined; // v5/v6 mark dev explicitly
    const dev = major < 9 && legacyDev !== undefined ? legacyDev === "true" : !prodPkgs.has(`${pkg.name}@${pkg.version}`);
    out.add(pkg.name, pkg.version, directPkgs.has(`${pkg.name}@${pkg.version}`), dev);
  }
  return out.result();
}
