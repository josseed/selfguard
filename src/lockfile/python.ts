/**
 * Static parsers for Python lockfiles: uv.lock and poetry.lock (with pyproject.toml to know
 * the direct dependencies). Pure data: never runs pip, uv, poetry or Python.
 * Only packages from a package index are checked; git, URL, path and editable sources are
 * skipped. Names are kept as written in the lockfile; OSV compares them PEP 503-normalized.
 */
import { normalizePyName } from "../pep440.ts";
import { Collector, reachable } from "./common.ts";
import { isTable, parseToml, type TomlTable } from "./toml.ts";
import type { ParsedLockfile } from "./types.ts";

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const tables = (v: unknown): TomlTable[] => (Array.isArray(v) ? v.filter(isTable) : []);

/** Name at the start of a PEP 508 requirement ("Requests[socks] >=2; python_version<'3.8'"). */
export function requirementName(req: string): string | null {
  const m = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)/.exec(req);
  return m ? normalizePyName(m[1]!) : null;
}

// ---------- uv.lock ----------

interface UvPackage {
  key: string;
  name: string;
  version: string;
  member: boolean;
  checkable: boolean;
  /** Runtime edges (dependencies + extras) and dev edges (dependency groups). */
  prodRefs: TomlTable[];
  devRefs: TomlTable[];
}

export function parseUvLockfile(text: string): ParsedLockfile {
  const doc = parseToml(text);
  if (doc.version === undefined && doc.package === undefined) throw new Error("unrecognized uv.lock format");
  const pkgs: UvPackage[] = [];
  for (const p of tables(doc.package)) {
    const name = str(p.name);
    if (!name) continue;
    const version = str(p.version) ?? "";
    const source = isTable(p.source) ? p.source : null;
    const member = Boolean(source && (source.editable !== undefined || source.virtual !== undefined));
    const checkable = Boolean(source && typeof source.registry === "string");
    const groupRefs = (v: unknown): TomlTable[] => (isTable(v) ? Object.values(v).flatMap(tables) : []);
    pkgs.push({
      key: `${normalizePyName(name)}@${version}`,
      name,
      version,
      member,
      checkable,
      prodRefs: [...tables(p.dependencies), ...groupRefs(p["optional-dependencies"])],
      devRefs: groupRefs(p["dev-dependencies"]),
    });
  }

  const byName = new Map<string, UvPackage[]>();
  for (const p of pkgs) {
    const n = normalizePyName(p.name);
    byName.set(n, [...(byName.get(n) ?? []), p]);
  }
  /** Package keys a reference points to (all versions of that name unless it says which). */
  const resolve = (ref: TomlTable): string[] => {
    const name = str(ref.name);
    if (!name) return [];
    const candidates = byName.get(normalizePyName(name)) ?? [];
    const version = str(ref.version);
    const exact = version ? candidates.filter((c) => c.version === version) : [];
    return (exact.length ? exact : candidates).map((c) => c.key);
  };
  const byKey = new Map(pkgs.map((p) => [p.key, p]));
  const edges = (key: string): string[] => (byKey.get(key)?.prodRefs ?? []).flatMap(resolve);

  const members = pkgs.filter((p) => p.member);
  const directProd = new Set(members.flatMap((m) => m.prodRefs.flatMap(resolve)));
  const directDev = new Set(members.flatMap((m) => m.devRefs.flatMap(resolve)));
  const prod = reachable(directProd, edges);

  const out = new Collector("PyPI");
  for (const p of pkgs) {
    if (p.member) continue; // your own project
    if (!p.checkable) {
      out.skipped++;
      continue;
    }
    const dev = members.length > 0 && !prod.has(p.key);
    out.add(p.name, p.version, directProd.has(p.key) || directDev.has(p.key), dev);
  }
  return out.result();
}

// ---------- poetry.lock ----------

/** Direct dependencies declared in pyproject.toml (Poetry and PEP 621 / PEP 735 styles). */
export function pyprojectDeps(manifest: unknown): { prod: Set<string>; dev: Set<string> } {
  const prod = new Set<string>();
  const dev = new Set<string>();
  if (!isTable(manifest)) return { prod, dev };
  const add = (into: Set<string>, names: Iterable<string | null>): void => {
    for (const n of names) if (n && n !== "python") into.add(n);
  };
  const keysOf = (t: unknown): string[] => (isTable(t) ? Object.keys(t).map(normalizePyName) : []);
  const reqs = (v: unknown): Array<string | null> =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").map(requirementName) : [];

  const project = isTable(manifest.project) ? manifest.project : null;
  if (project) {
    add(prod, reqs(project.dependencies));
    if (isTable(project["optional-dependencies"])) for (const v of Object.values(project["optional-dependencies"])) add(prod, reqs(v));
  }
  if (isTable(manifest["dependency-groups"])) for (const v of Object.values(manifest["dependency-groups"])) add(dev, reqs(v));
  const tool = isTable(manifest.tool) ? manifest.tool : null;
  const poetry = tool && isTable(tool.poetry) ? tool.poetry : null;
  if (poetry) {
    add(prod, keysOf(poetry.dependencies));
    add(dev, keysOf(poetry["dev-dependencies"]));
    if (isTable(poetry.group)) {
      for (const [group, g] of Object.entries(poetry.group)) {
        if (isTable(g)) add(group === "main" ? prod : dev, keysOf(g.dependencies));
      }
    }
  }
  return { prod, dev };
}

const NON_INDEX_SOURCES = new Set(["git", "directory", "file", "url"]);

export function parsePoetryLockfile(text: string, manifest?: unknown): ParsedLockfile {
  const doc = parseToml(text);
  if (doc.package === undefined) {
    if (isTable(doc.metadata)) return { deps: [], skipped: 0 };
    throw new Error("unrecognized poetry.lock format");
  }
  interface Pkg {
    name: string;
    norm: string;
    version: string;
    checkable: boolean;
    deps: string[];
    dev: boolean | null;
  }
  const pkgs: Pkg[] = [];
  for (const p of tables(doc.package)) {
    const name = str(p.name);
    if (!name) continue;
    const source = isTable(p.source) ? p.source : null;
    const type = source ? str(source.type) : null;
    let dev: boolean | null = null;
    if (Array.isArray(p.groups)) dev = !p.groups.includes("main"); // Poetry 2
    else if (typeof p.category === "string") dev = p.category === "dev"; // Poetry < 1.5
    pkgs.push({
      name,
      norm: normalizePyName(name),
      version: str(p.version) ?? "",
      checkable: !type || !NON_INDEX_SOURCES.has(type),
      deps: isTable(p.dependencies) ? Object.keys(p.dependencies).map(normalizePyName) : [],
      dev,
    });
  }

  const { prod: directProd, dev: directDev } = pyprojectDeps(manifest);
  const known = isTable(manifest);
  const depsOf = new Map<string, string[]>();
  for (const p of pkgs) depsOf.set(p.norm, [...(depsOf.get(p.norm) ?? []), ...p.deps]);
  const prod = reachable(directProd, (n) => depsOf.get(n) ?? []);

  const out = new Collector("PyPI");
  for (const p of pkgs) {
    if (!p.checkable) {
      out.skipped++;
      continue;
    }
    const dev = p.dev ?? (known && directProd.size + directDev.size > 0 ? !prod.has(p.norm) : false);
    out.add(p.name, p.version, directProd.has(p.norm) || directDev.has(p.norm), dev);
  }
  return out.result();
}
