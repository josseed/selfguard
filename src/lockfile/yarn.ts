/**
 * Static parsers for yarn.lock: classic (v1, custom format) and berry (v2+, YAML).
 * Pure data: never executes anything from the project.
 */
import { Collector, depsOf, devOnlyNames, parseAlias, PROD_FIELDS, reachable, splitNameAt, ALL_FIELDS } from "./common.ts";
import type { ParsedLockfile } from "./types.ts";
import { isMap, parseYamlDocuments } from "./yaml.ts";

interface Entry {
  name: string;
  version: string;
  registry: boolean;
  deps: Array<[string, string]>; // [name, range/descriptor spec]
}

function unquote(s: string): string {
  const t = s.trim();
  return t.length >= 2 && t.startsWith('"') && t.endsWith('"') ? t.slice(1, -1) : t;
}

/** Shared tail: classify direct/dev by walking from the manifest's production deps. */
function collect(entries: Map<string, Entry>, manifest: unknown, descriptor: (name: string, spec: string) => string): ParsedLockfile {
  const out = new Collector();
  const devOnly = devOnlyNames(manifest);
  const all = depsOf(manifest, ALL_FIELDS);
  const prodRoots = [...depsOf(manifest, PROD_FIELDS)]
    .filter(([name]) => !devOnly.has(name))
    .map(([name, spec]) => descriptor(name, spec));
  const haveManifest = all.size > 0;
  const prod = reachable(prodRoots, (d) => (entries.get(d)?.deps ?? []).map(([n, s]) => descriptor(n, s)));
  const prodPkgs = new Set([...prod].map((d) => entries.get(d)).filter(Boolean).map((e) => `${e!.name}@${e!.version}`));
  const directPkgs = new Set(
    [...all].map(([n, s]) => entries.get(descriptor(n, s))).filter(Boolean).map((e) => `${e!.name}@${e!.version}`),
  );

  const seen = new Set<Entry>();
  for (const e of entries.values()) {
    if (seen.has(e)) continue; // one entry is shared by several descriptors
    seen.add(e);
    if (!e.registry) {
      out.skipped++;
      continue;
    }
    const key = `${e.name}@${e.version}`;
    out.add(e.name, e.version, directPkgs.has(key), haveManifest ? !prodPkgs.has(key) : false);
  }
  return out.result();
}

// ---------- classic (v1) ----------

function parseClassic(text: string, manifest: unknown): ParsedLockfile {
  const entries = new Map<string, Entry>();
  let current: Entry | null = null;
  let inDeps = false;

  for (const line of text.split(/\r?\n/)) {
    if (line === "" || line.startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    const body = line.trim();
    if (indent === 0) {
      inDeps = false;
      if (!body.endsWith(":")) {
        current = null;
        continue;
      }
      const descriptors = body.slice(0, -1).split(/,\s*/).map(unquote);
      const first = splitNameAt(descriptors[0] ?? "");
      if (!first) {
        current = null;
        continue;
      }
      const alias = parseAlias(first.version);
      const spec = alias ? alias.version : first.version;
      // git/file/link/tarball specs, or GitHub "user/repo" shorthand, are not registry packages
      const registry = !/^(file|link|git|github|https?|portal|exec):|^git\+|^[\w.-]+\/[\w.-]+(#.*)?$/.test(spec);
      current = { name: alias?.name ?? first.name, version: "", registry, deps: [] };
      for (const d of descriptors) entries.set(d, current);
      continue;
    }
    if (!current) continue;
    if (indent === 2) {
      inDeps = body === "dependencies:" || body === "optionalDependencies:";
      const m = /^(\S+)\s+(.*)$/.exec(body);
      if (m && m[1] === "version") current.version = unquote(m[2]!);
      if (m && m[1] === "resolved" && /^"?(git|file:|link:)|codeload\.github\.com|\.git(#|"?$)/.test(m[2]!)) current.registry = false;
      continue;
    }
    if (indent >= 4 && inDeps) {
      const m = /^("(?:[^"\\]|\\.)*"|\S+)\s+(.*)$/.exec(body);
      if (m) current.deps.push([unquote(m[1]!), unquote(m[2]!)]);
    }
  }
  return collect(entries, manifest, (name, spec) => `${name}@${spec}`);
}

// ---------- berry (v2+) ----------

function parseBerry(text: string, manifest: unknown): ParsedLockfile {
  const doc = parseYamlDocuments(text)[0];
  if (!doc) throw new Error("empty yarn.lock");
  const entries = new Map<string, Entry>();

  for (const [key, value] of Object.entries(doc)) {
    if (key === "__metadata" || !isMap(value)) continue;
    const resolution = typeof value.resolution === "string" ? value.resolution : "";
    let resolved = splitNameAt(resolution);
    let registry = false;
    if (resolved?.version.startsWith("npm:")) {
      registry = true;
      resolved = { name: resolved.name, version: resolved.version.slice(4) };
    } else if (resolved?.version.startsWith("patch:")) {
      // "name@patch:name@npm%3A1.2.3#..." -> the patched npm package
      const inner = splitNameAt(decodeURIComponent(resolved.version.slice(6).split("#")[0]!));
      if (inner?.version.startsWith("npm:")) {
        registry = true;
        resolved = { name: inner.name, version: inner.version.slice(4) };
      }
    }
    const deps: Array<[string, string]> = [];
    for (const field of ["dependencies", "optionalDependencies"]) {
      const d = value[field];
      if (isMap(d)) for (const [n, s] of Object.entries(d)) if (typeof s === "string") deps.push([n, s]);
    }
    const entry: Entry = { name: resolved?.name ?? key, version: resolved?.version ?? "", registry, deps };
    const isWorkspace = /@workspace:/.test(resolution);
    for (const d of key.split(/,\s*/)) entries.set(d.trim(), entry);
    if (isWorkspace) entries.set(`__workspace__:${key}`, { ...entry, registry: false });
  }
  // Berry descriptors always carry a protocol; manifest ranges without one mean npm:.
  const descriptor = (name: string, spec: string): string => `${name}@${/^[a-z]+:/.test(spec) ? spec : `npm:${spec}`}`;
  return collect(
    new Map([...entries].filter(([k, e]) => !k.startsWith("__workspace__:") && !(e.version === "0.0.0-use.local"))),
    manifest,
    descriptor,
  );
}

export function parseYarnLockfile(text: string, manifest?: unknown): ParsedLockfile {
  if (/^__metadata:/m.test(text)) return parseBerry(text, manifest);
  if (/^# yarn lockfile v1/m.test(text) || /^\S.*:\n {2}version "/m.test(text)) return parseClassic(text, manifest);
  throw new Error("unrecognized yarn.lock format");
}
