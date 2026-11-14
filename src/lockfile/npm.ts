/**
 * Static parser for package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2 and 3).
 * Pure data: never executes anything from the project.
 */
import { isObject } from "../fsutil.ts";
import { isValid } from "../semver.ts";
import type { Dependency, ParsedLockfile } from "./types.ts";

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

function depNames(manifest: unknown): Set<string> {
  const names = new Set<string>();
  if (!isObject(manifest)) return names;
  for (const field of DEP_FIELDS) {
    const deps = manifest[field];
    if (isObject(deps)) for (const n of Object.keys(deps)) names.add(n);
  }
  return names;
}

class Collector {
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

function isNonRegistry(resolved: unknown): boolean {
  if (typeof resolved !== "string") return false;
  return /^(git\+|git:|github:|file:|link:)/.test(resolved) || resolved.endsWith(".git");
}

/** "npm:real-name@1.2.3" -> { name, version } */
function parseAlias(spec: string): { name: string; version: string } | null {
  if (!spec.startsWith("npm:")) return null;
  const rest = spec.slice(4);
  const at = rest.lastIndexOf("@");
  if (at <= 0) return null;
  return { name: rest.slice(0, at), version: rest.slice(at + 1) };
}

const NM = "node_modules/";

function parseV2(packages: Record<string, unknown>, out: Collector): void {
  // Direct deps = deps declared by the root package or any workspace package.
  const direct = new Set<string>();
  for (const [key, entry] of Object.entries(packages)) {
    if (key === "" || !key.includes(NM)) for (const n of depNames(entry)) direct.add(n);
  }

  for (const [key, entry] of Object.entries(packages)) {
    if (key === "" || !isObject(entry)) continue;
    const idx = key.lastIndexOf(NM);
    if (idx === -1) continue; // workspace source folder, not an installed package
    if (entry.link === true) continue; // symlink to a workspace
    if (isNonRegistry(entry.resolved)) {
      out.skipped++;
      continue;
    }
    const installedAs = key.slice(idx + NM.length);
    const name = typeof entry.name === "string" ? entry.name : installedAs; // aliases carry the real name
    const version = typeof entry.version === "string" ? entry.version : "";
    const isTopLevel = key.indexOf(NM) === idx; // only one node_modules segment in the path
    out.add(name, version, isTopLevel && direct.has(installedAs), entry.dev === true);
  }
}

function parseV1(deps: Record<string, unknown>, out: Collector, direct: Set<string>, depth: number): void {
  if (depth > 200) return; // defensive: malformed/cyclic input
  for (const [installedAs, entry] of Object.entries(deps)) {
    if (!isObject(entry)) continue;
    const spec = typeof entry.version === "string" ? entry.version : "";
    if (isNonRegistry(entry.resolved) || isNonRegistry(spec)) {
      out.skipped++;
    } else {
      const alias = parseAlias(spec);
      out.add(
        alias?.name ?? installedAs,
        alias?.version ?? spec,
        depth === 0 && direct.has(installedAs),
        entry.dev === true,
      );
    }
    if (isObject(entry.dependencies)) parseV1(entry.dependencies, out, direct, depth + 1);
  }
}

/**
 * @param lockText raw contents of package-lock.json
 * @param manifest parsed package.json (only needed for lockfileVersion 1 to know direct deps)
 */
export function parseNpmLockfile(lockText: string, manifest?: unknown): ParsedLockfile {
  const lock: unknown = JSON.parse(lockText);
  if (!isObject(lock)) throw new Error("package-lock.json is not a JSON object");
  const out = new Collector();
  if (isObject(lock.packages)) {
    parseV2(lock.packages, out);
  } else if (isObject(lock.dependencies)) {
    parseV1(lock.dependencies, out, depNames(manifest), 0);
  } else {
    throw new Error("unrecognized package-lock.json format");
  }
  return out.result();
}
