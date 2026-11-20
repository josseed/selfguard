/**
 * Static parser for bun.lock (text lockfile, JSON with trailing commas).
 * The binary bun.lockb format is not supported.
 */
import { isObject } from "../fsutil.ts";
import { Collector, devOnlyNames, PROD_FIELDS, reachable, splitNameAt } from "./common.ts";
import type { ParsedLockfile } from "./types.ts";

/** Remove trailing commas (outside strings) so JSON.parse accepts bun's JSONC. */
export function stripTrailingCommas(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (inString) {
      out += ch;
      if (ch === "\\") {
        out += text[++i] ?? "";
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === ",") {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      // A space, not nothing: JSON.parse error positions then still point into `text`.
      if (text[j] === "}" || text[j] === "]") {
        out += " ";
        continue;
      }
    }
    out += ch;
  }
  return out;
}

/** Split a package path like "a/@scope/b/c" into package-name segments. */
function segments(path: string): string[] {
  const parts = path.split("/");
  const out: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    if (parts[i]!.startsWith("@") && i + 1 < parts.length) out.push(`${parts[i]}/${parts[++i]}`);
    else out.push(parts[i]!);
  }
  return out;
}

export function parseBunLockfile(text: string, manifest?: unknown): ParsedLockfile {
  const lock: unknown = JSON.parse(stripTrailingCommas(text));
  if (!isObject(lock) || !isObject(lock.packages)) throw new Error("unrecognized bun.lock format");
  const packages = lock.packages;
  const workspaces = isObject(lock.workspaces) ? lock.workspaces : {};

  // Resolve a dependency name from a package path the way node_modules does: nearest first.
  const resolve = (fromPath: string, name: string): string | null => {
    const segs = fromPath ? segments(fromPath) : [];
    for (let i = segs.length; i >= 0; i--) {
      const key = [...segs.slice(0, i), name].join("/");
      if (key in packages) return key;
    }
    return null;
  };
  const depsOfPath = (path: string): string[] => {
    const info = Array.isArray(packages[path]) ? (packages[path] as unknown[]).find(isObject) : undefined;
    if (!info) return [];
    const out: string[] = [];
    for (const field of ["dependencies", "optionalDependencies"]) {
      const d = info[field];
      if (isObject(d)) for (const n of Object.keys(d)) {
        const k = resolve(path, n);
        if (k) out.push(k);
      }
    }
    return out;
  };

  const direct = new Set<string>();
  const prodRoots: string[] = [];
  const devOnly = devOnlyNames(manifest);
  for (const ws of Object.values(workspaces)) {
    if (!isObject(ws)) continue;
    for (const field of [...PROD_FIELDS, "devDependencies"]) {
      const d = ws[field];
      if (!isObject(d)) continue;
      for (const n of Object.keys(d)) {
        direct.add(n);
        if (field !== "devDependencies" && !devOnly.has(n) && n in packages) prodRoots.push(n);
      }
    }
  }
  const prod = reachable(prodRoots, depsOfPath);

  const out = new Collector();
  for (const [path, value] of Object.entries(packages)) {
    const ident = Array.isArray(value) && typeof value[0] === "string" ? value[0] : "";
    const parsed = splitNameAt(ident);
    if (!parsed || /^(workspace|link|file|git|github|https?):/.test(parsed.version)) {
      out.skipped++;
      continue;
    }
    const isTopLevel = segments(path).length === 1;
    out.add(parsed.name, parsed.version, isTopLevel && direct.has(path), !prod.has(path));
  }
  return out.result();
}
