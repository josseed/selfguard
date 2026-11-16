/**
 * Package specs as launchers take them: npm `name@version` (scoped `@scope/name@1.2.3`) and
 * PyPI `name==1.2.3` / `name@1.2.3` (uvx). Anything that isn't a registry name (git URLs,
 * tarballs, local paths, aliases) is rejected, so it is never stored.
 */
import type { Ecosystem } from "../../lockfile/types.ts";

export interface PackageSpec {
  ecosystem: Ecosystem;
  name: string;
  /** Exact version, or null (unpinned, a tag such as "latest", a range). */
  version: string | null;
  /** What follows the name as written ("latest", "^1.2", ">=1"), when not exact. */
  pin?: string;
  /** The spec as written (line numbers; npx keys its cache by it). Never stored. */
  raw?: string;
}

const NPM_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
const SEMVER = /^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;
const PY_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const PY_VERSION = /^(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|rc|alpha|beta|c|pre|preview)[-_.]?\d*)?(?:[-_.]?(?:post|rev|r)[-_.]?\d*)?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9.]+)?$/i;
/** Pins are shown to the user: keep them short and plain. */
const PIN = /^[0-9A-Za-z.^~<>=!*_+, -]{1,40}$/;

const pinOf = (s: string): string | undefined => (PIN.test(s) ? s.trim() || undefined : undefined);

/** `name`, `name@1.2.3`, `@scope/name@latest`… null for git, URL, path, `npm:` alias specs. */
export function parseNpmSpec(spec: string): PackageSpec | null {
  const s = spec.trim();
  if (!s || s.length > 214 + 64) return null;
  const at = s.indexOf("@", s.startsWith("@") ? 1 : 0);
  const name = at < 0 ? s : s.slice(0, at);
  const rest = at < 0 ? "" : s.slice(at + 1);
  if (!NPM_NAME.test(name) || name.length > 214) return null;
  const exact = SEMVER.exec(rest);
  if (exact) return { ecosystem: "npm", name, version: exact[1]!, raw: s };
  if (rest && !PIN.test(rest)) return null; // a URL, path or alias after "@": not a registry version
  const out: PackageSpec = { ecosystem: "npm", name, version: null, raw: s };
  const pin = rest ? pinOf(rest) : undefined;
  if (pin) out.pin = pin;
  return out;
}

/** `name`, `name[extra]`, `name==1.2.3`, `name@1.2.3` (uv), `name>=1`… null for URLs and paths. */
export function parsePySpec(spec: string): PackageSpec | null {
  const s = spec.trim();
  if (!s || s.length > 200) return null;
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9._, -]*\])?\s*(.*)$/.exec(s);
  if (!m || !PY_NAME.test(m[1]!)) return null;
  const name = m[1]!;
  const rest = m[3]!.trim();
  if (!rest) return { ecosystem: "PyPI", name, version: null, raw: s };
  if (rest.startsWith("@")) {
    const v = rest.slice(1).trim();
    if (PY_VERSION.test(v)) return { ecosystem: "PyPI", name, version: v, raw: s };
    if (/^[A-Za-z]+$/.test(v)) return { ecosystem: "PyPI", name, version: null, pin: v, raw: s }; // @latest
    return null; // "name @ https://…": a direct URL
  }
  const eq = /^===?\s*([^,;\s]+)$/.exec(rest);
  if (eq && PY_VERSION.test(eq[1]!)) return { ecosystem: "PyPI", name, version: eq[1]!, raw: s };
  if (!/^[<>=!~]/.test(rest)) return null;
  const out: PackageSpec = { ecosystem: "PyPI", name, version: null, raw: s };
  const pin = pinOf(rest.split(";")[0]!);
  if (pin) out.pin = pin;
  return out;
}
