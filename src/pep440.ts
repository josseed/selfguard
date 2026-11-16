/**
 * Minimal PEP 440 parser/comparator for Python package versions (no dependencies on purpose).
 * Ordering follows https://packaging.python.org/en/latest/specifications/version-specifiers/.
 */

export interface Pep440 {
  epoch: number;
  release: number[];
  /** [rank (a=0, b=1, rc=2), number] */
  pre: [number, number] | null;
  post: number | null;
  dev: number | null;
  local: Array<string | number>;
}

const RE =
  /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/;

const PRE_RANK: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

function num(s: string | undefined): number | null {
  if (s === undefined) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : NaN;
}

export function parsePep440(input: string): Pep440 | null {
  if (typeof input !== "string" || input.length > 256) return null;
  const m = RE.exec(input.trim().toLowerCase());
  if (!m) return null;
  const epoch = num(m[1]) ?? 0;
  const release = m[2]!.split(".").map(Number);
  const pre: Pep440["pre"] = m[3] ? [PRE_RANK[m[3]]!, num(m[4]) ?? 0] : null;
  const post = m[5] !== undefined ? num(m[5]) : m[6] ? (num(m[7]) ?? 0) : null;
  const dev = m[8] ? (num(m[9]) ?? 0) : null;
  const local = m[10] ? m[10].split(/[-_.]/).map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : [];
  const nums = [epoch, ...release, ...(pre ?? []), post ?? 0, dev ?? 0];
  if (!nums.every(Number.isSafeInteger)) return null;
  return { epoch, release, pre, post, dev, local };
}

const cmp = (a: number, b: number): number => (a < b ? -1 : a > b ? 1 : 0);

export function comparePep440(a: Pep440, b: Pep440): number {
  let c = cmp(a.epoch, b.epoch);
  if (c) return c;
  const len = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < len; i++) {
    c = cmp(a.release[i] ?? 0, b.release[i] ?? 0);
    if (c) return c;
  }
  // Pre-release: "1.0.dev0" < "1.0a1" < "1.0" ; a final release (or post) sorts after any pre.
  const preKey = (v: Pep440): [number, number, number] =>
    v.pre ? [1, v.pre[0], v.pre[1]] : v.post === null && v.dev !== null ? [0, 0, 0] : [2, 0, 0];
  const pa = preKey(a);
  const pb = preKey(b);
  c = cmp(pa[0], pb[0]) || cmp(pa[1], pb[1]) || cmp(pa[2], pb[2]);
  if (c) return c;
  c = cmp(a.post ?? -1, b.post ?? -1);
  if (c) return c;
  c = cmp(a.dev ?? Infinity, b.dev ?? Infinity);
  if (c) return c;
  const n = Math.max(a.local.length, b.local.length);
  for (let i = 0; i < n; i++) {
    const x = a.local[i];
    const y = b.local[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (typeof x === "number" && typeof y === "number") c = cmp(x, y);
    else if (typeof x === "number") c = 1; // numeric segments sort after alphanumeric ones
    else if (typeof y === "number") c = -1;
    else c = x < y ? -1 : x > y ? 1 : 0;
    if (c) return c;
  }
  return 0;
}

/** PEP 503 normalized project name ("Foo_Bar.baz" -> "foo-bar-baz"). */
export const normalizePyName = (name: string): string => name.toLowerCase().replace(/[-_.]+/g, "-");
