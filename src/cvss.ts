/**
 * CVSS v3.x base score from a vector string (https://www.first.org/cvss/v3.1/specification-document),
 * for advisories that carry a vector but no severity label (PYSEC, RUSTSEC, OSV entries).
 * CVSS v4 vectors aren't scored here.
 */

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

/** Round up to one decimal, as the specification's Roundup (float-safe). */
function roundUp(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** Base score 0-10, or null if the vector isn't a complete CVSS v3 vector. */
export function cvss3Score(vector: string): number | null {
  if (typeof vector !== "string" || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const m: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  const av = W.AV[m.AV as keyof typeof W.AV];
  const ac = W.AC[m.AC as keyof typeof W.AC];
  const ui = W.UI[m.UI as keyof typeof W.UI];
  const c = W.CIA[m.C as keyof typeof W.CIA];
  const i = W.CIA[m.I as keyof typeof W.CIA];
  const a = W.CIA[m.A as keyof typeof W.CIA];
  const scope = m.S;
  if ([av, ac, ui, c, i, a].some((x) => x === undefined) || (scope !== "U" && scope !== "C")) return null;
  const changed = scope === "C";
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR ?? ""];
  if (pr === undefined) return null;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr * ui!;
  return roundUp(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
}
