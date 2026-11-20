// Mutation fuzzing helpers: a seeded PRNG and mutators for text inputs that selfguard reads
// from untrusted places (lockfiles, workflows, agent configs, answers from other machines).
// Deterministic for a given seed, so any failure can be replayed with SELFGUARD_FUZZ_SEED.

export const ITERATIONS = Number(process.env.SELFGUARD_FUZZ_ITERATIONS ?? 300);
export const SEED = Number(process.env.SELFGUARD_FUZZ_SEED ?? 0x5e1f9a7d);
/** A single input slower than this is reported as a potential hang (ReDoS, quadratic loop). */
export const SLOW_MS = Number(process.env.SELFGUARD_FUZZ_SLOW_MS ?? 1500);

export type Rng = () => number;

export function rng(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const int = (r: Rng, n: number): number => Math.floor(r() * n);
const pick = <T>(r: Rng, xs: readonly T[]): T => xs[int(r, xs.length)]!;

/** Tokens that historically break hand-written parsers or reach dangerous code paths. */
const TOKENS = [
  "__proto__", "constructor", "prototype", "__proto__: {}", '"__proto__": {"polluted": 1}',
  "[__proto__]", "[constructor.prototype]", "toString", "hasOwnProperty",
  "{", "}", "[", "]", "[[", "]]", "{{", "}}", ":", ": ", "- ", "  - ", "?", "&a", "*a", "!!js/function", "!<tag>",
  '"', "'", '"""', "'''", "\\", "\\u0000", "\\uD800", "#", "//", "/*", "*/", ",", ",,", "=", "==", "@", "@npm:", "workspace:",
  "\n", "\r\n", "\r", "\t", "\u0000", "\u001b[31m", "\u001b]8;;http://x\u0007", "‮", "⁦", "﻿", "\uD800", "😀",
  "../", "../../", "/..", "~/", "/etc/passwd", "file:", "git+ssh://", "https://", "${{ github.event.issue.title }}",
  "-e", "--", "$(id)", "`id`", ";", "|", "&&",
  "1e9999", "-0", "NaN", "Infinity", "0x", "99999999999999999999999", "v", "1.2.3-", "1.2.3+", ">=1 <2 || ^3",
];

/** One random mutation of `text`. `pool` holds other seeds for splicing. */
export function mutate(r: Rng, text: string, pool: readonly string[]): string {
  const at = int(r, text.length + 1);
  switch (int(r, 12)) {
    case 0: // insert a token
      return text.slice(0, at) + pick(r, TOKENS) + text.slice(at);
    case 1: { // delete a range
      const len = int(r, 64);
      return text.slice(0, at) + text.slice(at + len);
    }
    case 2: { // duplicate a range
      const len = 1 + int(r, 200);
      return text.slice(0, at + len) + text.slice(at, at + len) + text.slice(at + len);
    }
    case 3: // truncate
      return text.slice(0, at);
    case 4: { // flip a character
      if (!text.length) return pick(r, TOKENS);
      const i = Math.min(at, text.length - 1);
      return text.slice(0, i) + String.fromCharCode(int(r, 0x3000)) + text.slice(i + 1);
    }
    case 5: { // splice from another seed
      const other = pick(r, pool);
      const from = int(r, other.length + 1);
      return text.slice(0, at) + other.slice(from, from + int(r, 400)) + text.slice(at);
    }
    case 6: { // deep nesting
      const open = pick(r, ["[", "{", "  ", "- ", "{a=", "[[", '{"a":']);
      const n = 10 + int(r, 5000);
      return text.slice(0, at) + open.repeat(n) + text.slice(at);
    }
    case 7: { // very long token
      const n = 1000 + int(r, 200_000);
      return text.slice(0, at) + pick(r, ["a", "1", " ", "\\", '"', "-", ".", "/", "@", "0."]).repeat(n) + text.slice(at);
    }
    case 8: { // swap two lines
      const lines = text.split("\n");
      if (lines.length < 2) return text;
      const i = int(r, lines.length), j = int(r, lines.length);
      [lines[i], lines[j]] = [lines[j]!, lines[i]!];
      return lines.join("\n");
    }
    case 9: { // change indentation of a line
      const lines = text.split("\n");
      const i = int(r, lines.length);
      lines[i] = " ".repeat(int(r, 40)) + lines[i]!.trimStart();
      return lines.join("\n");
    }
    case 10: // repeat the whole input (large but legitimate-looking files)
      return text.repeat(2 + int(r, 6));
    default: // replace a key-like word with a dangerous key
      return text.replace(/[A-Za-z_][\w-]{2,}/, () => pick(r, ["__proto__", "constructor", "prototype"]));
  }
}

/** Seed → several stacked mutations. */
export function* cases(seeds: readonly string[], salt: number, n = ITERATIONS): Generator<{ i: number; input: string }> {
  const r = rng(SEED ^ salt);
  for (let i = 0; i < n; i++) {
    let input = pick(r, seeds);
    const rounds = 1 + int(r, 4);
    for (let k = 0; k < rounds; k++) input = mutate(r, input, seeds);
    yield { i, input };
  }
}

const PROTO_KEYS = (): string => [Object.prototype, Array.prototype, Function.prototype, String.prototype]
  .map((p) => Object.getOwnPropertyNames(p).sort().join(",")).join("|");
const baseline = PROTO_KEYS();

export interface Failure {
  target: string;
  i: number;
  reason: string;
  input: string;
}

/**
 * Runs `fn` on one input and returns a failure when it:
 * - overflows the stack (unbounded recursion),
 * - throws something that isn't an Error,
 * - takes longer than SLOW_MS,
 * - adds properties to a built-in prototype.
 * Controlled errors (the parser rejecting the input) are fine.
 */
export async function check(target: string, i: number, input: string, fn: (input: string) => unknown): Promise<Failure | null> {
  const t0 = performance.now();
  let reason: string | null = null;
  try {
    await fn(input);
  } catch (e) {
    if (!(e instanceof Error)) reason = `threw a non-Error: ${String(e)}`;
    else if (e instanceof RangeError && /call stack/i.test(e.message)) reason = "stack overflow";
  }
  const ms = performance.now() - t0;
  if (!reason && ms > SLOW_MS) reason = `slow: ${Math.round(ms)} ms for ${input.length} chars`;
  if (!reason && PROTO_KEYS() !== baseline) reason = "a built-in prototype was modified";
  return reason ? { target, i, reason, input } : null;
}

export function describe(f: Failure): string {
  const sample = f.input.length > 300 ? `${JSON.stringify(f.input.slice(0, 300))}… (${f.input.length} chars)` : JSON.stringify(f.input);
  return `${f.target} #${f.i} (seed ${SEED}): ${f.reason}\n  input: ${sample}`;
}
