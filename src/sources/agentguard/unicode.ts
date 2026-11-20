/**
 * Invisible and deceptive Unicode in files an AI agent reads ("hidden-unicode"):
 *
 * - Unicode Tags (U+E0000–E007F): ASCII smuggling, text the model reads and you can't see.
 *   Emoji subdivision flags (🏴 + tag letters + cancel tag) are fine.
 * - Bidi controls (U+202A–202E, U+2066–2069): Trojan Source, text that displays in another order.
 * - Zero-width characters (U+200B/200C/200D/2060/FEFF) and variation selectors (U+FE00–FE0F,
 *   U+E0100–E01EF) outside emoji and scripts that need them (GlassWorm hides code in runs of
 *   variation selectors). A leading BOM is fine.
 *
 * Counts and the first line only: hidden text is never decoded into a warning.
 */
import type { ExtractResult } from "../types.ts";

type Warning = ExtractResult["warnings"][number];

/** A run this long, or one that decodes to text, is deliberate. */
const LONG_RUN = 10;

const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const isBidi = (cp: number) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
const isZeroWidth = (cp: number) => cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff;
const isSelector = (cp: number) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const isInvisible = (cp: number) => isZeroWidth(cp) || isSelector(cp);

const EMOJI = /\p{Emoji}/u;
const PICTO = /[\p{Extended_Pictographic}\p{Emoji_Modifier}\p{Regional_Indicator}]/u;
const LETTER = /[\p{L}\p{M}]/u;
const ch = (cp: number | undefined) => (cp === undefined ? "" : String.fromCodePoint(cp));
const nonAscii = (cp: number | undefined) => cp !== undefined && cp > 0x7f;

/**
 * Is this run of invisible characters part of normal text? `prev` and `next` are the code
 * points around it (undefined at the edges).
 */
function legitimate(run: number[], prev: number | undefined, next: number | undefined): boolean {
  const p = ch(prev);
  const n = ch(next);
  // Emoji presentation (heart + FE0F), keycaps (1 + FE0F + 20E3) and ZWJ sequences
  // (rainbow flag, technologist with a skin tone).
  if (prev !== undefined && EMOJI.test(p) && run.length <= 2) {
    const [a, b] = run;
    const vs = (cp: number | undefined) => cp === 0xfe0f || cp === 0xfe0e;
    if (run.length === 1 && vs(a)) return true;
    if (run.length === 1 && a === 0x200d && PICTO.test(n)) return true;
    if (run.length === 2 && vs(a) && b === 0x200d && PICTO.test(n)) return true;
  }
  if (run.length !== 1) return false;
  const cp = run[0]!;
  // ZWNJ / ZWJ inside words of scripts that use them (Persian, Indic…).
  if ((cp === 0x200c || cp === 0x200d) && nonAscii(prev) && nonAscii(next) && LETTER.test(p) && LETTER.test(n)) return true;
  // One selector after a non-ASCII symbol: standardized variants (math, CJK ideographic
  // variation sequences), emoji presentation of symbols \p{Emoji} doesn't list.
  if (isSelector(cp) && nonAscii(prev) && !/\s/.test(p)) return true;
  return false;
}

/** GlassWorm-style payload: one byte per variation selector, mostly printable ASCII. */
function decodesToText(run: number[]): boolean {
  const bytes = run.filter(isSelector).map((cp) => (cp <= 0xfe0f ? cp - 0xfe00 : cp - 0xe0100 + 16));
  if (bytes.length < 4) return false;
  const printable = bytes.filter((b) => (b >= 0x20 && b <= 0x7e) || b === 9 || b === 10).length;
  return printable / bytes.length >= 0.8;
}

interface Tally {
  count: number;
  line: number;
}
const add = (t: Tally, n: number, line: number) => {
  if (t.count === 0) t.line = line;
  t.count += n;
};

export function hiddenUnicode(text: string): Warning[] {
  const cps: number[] = [];
  for (const c of typeof text === "string" ? text : "") cps.push(c.codePointAt(0)!);
  const tags: Tally = { count: 0, line: 0 };
  const bidi: Tally = { count: 0, line: 0 };
  const hidden: Tally = { count: 0, line: 0 };
  let longest = 0;
  let decodes = false;
  let line = 1;
  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i]!;
    if (cp === 0x0a) line++;
    else if (isBidi(cp)) add(bidi, 1, line);
    else if (isTag(cp)) {
      let j = i;
      while (j < cps.length && isTag(cps[j]!)) j++;
      // A subdivision flag: 🏴 + lowercase letters/digits + CANCEL TAG.
      const seq = cps.slice(i, j);
      const flag = cps[i - 1] === 0x1f3f4 && seq.length <= 8 && seq.at(-1) === 0xe007f && seq.slice(0, -1).every((t) => (t >= 0xe0061 && t <= 0xe007a) || (t >= 0xe0030 && t <= 0xe0039));
      if (!flag) add(tags, seq.length, line);
      i = j - 1;
    } else if (isInvisible(cp) && !(i === 0 && cp === 0xfeff)) {
      let j = i;
      while (j < cps.length && isInvisible(cps[j]!)) j++;
      const run = cps.slice(i, j);
      if (!legitimate(run, cps[i - 1], cps[j])) {
        add(hidden, run.length, line);
        longest = Math.max(longest, run.length);
        decodes ||= decodesToText(run);
      }
      i = j - 1;
    }
  }
  const out: Warning[] = [];
  const advice = "Remove them with an editor that shows invisible characters.";
  if (tags.count) {
    out.push({
      rule: "hidden-unicode",
      message: `${tags.count} invisible Unicode tag character(s) hide text that an AI agent reads but you can't see. ${advice}`,
      line: tags.line,
      severity: "high",
      key: "tags",
      notify: true,
      urgent: true,
    });
  }
  if (bidi.count) {
    out.push({
      rule: "hidden-unicode",
      message: `${bidi.count} bidirectional control character(s) make this file read differently from how it displays. ${advice}`,
      line: bidi.line,
      severity: "high",
      key: "bidi",
      notify: true,
      urgent: true,
    });
  }
  if (hidden.count) {
    const deliberate = decodes || longest >= LONG_RUN;
    const w: Warning = {
      rule: "hidden-unicode",
      message:
        `${hidden.count} invisible character(s) (zero-width or variation selectors) outside emoji` +
        `${decodes ? ", encoding hidden text" : deliberate ? ", in long runs" : ""}. ${advice}`,
      line: hidden.line,
      severity: deliberate ? "high" : "moderate",
      key: "invisible",
    };
    if (deliberate) w.notify = true;
    if (decodes) w.urgent = true;
    out.push(w);
  }
  return out;
}
