/**
 * JSON with comments and trailing commas (VS Code, Cursor and Gemini configs accept them).
 * Comments become spaces (newlines kept, so offsets and line numbers stay right), trailing
 * commas are dropped, then JSON.parse. Pure data: nothing is evaluated.
 */

/** The text with comments blanked out and trailing commas removed; same length and lines. */
export function stripJsonc(text: string): string {
  const out = text.replace(/^﻿/, " ").split("");
  const n = out.length;
  let i = 0;
  let lastComma = -1; // index of a comma not yet followed by a value
  while (i < n) {
    const ch = out[i]!;
    if (ch === '"') {
      lastComma = -1;
      i++;
      while (i < n && out[i] !== '"') i += out[i] === "\\" ? 2 : 1;
      i++;
      continue;
    }
    if (ch === "/" && out[i + 1] === "/") {
      while (i < n && out[i] !== "\n") out[i++] = " ";
      continue;
    }
    if (ch === "/" && out[i + 1] === "*") {
      out[i++] = " ";
      out[i++] = " ";
      while (i < n && !(out[i] === "*" && out[i + 1] === "/")) {
        if (out[i] !== "\n") out[i] = " ";
        i++;
      }
      if (i < n) out[i++] = " ";
      if (i < n) out[i++] = " ";
      continue;
    }
    if (ch === ",") lastComma = i;
    else if ((ch === "}" || ch === "]") && lastComma >= 0) out[lastComma] = " ";
    if (!/\s/.test(ch) && ch !== ",") lastComma = -1;
    i++;
  }
  return out.join("");
}

/** Plain JSON first (fast path for large files such as ~/.claude.json), then JSONC. */
export function parseJsonc(text: string): unknown {
  try {
    return JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    return JSON.parse(stripJsonc(text));
  }
}
