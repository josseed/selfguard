/**
 * Everything we print comes from untrusted sources (lockfiles, advisory text).
 * Strip control characters so nobody can inject terminal escape sequences
 * (cursor movement, OSC 8 links, title changes, clipboard writes...) and
 * bidirectional overrides ("Trojan Source" style spoofing).
 */
const CONTROL = new RegExp(
  "[\\u0000-\\u0008\\u000B-\\u001F\\u007F-\\u009F\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069]",
  "g",
);

export function clean(input: unknown, maxLen = 300, opts: { multiline?: boolean } = {}): string {
  const stripped = String(input ?? "").replace(CONTROL, "");
  // Linear on purpose: a regex like /\s*\n\s*/ is quadratic on long runs of spaces, and this
  // text comes from lockfiles and advisories (seconds of CPU for a 100 KB field).
  const s = (opts.multiline ? stripped.replace(/\n{3,}/g, "\n\n") : oneLine(stripped)).trim();
  return s.length > maxLen ? `${s.slice(0, maxLen - 1)}…` : s;
}

/** Lines joined by a single space, blank lines dropped (what /\s*\n\s* / → " " did). */
function oneLine(s: string): string {
  if (!s.includes("\n")) return s;
  return s.split("\n").map((l) => l.trim()).filter(Boolean).join(" ");
}
