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
  const s = (opts.multiline ? stripped.replace(/\n{3,}/g, "\n\n") : stripped.replace(/\s*\n\s*/g, " ")).trim();
  return s.length > maxLen ? `${s.slice(0, maxLen - 1)}…` : s;
}
