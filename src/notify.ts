import { execFile } from "node:child_process";
import { clean } from "./sanitize.ts";

/*
 * macOS alerts via osascript. Untrusted text (package names, advisory text, file names from
 * scanned repos) is always passed as argv to an `on run` handler, never interpolated into
 * AppleScript source. osascript parses options until the first non-option word, so a text
 * starting with "-e" would become another script line: a fixed word goes first (option parsing
 * stops there) and leading dashes are dropped as well.
 */

const enabled = (): boolean => process.platform === "darwin" && process.env.SELFGUARD_NO_NOTIFY !== "1";

/** Fixed first argument: osascript stops parsing options at it, so nothing after is an option. */
const ARGV_GUARD = "selfguard";

/**
 * osascript's arguments for an `on run argv` script `lines` (which must start with
 * "on run argv"): the script reads `a`, the untrusted values, as `item 1 of a`… Pure, for tests.
 */
export function osascriptArgs(lines: string[], argv: string[]): string[] {
  const [first, ...rest] = lines;
  const script = first === "on run argv" ? [first, "set a to rest of argv", ...rest] : lines;
  return [...script.flatMap((line) => ["-e", line]), ARGV_GUARD, ...argv.map((v) => v.replace(/^[\s-]+/, ""))];
}

function osascript(lines: string[], argv: string[], timeoutMs: number): Promise<string> {
  const args = osascriptArgs(lines, argv);
  return new Promise((resolve) => {
    execFile("/usr/bin/osascript", args, { timeout: timeoutMs }, (_err, stdout) => resolve(String(stdout ?? "").trim()));
  });
}

/** Banner in the corner + Notification Center. */
export function notify(title: string, message: string, subtitle = ""): Promise<void> {
  if (!enabled()) return Promise.resolve();
  return osascript(
    ["on run argv", "display notification (item 1 of a) with title (item 2 of a) subtitle (item 3 of a)", "end run"],
    [clean(message, 220), clean(title, 80), clean(subtitle, 120)],
    10_000,
  ).then(() => undefined);
}

/**
 * Blocking dialog that stays on screen until dismissed. Reserved for critical events
 * (malicious packages) so it can't be missed. Returns true if the user chose to open `url`.
 */
export async function criticalDialog(title: string, message: string, url: string): Promise<boolean> {
  if (!enabled()) return false;
  // Only ever open advisory pages we built ourselves.
  if (!/^https:\/\/osv\.dev\/vulnerability\/[A-Za-z0-9._%-]+$/.test(url)) return false;
  const answer = await osascript(
    [
      "on run argv",
      'set r to display alert (item 1 of a) message (item 2 of a) as critical buttons {"Dismiss", "Open advisory"} default button "Open advisory" giving up after 1800',
      'if gave up of r then return ""',
      "return button returned of r",
      "end run",
    ],
    [clean(title, 100), clean(message, 800, { multiline: true })],
    1_900_000,
  );
  if (answer !== "Open advisory") return false;
  await new Promise<void>((resolve) => execFile("/usr/bin/open", [url], { timeout: 10_000 }, () => resolve()));
  return true;
}
