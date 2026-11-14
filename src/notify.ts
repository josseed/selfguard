import { execFile } from "node:child_process";
import { clean } from "./sanitize.ts";

/*
 * macOS alerts via osascript. Untrusted text (package names, advisory text) is always
 * passed as argv to an `on run` handler, never interpolated into AppleScript source,
 * so it cannot inject script.
 */

const enabled = (): boolean => process.platform === "darwin" && process.env.SELFGUARD_NO_NOTIFY !== "1";

function osascript(lines: string[], argv: string[], timeoutMs: number): Promise<string> {
  const args = lines.flatMap((line) => ["-e", line]);
  args.push(...argv);
  return new Promise((resolve) => {
    execFile("/usr/bin/osascript", args, { timeout: timeoutMs }, (_err, stdout) => resolve(String(stdout ?? "").trim()));
  });
}

/** Banner in the corner + Notification Center. */
export function notify(title: string, message: string, subtitle = ""): Promise<void> {
  if (!enabled()) return Promise.resolve();
  return osascript(
    ["on run argv", "display notification (item 1 of argv) with title (item 2 of argv) subtitle (item 3 of argv)", "end run"],
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
      'set r to display alert (item 1 of argv) message (item 2 of argv) as critical buttons {"Dismiss", "Open advisory"} default button "Open advisory" giving up after 1800',
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
