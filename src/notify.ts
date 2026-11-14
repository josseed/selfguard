import { execFile } from "node:child_process";
import { clean } from "./sanitize.ts";

/**
 * Native macOS notification via osascript.
 * Text is passed as argv to an `on run` handler, never interpolated into the
 * AppleScript source, so package names/advisory text cannot inject script.
 */
export function notify(title: string, message: string, subtitle = ""): Promise<void> {
  if (process.platform !== "darwin" || process.env.SELFGUARD_NO_NOTIFY === "1") return Promise.resolve();
  const script = [
    "on run argv",
    "display notification (item 1 of argv) with title (item 2 of argv) subtitle (item 3 of argv)",
    "end run",
  ];
  const args = script.flatMap((line) => ["-e", line]);
  args.push(clean(message, 220), clean(title, 80), clean(subtitle, 120));
  return new Promise((resolve) => {
    execFile("/usr/bin/osascript", args, { timeout: 10_000 }, () => resolve());
  });
}
