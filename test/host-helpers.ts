// Shared by the host tests: a fresh fake home and system root per test (never the real ones).
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { SourceRecord, SourceTarget } from "../src/sources/types.ts";

/** Point HOME and SELFGUARD_SYSTEM_ROOT at new temp folders; returns them. */
export function freshHome(): { home: string; system: string } {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-host-user-")));
  const system = realpathSync(mkdtempSync(join(tmpdir(), "sg-host-sys-")));
  process.env.HOME = home;
  process.env.SELFGUARD_SYSTEM_ROOT = system;
  return { home, system };
}

export function put(root: string, rel: string, text: string | Buffer): string {
  const file = join(root, ...rel.split("/"));
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text);
  return file;
}

export function plist(label: string, argv: string[], extra = ""): string {
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${esc(label)}</string>
  <key>ProgramArguments</key>
  <array>
${argv.map((a) => `    <string>${esc(a)}</string>`).join("\n")}
  </array>
  <key>RunAtLoad</key>
  <true/>${extra}
</dict>
</plist>
`;
}

type Sources = typeof import("../src/sources.ts");

/** The host record of a target, read now (not saved). */
export function scanHost(sources: Sources, target: SourceTarget): SourceRecord {
  const { inventories } = sources.prepareSources([{ kind: "host", target }]);
  return inventories[0]!.record;
}

/** "severity rule key @basename:line" for compact assertions. */
export function summary(rec: SourceRecord): string[] {
  return rec.warnings.map((w) => `${w.severity} ${w.rule} ${w.key ?? "-"} @${w.file.split("/").pop()}:${w.line}${w.notify ? " N" : ""}`);
}
