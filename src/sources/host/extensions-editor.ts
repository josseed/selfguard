/**
 * Editor extensions (VS Code, Insiders, Cursor, Windsurf, VSCodium and a few forks): the list
 * each editor keeps in `<editor folder>/extensions/extensions.json`, read as data. Nothing is
 * loaded or run, no network. Rules (all keyed by the extension id):
 * - malicious-extension (high, urgent): on the bundled list of publicly reported ones.
 * - hidden-unicode (high, urgent): invisible Unicode in its `main`/`browser` file (GlassWorm).
 * - sideloaded-extension (moderate, N): installed from a .vsix or a URL, not a marketplace.
 * - editor-extension (low, N): every extension, so a new one is announced once.
 * Only extensions.json is a record file: it changes when an extension is installed, updated or
 * removed, and the entry points are scanned in that same pass (see extensions-editor-code.ts).
 */
import { dirname, join } from "node:path";
import { isObject } from "../../fsutil.ts";
import { clean } from "../../sanitize.ts";
import type { ExtractResult, SourceExtractor, SourceTarget } from "../types.ts";
import { scanExtensionCode, extensionFolder } from "./extensions-editor-code.ts";
import { deniedExtension } from "./extensions-editor-denylist.ts";
import { home, isDir, NONE } from "./fs.ts";

/** Dot folders of the editors (same layout on macOS and Linux); each has an `extensions` folder. */
const EDITORS: Array<{ dir: string; name: string }> = [
  { dir: ".vscode", name: "VS Code" },
  { dir: ".vscode-insiders", name: "VS Code Insiders" },
  { dir: ".vscode-oss", name: "VSCodium" },
  { dir: ".vscode-server", name: "VS Code Server" },
  { dir: ".cursor", name: "Cursor" },
  { dir: ".windsurf", name: "Windsurf" },
  { dir: ".kiro", name: "Kiro" },
  { dir: ".antigravity", name: "Antigravity" },
];

/**
 * Entries fully handled per extensions.json (every entry is checked against the denylist first),
 * and the code scanned per extractor call, shared fairly: each extension gets its turn's share
 * of what is left, never less than MIN_SHARE.
 */
export const MAX_EXTENSIONS = 400;
export const MAX_SCAN_BYTES = 64 * 1024 * 1024;
const MIN_SHARE = 128 * 1024;
const ID = /^[a-z0-9][a-z0-9-]{0,99}\.[a-z0-9][a-z0-9._-]{0,99}$/i;
const VERSION = /^[0-9a-z][0-9a-z.+_-]{0,63}$/i;

const roots = (): Array<{ root: string; name: string }> => EDITORS.map((e) => ({ root: join(home(), e.dir, "extensions"), name: e.name }));
const machine = (target: SourceTarget): boolean => target.scope === "machine";

interface Entry {
  id: string;
  version: string;
  folder: unknown;
  source: unknown;
  builtin: boolean;
}

function entries(text: string): Entry[] {
  let list: unknown;
  try {
    list = JSON.parse(text);
  } catch {
    return [];
  }
  if (!Array.isArray(list)) return [];
  const out: Entry[] = [];
  for (const raw of list) {
    if (!isObject(raw) || !isObject(raw.identifier)) continue;
    const id = raw.identifier.id;
    if (typeof id !== "string" || !ID.test(id)) continue;
    const meta = isObject(raw.metadata) ? raw.metadata : {};
    out.push({
      id,
      version: typeof raw.version === "string" && VERSION.test(raw.version) ? raw.version : "unknown",
      folder: raw.relativeLocation,
      source: meta.source,
      builtin: meta.isBuiltin === true,
    });
  }
  return out;
}

export function extractEditorExtensions(file: string, text: string): ExtractResult {
  const root = dirname(file);
  const editor = roots().find((r) => r.root === root)?.name ?? "an editor";
  const warnings: ExtractResult["warnings"] = [];
  const seen = new Set<string>();
  let budget = MAX_SCAN_BYTES;
  const add = (w: Omit<ExtractResult["warnings"][number], "line">) => {
    const k = `${w.rule}|${w.key}`;
    if (!seen.has(k)) (seen.add(k), warnings.push({ ...w, line: 0, notify: true }));
  };
  const all = entries(text);
  let left = Math.min(all.length, MAX_EXTENSIONS);
  for (const [n, e] of all.entries()) {
    const key = e.id.toLowerCase();
    const who = `"${clean(e.id, 200)}" ${clean(e.version, 64)} in ${editor}`;
    if (deniedExtension(e.id, e.version)) {
      add({ rule: "malicious-extension", severity: "high", key, urgent: true, message: `Extension ${who} was publicly reported as malicious or compromised. Uninstall it and rotate the secrets on this machine.` });
    }
    if (n >= MAX_EXTENSIONS) continue; // past the limit only the denylist applies
    const dir = extensionFolder(root, e.folder);
    const share = Math.max(MIN_SHARE, Math.floor(budget / left--));
    if (dir) {
      const scan = scanExtensionCode(dir, share);
      budget -= scan.bytes;
      if (scan.problems.length) {
        add({ rule: "hidden-unicode", severity: "high", key, urgent: true, message: `Extension ${who} hides ${scan.problems.join(" and ")} in its code (the GlassWorm technique). Uninstall it and rotate the secrets on this machine.` });
      }
    }
    if (e.source === "vsix" || e.source === "resource") {
      add({ rule: "sideloaded-extension", severity: "moderate", key, message: `Extension ${who} was installed from a file or URL, not from a marketplace.` });
    }
    if (!e.builtin) add({ rule: "editor-extension", severity: "low", key, message: `Editor extension ${who}` });
  }
  return { refs: [], warnings, skipped: 0 };
}

const dirs = (target: SourceTarget): string[] => (machine(target) ? roots().map((r) => r.root) : []);

export const EDITOR_EXTENSIONS: SourceExtractor = {
  id: "host-editor-extensions",
  kind: "host",
  files: (target) => dirs(target).map((d) => join(d, "extensions.json")),
  // Installing or removing an extension changes the folder's mtime (and rewrites extensions.json).
  markers: (target) => dirs(target),
  watch: (target) => dirs(target).filter(isDir),
  extract: (file, text, target) => (machine(target) ? extractEditorExtensions(file, text) : NONE),
};
