/**
 * Package manager and global git config of this machine: where packages come from (a changed
 * registry or an extra index is how dependency confusion starts); the git rules are in
 * git-machine.ts. Messages name the registry's host only (URLs may embed credentials).
 */
import { join } from "node:path";
import type { ExtractResult, SourceExtractor, SourceTarget, SourceWarning } from "../types.ts";
import { home, NONE } from "./fs.ts";
import { machineGitWarnings } from "./git-machine.ts";

type Warn = Omit<SourceWarning, "file">;

const NPM_HOSTS = new Set(["registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com"]);
const PYPI_HOSTS = new Set(["pypi.org", "pypi.python.org", "files.pythonhosted.org"]);

/** Host of a URL, never its credentials or path; "an unreadable URL" otherwise. */
export function hostOf(raw: string): string {
  try {
    return new URL(raw.trim().replace(/^["']|["']$/g, "")).hostname || "an unreadable URL";
  } catch {
    return "an unreadable URL";
  }
}

/** `key = value` lines of an INI-like file, with their section and 1-based line. */
export function iniEntries(text: string): Array<{ section: string; key: string; value: string; line: number }> {
  const out: Array<{ section: string; key: string; value: string; line: number }> = [];
  let section = "";
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) return;
    const s = /^\[\s*([^\]\s"]+)(?:\s+"[^"]*")?\s*\]/.exec(line);
    if (s) {
      section = s[1]!.toLowerCase();
      return;
    }
    const m = /^([^=:\s]+)\s*[=:]?\s*(.*)$/.exec(line);
    if (m) out.push({ section, key: m[1]!, value: m[2]!.trim(), line: i + 1 });
  });
  return out;
}

function npmrc(text: string): Warn[] {
  const out: Warn[] = [];
  for (const e of iniEntries(text)) {
    // Scoped registries (@corp:registry=) are how private packages are meant to be served.
    if (e.key !== "registry" || !e.value) continue;
    const host = hostOf(e.value);
    if (NPM_HOSTS.has(host)) continue;
    out.push({
      rule: "custom-registry",
      severity: "moderate",
      notify: true,
      key: "npm registry",
      line: e.line,
      message: `npm installs every package from ${host} instead of registry.npmjs.org. Fine for a company mirror you trust; otherwise remove it.`,
    });
  }
  return out;
}

function pipConf(text: string): Warn[] {
  const out: Warn[] = [];
  for (const e of iniEntries(text)) {
    const key = e.key.toLowerCase().replace(/_/g, "-");
    if (key === "extra-index-url" && e.value) {
      out.push({
        rule: "pip-extra-index",
        severity: "moderate",
        notify: true,
        key: "extra-index-url",
        line: e.line,
        message: `pip also looks for packages on ${hostOf(e.value.split(/\s+/)[0]!)} (extra-index-url): a public package with the name of a private one can win (dependency confusion). Prefer a single index that proxies PyPI.`,
      });
    } else if (key === "index-url" && e.value && !PYPI_HOSTS.has(hostOf(e.value))) {
      out.push({
        rule: "custom-registry",
        severity: "moderate",
        notify: true,
        key: "pip index-url",
        line: e.line,
        message: `pip installs every package from ${hostOf(e.value)} instead of pypi.org. Fine for a company mirror you trust; otherwise remove it.`,
      });
    }
  }
  return out;
}

/** The files and what reads each one (paths relative to the home folder). */
const FILES: Array<{ path: string; read: (text: string) => Warn[] }> = [
  { path: ".npmrc", read: npmrc },
  { path: ".config/pip/pip.conf", read: pipConf },
  { path: ".pip/pip.conf", read: pipConf },
  { path: "Library/Application Support/pip/pip.conf", read: pipConf },
  { path: ".gitconfig", read: machineGitWarnings },
  { path: ".config/git/config", read: machineGitWarnings },
];

const pathOf = (rel: string): string => join(home(), ...rel.split("/"));
const files = (target: SourceTarget): string[] => (target.scope === "machine" ? FILES.map((f) => pathOf(f.path)) : []);

export function extractConfig(file: string, text: string): ExtractResult {
  const entry = FILES.find((f) => pathOf(f.path) === file);
  return entry ? { refs: [], warnings: entry.read(text).slice(0, 20), skipped: 0 } : NONE;
}

export const PACKAGE_CONFIG: SourceExtractor = {
  id: "host-package-config",
  kind: "host",
  files,
  markers: files,
  probe: files,
  extract: (file, text, target) => (target.scope === "machine" ? extractConfig(file, text) : NONE),
};
