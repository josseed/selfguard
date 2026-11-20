/**
 * Python startup hooks: `.pth` files whose `import` lines Python runs at every start, and
 * sitecustomize.py / usercustomize.py (the LiteLLM compromises used both). Read in the
 * site-packages folders of a repo's virtualenvs and, machine-wide, of uv tools, pipx and the
 * user site. Only those folders are listed, never the packages inside them.
 */
import { basename, dirname, join } from "node:path";
import type { ExtractResult, SourceExtractor, SourceTarget } from "../types.ts";
import { home, isDir, names, NONE } from "./fs.ts";
import { benignPth, DANGEROUS } from "./python-allow.ts";

const MAX_ENVS = 100;
const MAX_HOOKS_PER_DIR = 40;
const VENVS = [".venv", "venv", "env"];
const CUSTOMIZE = new Set(["sitecustomize.py", "usercustomize.py"]);

/** `lib/python3.*\/site-packages` of a virtualenv (or a uv/pipx environment). */
function venvSites(env: string): string[] {
  const lib = join(env, "lib");
  return names(lib, 20)
    .filter((n) => /^python3(\.\d+)?t?$/.test(n))
    .map((n) => join(lib, n, "site-packages"))
    .filter(isDir);
}

/** Folders holding one environment per tool. */
const toolHomes = (): string[] => [
  join(home(), ".local", "share", "uv", "tools"),
  join(home(), ".local", "pipx", "venvs"),
  join(home(), ".local", "share", "pipx", "venvs"),
];

function userSites(): string[] {
  const mac = join(home(), "Library", "Python");
  const local = join(home(), ".local", "lib");
  return [
    ...names(mac, 20).filter((n) => /^3\.\d+$/.test(n)).map((n) => join(mac, n, "lib", "python", "site-packages")),
    ...names(local, 20).filter((n) => /^python3(\.\d+)?$/.test(n)).map((n) => join(local, n, "site-packages")),
  ].filter(isDir);
}

/** Every site-packages folder to read for a target. */
export function siteDirs(target: SourceTarget): string[] {
  if (target.scope === "repo") return VENVS.flatMap((v) => venvSites(join(target.root, v)));
  const tools = toolHomes().flatMap((dir) => names(dir, MAX_ENVS).flatMap((env) => venvSites(join(dir, env))));
  return [...userSites(), ...tools];
}

const isHook = (name: string): boolean => name.endsWith(".pth") || CUSTOMIZE.has(name);

function files(target: SourceTarget): string[] {
  return siteDirs(target).flatMap((dir) => names(dir, 5000).filter(isHook).slice(0, MAX_HOOKS_PER_DIR).map((n) => join(dir, n)));
}

/** Folders whose mtime changes when an environment or a hook appears (no walk). */
function markers(target: SourceTarget): string[] {
  const sites = siteDirs(target);
  const parents = sites.flatMap((s) => [dirname(s), dirname(dirname(s))]);
  const roots =
    target.scope === "repo"
      ? VENVS.map((v) => join(target.root, v))
      : [...toolHomes(), join(home(), "Library", "Python"), join(home(), ".local", "lib")];
  return [...new Set([...roots, ...parents, ...sites])];
}

/** Which environment a site-packages folder belongs to, for messages: ".venv", "uv tool httpie". */
function envName(file: string, target: SourceTarget): string {
  const site = dirname(file);
  if (target.scope === "repo") return `virtualenv ${basename(dirname(dirname(dirname(site))))}`;
  const env = dirname(dirname(dirname(site)));
  const parent = basename(dirname(env));
  if (parent === "tools") return `uv tool ${basename(env)}`;
  if (parent === "venvs") return `pipx app ${basename(env)}`;
  return "your user site-packages";
}

export function extractPythonHook(file: string, text: string, where: string): ExtractResult {
  const name = basename(file);
  const lines = text.split(/\r?\n/);
  if (CUSTOMIZE.has(name)) {
    const bad = DANGEROUS.test(text);
    return {
      refs: [],
      warnings: [
        {
          rule: bad ? "malicious-looking-startup-hook" : "python-startup-hook",
          severity: bad ? "high" : "moderate",
          notify: true,
          key: name,
          line: 0,
          message: bad
            ? `${name} in ${where} runs at every Python start and decodes, evaluates or downloads code: the LiteLLM compromise worked this way. Remove the environment and rotate credentials.`
            : `${name} in ${where} runs at every Python start. Packages rarely ship one: check where it came from.`,
        },
      ],
      skipped: 0,
    };
  }
  // Python executes the lines of a .pth file that start with "import"; the others are paths.
  const exec = lines.map((l, i) => ({ l, line: i + 1 })).filter(({ l }) => /^import[ \t]/.test(l));
  if (exec.length === 0 || benignPth(name, exec.map((e) => e.l))) return NONE;
  const bad = exec.find(({ l }) => l.length > 1000 || DANGEROUS.test(l));
  const line = (bad ?? exec[0]!).line;
  return {
    refs: [],
    warnings: [
      bad
        ? {
            rule: "malicious-looking-startup-hook",
            severity: "high",
            notify: true,
            urgent: true,
            key: name,
            line,
            message: `${name} in ${where} runs hidden code at every Python start (decodes, evaluates or downloads code), like the LiteLLM .pth stealer. Remove the package that installed it and rotate credentials.`,
          }
        : {
            rule: "python-startup-hook",
            severity: "moderate",
            notify: true,
            key: name,
            line,
            message: `${name} in ${where} runs code at every Python start. Make sure you know which package installed it.`,
          },
    ],
    skipped: 0,
  };
}

export const PYTHON_STARTUP_HOOKS: SourceExtractor = {
  id: "python-startup-hooks",
  kind: "host",
  files,
  markers,
  probe: (target) => (target.scope === "repo" ? VENVS.map((v) => join(target.root, v, "pyvenv.cfg")) : []),
  // The site-packages folders themselves: an install adding a hook wakes the watcher.
  watch: (target) => siteDirs(target).slice(0, 20),
  extract: (file, text, target) => extractPythonHook(file, text, envName(file, target)),
};
