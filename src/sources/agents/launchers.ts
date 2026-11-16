/**
 * An MCP server's `command` and `args` -> the packages its launcher downloads and runs.
 * Supported: npx, bunx, pnpm dlx (pnpx), yarn dlx, npm exec (npm x) -> npm; uvx (uv tool
 * run), pipx run -> PyPI. A command given as a path (/opt/homebrew/bin/npx) counts too.
 * Anything else (docker, node /path, python /path, other binaries) is not checked. Only the
 * package specs are kept: other arguments may hold secrets and are never returned.
 */
import { parseNpmSpec, parsePySpec, type PackageSpec } from "./specs.ts";

export interface Launch {
  launcher: string;
  packages: PackageSpec[];
}

/** Flags that take a value as the next argument (a "--flag=value" form is one token anyway). */
const NPM_VALUE_FLAGS = new Set(["--registry", "--cache", "--prefix", "--userconfig", "--workspace", "-w", "--node-options", "--shell", "--script-shell"]);
const UV_VALUE_FLAGS = new Set([
  "--with", "--with-editable", "--with-requirements", "--python", "-p", "--index", "--index-url", "--extra-index-url",
  "--default-index", "--find-links", "-f", "--constraint", "-c", "--overrides", "--build-constraint", "-b", "--directory",
  "--project", "--config-file", "--cache-dir", "--python-preference", "--color", "--index-strategy", "--keyring-provider",
  "--resolution", "--prerelease", "--exclude-newer", "--refresh-package", "--reinstall-package", "--upgrade-package",
  "-P", "--env-file", "--allow-insecure-host", "--link-mode", "--compile-bytecode",
]);
const PIPX_VALUE_FLAGS = new Set(["--python", "--pip-args", "--index-url", "-i", "--backend"]);

/** The executable's base name, without a Windows extension: "/opt/homebrew/bin/npx" -> "npx". */
export const commandName = (command: string): string =>
  (command.split(/[\\/]/).pop() ?? "").replace(/\.(cmd|exe|bat|ps1)$/i, "").toLowerCase();

interface Parsed {
  positionals: string[];
  values: Map<string, string[]>;
  /** Saw a flag that runs a shell command instead of a package (npx -c). */
  call: boolean;
}

/** Positionals, and the values of `wanted` flags in their "--flag value" and "--flag=value" forms. */
function parseFlags(args: string[], valueFlags: Set<string>, wanted: Record<string, string>): Parsed {
  const out: Parsed = { positionals: [], values: new Map(), call: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (out.positionals.length > 0) {
      out.positionals.push(a); // flags after the package belong to the server
      continue;
    }
    if (a === "--") {
      out.positionals.push(...args.slice(i + 1, i + 2));
      break;
    }
    if (!a.startsWith("-") || a === "-") {
      out.positionals.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const flag = a.startsWith("--") && eq > 0 ? a.slice(0, eq) : a;
    const canonical = wanted[flag];
    if (canonical === "call") out.call = true;
    let value: string | undefined;
    if (flag !== a) value = a.slice(eq + 1);
    else if (canonical || valueFlags.has(flag)) value = args[++i];
    if (canonical && value !== undefined) out.values.set(canonical, [...(out.values.get(canonical) ?? []), value]);
  }
  return out;
}

const NPM_WANTED = { "-p": "package", "--package": "package", "--call": "call", "-c": "call" };

/** npx-like: packages from -p/--package, else the first positional. */
function npmLike(launcher: string, args: string[], valueFlags = NPM_VALUE_FLAGS): Launch | null {
  const p = parseFlags(args, valueFlags, NPM_WANTED);
  const specs = p.values.get("package") ?? (p.call ? [] : p.positionals.slice(0, 1));
  const packages = specs.map(parseNpmSpec).filter((s): s is PackageSpec => s !== null);
  return packages.length ? { launcher, packages } : null;
}

function uvx(launcher: string, args: string[]): Launch | null {
  const p = parseFlags(args, UV_VALUE_FLAGS, { "--from": "from" });
  const from = p.values.get("from");
  const spec = from ? from[0] : p.positionals[0];
  const pkg = spec !== undefined ? parsePySpec(spec) : null;
  return pkg ? { launcher, packages: [pkg] } : null;
}

function pipxRun(args: string[]): Launch | null {
  const p = parseFlags(args, PIPX_VALUE_FLAGS, { "--spec": "spec" });
  const spec = p.values.get("spec")?.[0] ?? p.positionals[0];
  const pkg = spec !== undefined ? parsePySpec(spec) : null;
  return pkg ? { launcher: "pipx run", packages: [pkg] } : null;
}

/** Skip global flags before a subcommand ("pnpm --silent dlx x"). */
function subcommand(args: string[]): { sub: string; rest: string[] } | null {
  for (let i = 0; i < args.length; i++) {
    if (!args[i]!.startsWith("-")) return { sub: args[i]!, rest: args.slice(i + 1) };
  }
  return null;
}

/** null: not a launcher we check (docker, node, local binaries) or no registry package. */
export function parseLaunch(command: unknown, args: unknown): Launch | null {
  if (typeof command !== "string" || !command.trim()) return null;
  let argv = Array.isArray(args) ? args.filter((a): a is string => typeof a === "string") : [];
  let cmd = command.trim();
  // "npx -y pkg" written as one command string, with no args.
  if (argv.length === 0 && /\s/.test(cmd)) {
    const parts = cmd.split(/\s+/);
    cmd = parts[0]!;
    argv = parts.slice(1);
  }
  let name = commandName(cmd);
  // Windows: "cmd /c npx -y pkg".
  if (name === "cmd" && argv[0]?.toLowerCase() === "/c" && argv[1]) {
    name = commandName(argv[1]);
    argv = argv.slice(2);
  }
  switch (name) {
    case "npx":
      return npmLike("npx", argv);
    case "bunx":
      return npmLike("bunx", argv);
    case "pnpx":
      return npmLike("pnpm dlx", argv);
    case "uvx":
      return uvx("uvx", argv);
    case "bun": {
      const s = subcommand(argv);
      return s?.sub === "x" ? npmLike("bunx", s.rest) : null;
    }
    case "pnpm":
    case "yarn": {
      const s = subcommand(argv);
      return s?.sub === "dlx" ? npmLike(`${name} dlx`, s.rest) : null;
    }
    case "npm": {
      const s = subcommand(argv);
      return s && (s.sub === "exec" || s.sub === "x") ? npmLike("npm exec", s.rest) : null;
    }
    case "uv": {
      const s = subcommand(argv);
      if (s?.sub === "tool" && s.rest[0] === "run") return uvx("uvx", s.rest.slice(1));
      return null;
    }
    case "pipx": {
      const s = subcommand(argv);
      return s?.sub === "run" ? pipxRun(s.rest) : null;
    }
    default:
      return null;
  }
}
