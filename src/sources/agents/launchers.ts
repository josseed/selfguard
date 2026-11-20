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
  /** An unknown option before the package makes it unclear what runs: nothing is checked. */
  ambiguous?: true;
}

/** Thrown by the flag parsers on an ambiguous flag; parseLaunch turns it into `ambiguous`. */
const AMBIGUOUS = Symbol("ambiguous");

/**
 * Which flags take the next argument as their value ("--flag=value" is one token anyway). A
 * flag in neither list is ambiguous when a plain word follows it: npx's own argv pre-pass reads
 * that word as the flag's value, npm's parser then reads it as the package. Guessing either way
 * is wrong (a secret, `--_authToken npm_…`, taken for the package and sent to OSV, or a package
 * hidden behind a flag), so such a server is skipped as unparseable.
 */
interface FlagSpec {
  values: ReadonlySet<string>;
  switches: ReadonlySet<string>;
  /** `--no-x` never takes a value (npm's parser; not uv, whose `--no-build-package` does). */
  negations: boolean;
}

const NPM_FLAGS: FlagSpec = {
  values: new Set([
    "--registry", "--reg", "--cache", "--prefix", "-C", "--userconfig", "--globalconfig", "--workspace", "-w",
    "--node-options", "--shell", "--script-shell", "--loglevel", "--location", "-L", "--before", "--tag", "--scope",
    "--ca", "--cafile", "--cert", "--key", "--proxy", "--https-proxy", "--noproxy", "--otp", "--_auth", "--auth-type",
    "--fetch-retries", "--fetch-timeout", "--omit", "--include", "--install-strategy", "--logs-dir", "--logs-max",
    "--user-agent", "--replace-registry-host", "--os", "--cpu", "--libc", "--node-gyp", "--maxsockets", "--local-address",
    "--dir", "--filter", "-F", "--reporter", "--allow-build", "--cwd", // pnpm, yarn, bun
  ]),
  switches: new Set([
    "-y", "--yes", "-n", "--no", "-q", "--quiet", "-s", "--silent", "-d", "-dd", "-ddd", "--verbose", "-f", "--force",
    "-g", "--global", "-ws", "--workspaces", "-iwr", "--include-workspace-root", "--prefer-offline", "--prefer-online",
    "--offline", "--ignore-scripts", "--legacy-peer-deps", "--strict-peer-deps", "--foreground-scripts", "--install-links",
    "--audit", "--fund", "--update-notifier", "--progress", "--color", "--strict-ssl", "--unicode", "--timing", "--json",
    "--dry-run", "-v", "--version", "-h", "--help", "--bun", // bunx
  ]),
  negations: true,
};
const UV_FLAGS: FlagSpec = {
  values: new Set([
    "--with", "-w", "--with-editable", "--with-requirements", "--with-executables-from", "--python", "-p", "--index",
    "--index-url", "-i", "--extra-index-url", "--default-index", "--find-links", "-f", "--constraints", "--constraint", "-c",
    "--overrides", "--build-constraints", "--build-constraint", "-b", "--directory", "--project", "--config-file",
    "--cache-dir", "--python-preference", "--color", "--index-strategy", "--keyring-provider", "--resolution", "--prerelease",
    "--exclude-newer", "--exclude-newer-package", "--refresh-package", "--reinstall-package", "--upgrade-package", "-P",
    "--no-build-package", "--no-binary-package", "--no-build-isolation-package", "--config-setting", "-C", "--env-file",
    "--allow-insecure-host", "--link-mode", "--fork-strategy", "--torch-backend", "--python-platform",
  ]),
  switches: new Set([
    "-q", "--quiet", "-v", "--verbose", "-n", "--no-cache", "--offline", "--native-tls", "--isolated", "--no-config",
    "--no-progress", "--no-python-downloads", "--managed-python", "--no-managed-python", "--preview", "--no-preview",
    "--refresh", "--reinstall", "-U", "--upgrade", "--compile-bytecode", "--no-build", "--no-binary", "--no-sources",
    "--no-build-isolation", "--no-index", "--no-env-file", "--show-resolution", "-h", "--help", "-V", "--version",
  ]),
  negations: false,
};
const PIPX_FLAGS: FlagSpec = {
  values: new Set(["--python", "--pip-args", "--index-url", "-i", "--backend"]),
  switches: new Set([
    "-v", "--verbose", "-q", "--quiet", "--no-cache", "--pypackages", "--system-site-packages", "-e", "--editable",
    "--fetch-missing-python", "-h", "--help", "--version",
  ]),
  negations: false,
};

/** The executable's base name, without a Windows extension: "/opt/homebrew/bin/npx" -> "npx". */
export const commandName = (command: string): string =>
  (command.split(/[\\/]/).pop() ?? "").replace(/\.(cmd|exe|bat|ps1)$/i, "").toLowerCase();

interface Parsed {
  positionals: string[];
  values: Map<string, string[]>;
  /** Saw a flag that runs a shell command instead of a package (npx -c). */
  call: boolean;
}

/** A flag that is in neither list and is followed by a plain word: its value or the package? */
function ambiguous(flag: string, next: string | undefined, spec: FlagSpec): boolean {
  if (spec.switches.has(flag) || (spec.negations && flag.startsWith("--no-"))) return false;
  return next !== undefined && !next.startsWith("-");
}

/**
 * Positionals, and the values of `wanted` flags in their "--flag value" and "--flag=value"
 * forms. Throws AMBIGUOUS when an unknown flag makes it unclear which argument is the package.
 */
function parseFlags(args: string[], spec: FlagSpec, wanted: Record<string, string>): Parsed {
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
    else if (canonical || spec.values.has(flag)) value = args[++i];
    else if (ambiguous(flag, args[i + 1], spec)) throw AMBIGUOUS;
    if (canonical && value !== undefined) out.values.set(canonical, [...(out.values.get(canonical) ?? []), value]);
  }
  return out;
}

const NPM_WANTED = { "-p": "package", "--package": "package", "--call": "call", "-c": "call", "--shell-mode": "call" };

/** npx-like: packages from -p/--package, else the first positional. */
function npmLike(launcher: string, args: string[]): Launch | null {
  const p = parseFlags(args, NPM_FLAGS, NPM_WANTED);
  const specs = p.values.get("package") ?? (p.call ? [] : p.positionals.slice(0, 1));
  const packages = specs.map(parseNpmSpec).filter((s): s is PackageSpec => s !== null);
  return packages.length ? { launcher, packages } : null;
}

function uvx(launcher: string, args: string[]): Launch | null {
  const p = parseFlags(args, UV_FLAGS, { "--from": "from" });
  const from = p.values.get("from");
  const spec = from ? from[0] : p.positionals[0];
  const pkg = spec !== undefined ? parsePySpec(spec) : null;
  return pkg ? { launcher, packages: [pkg] } : null;
}

function pipxRun(args: string[]): Launch | null {
  const p = parseFlags(args, PIPX_FLAGS, { "--spec": "spec" });
  const spec = p.values.get("spec")?.[0] ?? p.positionals[0];
  const pkg = spec !== undefined ? parsePySpec(spec) : null;
  return pkg ? { launcher: "pipx run", packages: [pkg] } : null;
}

/** Skip global flags before a subcommand ("pnpm --silent dlx x"), with the same rules. */
function subcommand(args: string[], spec: FlagSpec): { sub: string; rest: string[] } | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") return null;
    if (!a.startsWith("-") || a === "-") return { sub: a, rest: args.slice(i + 1) };
    if (a.startsWith("--") && a.includes("=")) continue;
    if (spec.values.has(a)) i++;
    else if (ambiguous(a, args[i + 1], spec)) throw AMBIGUOUS;
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
  try {
    return launchOf(name, argv);
  } catch (e) {
    if (e === AMBIGUOUS) return { launcher: name, packages: [], ambiguous: true };
    throw e;
  }
}

function launchOf(name: string, argv: string[]): Launch | null {
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
      const s = subcommand(argv, NPM_FLAGS);
      return s?.sub === "x" ? npmLike("bunx", s.rest) : null;
    }
    case "pnpm":
    case "yarn": {
      const s = subcommand(argv, NPM_FLAGS);
      return s?.sub === "dlx" ? npmLike(`${name} dlx`, s.rest) : null;
    }
    case "npm": {
      const s = subcommand(argv, NPM_FLAGS);
      return s && (s.sub === "exec" || s.sub === "x") ? npmLike("npm exec", s.rest) : null;
    }
    case "uv": {
      const s = subcommand(argv, UV_FLAGS);
      const t = s?.sub === "tool" ? subcommand(s.rest, UV_FLAGS) : null;
      return t?.sub === "run" ? uvx("uvx", t.rest) : null;
    }
    case "pipx": {
      const s = subcommand(argv, PIPX_FLAGS);
      return s?.sub === "run" ? pipxRun(s.rest) : null;
    }
    default:
      return null;
  }
}
