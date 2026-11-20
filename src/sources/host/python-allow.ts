/**
 * Known `.pth` files that run code for a good reason, recognised by name AND by the shape of
 * every executable line: a stealer reusing a familiar name with other content is still flagged.
 */

/** Code that decodes, evaluates, spawns or downloads: never in a benign startup hook. */
export const DANGEROUS =
  /\b(?:exec|eval|compile)\s*\(|base64|b64decode|\bzlib\b|\bmarshal\b|\bsubprocess\b|os\.system|os\.popen|\burllib\b|\bsocket\b|__import__|http\.client|\brequests\b|\bctypes\b/;

type LineCheck = RegExp | ((line: string) => boolean);

interface AllowedPth {
  name: RegExp;
  /** Every `import` line must pass one of these. */
  lines: LineCheck[];
}

/** A setuptools namespace line: only path and module plumbing, nothing that runs other code. */
function nspkgLine(line: string): boolean {
  if (!line.startsWith("import sys, types, os;") || line.length > 1000 || !line.includes("f_locals['sitedir']")) return false;
  return !DANGEROUS.test(line.replace(/__import__\('importlib\.(?:util|machinery)'\)/g, ""));
}

/** pytest-cov's subprocess hook (older releases): exec of a fixed block importing pytest_cov.embed. */
function pytestCovLine(line: string): boolean {
  if (!line.startsWith("import os, sys;exec('if \\'COV_CORE_SOURCE\\' in os.environ:") || line.length > 1000) return false;
  if (!line.includes("from pytest_cov.embed import init")) return false;
  return !DANGEROUS.test(line.replace("exec('", "'"));
}

export const ALLOWED_PTH: AllowedPth[] = [
  {
    name: /^distutils-precedence\.pth$/,
    lines: [/^import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '(?:local|stdlib)'\) == 'local'; enabled and __import__\('_distutils_hack'\)\.add_shim\(\); ?$/],
  },
  { name: /^_virtualenv\.pth$/, lines: [/^import _virtualenv\s*$/] },
  { name: /^__editable__\..+\.pth$/, lines: [/^import (__editable___[\w.]+_finder); \1\.install\(\)\s*$/] },
  { name: /^.+-nspkg\.pth$/, lines: [nspkgLine] },
  { name: /^pytest-cov\.pth$/, lines: [pytestCovLine] },
  { name: /^pywin32\.pth$/, lines: [/^import pywin32_bootstrap\s*$/] },
  {
    name: /^(?:a1_coverage|coverage|.*coverage.*)\.pth$/,
    lines: [
      /^import coverage; ?coverage\.process_startup\(\)\s*$/,
      /^import os; os\.environ\.get\('COVERAGE_PROCESS_START'\) and __import__\('coverage'\)\.process_startup\(\)\s*$/,
    ],
  },
  {
    name: /^easy-install\.pth$/,
    lines: [
      /^import sys; sys\.__plen = len\(sys\.path\)\s*$/,
      /^import sys; new = sys\.path\[sys\.__plen:\]; del sys\.path\[sys\.__plen:\]; p = getattr\(sys, '__egginsert', 0\); sys\.path\[p:p\] = new; sys\.__egginsert = p \+ len\(new\)\s*$/,
    ],
  },
];

/** True when this `.pth` file is a known benign one (name and every executable line). */
export function benignPth(name: string, importLines: string[]): boolean {
  const entry = ALLOWED_PTH.find((a) => a.name.test(name));
  if (!entry) return false;
  return importLines.every((l) => entry.lines.some((check) => (typeof check === "function" ? check(l) : check.test(l))));
}
