// Realistic answers for the dashboard's API calls, for the preview harness only (never shipped).
// Shapes follow src/ui/routes.ts, src/ui/overview.ts and src/api/*.
const now = Date.now();
const at = (minutes) => new Date(now - minutes * 60_000).toISOString();
const HOME = "/Users/dev";

function checkout(path, o = {}) {
  return {
    path, machine: null, branch: "main", worktree: false, orphaned: false, exists: true, active: true,
    lastActivity: at(90), worstSeverity: null, vulnerablePackages: 0, advisories: 0, error: null,
    role: "default-branch", representative: true, ...o,
  };
}

function repo(key, label, folder, checkouts, o = {}) {
  const rep = checkouts.find((k) => k.representative) || checkouts[0];
  return {
    key, label, machine: rep.machine, active: checkouts.some((k) => k.active), dismissedAt: null,
    worstSeverity: rep.worstSeverity, vulnerablePackages: rep.vulnerablePackages,
    inactiveCheckouts: checkouts.filter((k) => !k.active).length,
    folder, checkouts, ...o,
  };
}

const code = { path: `${HOME}/code`, label: "code", root: true };
const acme = { path: `${HOME}/code/acme`, label: "acme", root: false };
const lab = { path: `${HOME}/lab`, label: "lab", root: true };

const repos = [
  repo("web", "web", acme, [
    checkout(`${HOME}/code/acme/web`, { worstSeverity: "critical", vulnerablePackages: 3, advisories: 5, lastActivity: at(40) }),
    checkout(`${HOME}/code/acme/web-feature-login`, { branch: "feature/login", worktree: true, role: "branch", representative: false, worstSeverity: "critical", vulnerablePackages: 4, lastActivity: at(300) }),
  ]),
  repo("api-server", "api-server", acme, [checkout(`${HOME}/code/acme/api`, { worstSeverity: "critical", vulnerablePackages: 7, advisories: 9, lastActivity: at(120) })]),
  repo("mobile", "mobile", acme, [checkout(`${HOME}/code/acme/mobile`, { branch: "develop", worstSeverity: "high", vulnerablePackages: 4, lastActivity: at(60 * 26) })]),
  repo("infra", "infra", code, [checkout(`${HOME}/code/infra`, { worstSeverity: "moderate", vulnerablePackages: 2, lastActivity: at(60 * 30) })]),
  repo("docs-site", "docs-site", code, [checkout(`${HOME}/code/docs-site`, { lastActivity: at(60 * 24 * 3) })]),
  repo("ml-pipeline", "ml-pipeline", lab, [checkout(`${HOME}/lab/ml-pipeline`, { worstSeverity: "low", vulnerablePackages: 1, lastActivity: at(60 * 24 * 12) })]),
  repo("old-prototype", "old-prototype", lab, [checkout(`${HOME}/lab/old-prototype`, { active: false, worstSeverity: "high", vulnerablePackages: 6, lastActivity: at(60 * 24 * 140) })]),
  repo("devbox:billing", "billing", { path: "devbox:/home/dev/src", label: "src", root: true }, [checkout("/home/dev/src/billing", { machine: "devbox", worstSeverity: "high", vulnerablePackages: 2, lastActivity: at(200) })]),
];

const ev = (kind, repoName, minutes, packages, o = {}) => ({
  kind, repo: repoName, repoKey: repoName, branch: "main", at: at(minutes), active: true, firstScan: false,
  total: packages.length || o.total || 0, packages, ...o,
});

const events = [
  ev("new", "web", 300, [{ name: "lodash", version: "4.17.20", ecosystem: "npm", severity: "critical" }]),
  ev("new", "api-server", 120, [
    { name: "express", version: "4.17.1", ecosystem: "npm", severity: "high" },
    { name: "qs", version: "6.5.2", ecosystem: "npm", severity: "high" },
    { name: "jsonwebtoken", version: "8.5.1", ecosystem: "npm", severity: "high" },
  ]),
  ev("resolved", "infra", 60 * 26, [{ name: "axios", version: "0.21.1", ecosystem: "npm", severity: "high" }, { name: "minimist", version: "1.2.5", ecosystem: "npm", severity: "moderate" }]),
  ev("reminder", "3 repos need attention", 60 * 30, [], { repoKey: "reminder", branch: null, total: 3 }),
  ev("watching", `${HOME}/lab`, 60 * 24 * 4, [], { repoKey: `${HOME}/lab`, branch: null, total: 2 }),
  ev("new", "docs-site", 60 * 24 * 9, [{ name: "next", version: "13.4.0", ecosystem: "npm", severity: "moderate" }], { firstScan: true }),
];

export const overview = {
  version: "0.16.0",
  generatedAt: at(0),
  settings: { remind: "daily", activeDays: 30, autoDiscover: true, lastEverywhere: at(60 * 24 * 2), updateCheck: true, lastReminder: at(60 * 30), lastSync: at(62), lastCheck: at(4) },
  schedule: { enabled: true, owner: "app", watcher: false, watchedPaths: 42, remote: true },
  inApp: true,
  update: { enabled: true, current: "0.16.0", latest: "0.16.0", available: false, checkedAt: at(300) },
  share: { enabled: true, requests: 0 },
  machines: [
    { name: "devbox", host: "devbox.tail1234.ts.net", os: "Linux", lastSync: at(14), error: null, trackedProjects: 6, roots: 1 },
    { name: "studio", host: "studio.tail1234.ts.net", os: "macOS", lastSync: at(60 * 5), error: null, trackedProjects: 11, roots: 2 },
  ],
  roots: 3,
  totals: { malicious: 0, critical: 51, high: 215, moderate: 122, low: 17, unknown: 0 },
  needsAttention: ["web", "api-server", "mobile", "devbox:billing"],
  seriousByRepo: { web: 3, "api-server": 7, mobile: 4, "devbox:billing": 2 },
  trackedProjects: 42,
  activeCheckouts: 31,
  repos,
  events,
};

const pkg = (name, sev, fixes, repoList, o = {}) => ({
  name, ecosystem: "npm", worstSeverity: sev, direct: true, dev: false,
  fixes, repos: repoList, advisories: o.advisories || [`GHSA-${name.slice(0, 4)}-x7hr-2rc4`, `GHSA-${name.slice(0, 4)}-8qv2-pm3f`], ...o,
});
const use = (key, version, o = {}) => ({ key, label: key.replace(/^devbox:/, ""), version, direct: true, dev: false, branch: "main", path: `${HOME}/code/acme/${key}`, ...o });

export const packages = [
  pkg("lodash", "critical", [{ version: "4.17.20", worstSeverity: "critical", upgradeTo: "4.17.21" }], [use("web", "4.17.20"), use("api-server", "4.17.20"), use("mobile", "4.17.20", { direct: false })]),
  pkg("jsonwebtoken", "high", [{ version: "8.5.1", worstSeverity: "high", upgradeTo: "9.0.0" }], [use("api-server", "8.5.1"), use("devbox:billing", "8.5.1")]),
  pkg("express", "high", [{ version: "4.17.1", worstSeverity: "high", upgradeTo: "4.19.2" }, { version: "4.18.1", worstSeverity: "moderate", upgradeTo: "4.19.2" }], [use("api-server", "4.17.1"), use("web", "4.18.1")]),
  pkg("requests", "high", [{ version: "2.25.0", worstSeverity: "high", upgradeTo: "2.31.0" }], [use("mobile", "2.25.0")], { ecosystem: "PyPI" }),
  pkg("node-fetch", "high", [{ version: "2.6.0", worstSeverity: "high", upgradeTo: null }], [use("mobile", "2.6.0")]),
  pkg("semver", "moderate", [{ version: "5.7.1", worstSeverity: "moderate", upgradeTo: "5.7.2" }], [use("infra", "5.7.1", { direct: false })], { direct: false }),
  pkg("postcss", "moderate", [{ version: "8.4.14", worstSeverity: "moderate", upgradeTo: "8.4.31" }], [use("web", "8.4.14", { dev: true })], { dev: true }),
];

const adv = (id, severity, summary) => ({ id, aliases: [], severity, summary, fixedIn: null, firstSeen: at(600), url: "" });
export function repoDetail(key) {
  const g = repos.find((r) => r.key === key) || repos[0];
  const reps = g.checkouts.map((k) => ({ path: k.path, branch: k.branch, active: k.active, representative: k.representative }));
  return {
    ...g,
    packages: [
      { name: "lodash", version: "4.17.20", ecosystem: "npm", direct: true, dev: false, worstSeverity: "critical", upgradeTo: "4.17.21", advisoriesWithoutFix: 0, advisories: [adv("GHSA-35jh-r3h4-6jhm", "critical", "Command injection in lodash"), adv("GHSA-29mw-wpgm-hmr9", "moderate", "Regular expression denial of service")], checkouts: reps },
      { name: "express", version: "4.18.1", ecosystem: "npm", direct: true, dev: false, worstSeverity: "high", upgradeTo: "4.19.2", advisoriesWithoutFix: 1, advisories: [adv("GHSA-rv95-896h-c2vc", "high", "Open redirect in malformed URLs")], checkouts: reps },
      { name: "minimist", version: "1.2.5", ecosystem: "npm", direct: false, dev: false, worstSeverity: "critical", upgradeTo: "1.2.6", advisoriesWithoutFix: 0, advisories: [adv("GHSA-xvch-5gv4-984h", "critical", "Prototype pollution in minimist")], checkouts: reps.slice(1).length ? reps.slice(1) : reps },
      { name: "postcss", version: "8.4.14", ecosystem: "npm", direct: true, dev: true, worstSeverity: "moderate", upgradeTo: "8.4.31", advisoriesWithoutFix: 0, advisories: [adv("GHSA-7fh5-64p2-3v2j", "moderate", "Line return parsing error")], checkouts: reps },
    ],
  };
}

const source = (label, path, findings, warnings, refs) => ({
  label, path, references: refs, skippedReferences: 0, scannedAt: at(30), error: null, findings, warnings,
  vulnerableReferences: findings.length,
});
export const sources = {
  kinds: ["agents", "ci"],
  machine: [
    source("Claude Code", `${HOME}/.claude.json`, [
      { severity: "high", name: "@modelcontextprotocol/server-filesystem", version: "0.5.0", ecosystem: "npm", certainty: "may-be-affected", id: "GHSA-hc55-p739-j48w", summary: "Path validation bypass", locations: [{ file: `${HOME}/.claude.json`, line: 14 }], fixedIn: "0.6.3" },
    ], [], [{ agent: "Claude Code" }, { agent: "Claude Code" }, { agent: "Claude Code" }]),
    source("Cursor", `${HOME}/.cursor/mcp.json`, [], [], [{ agent: "Cursor" }]),
  ],
};
export const repoSources = {
  sources: [source("GitHub Actions", `${HOME}/code/acme/web/.github/workflows`, [], [
    { rule: "unpinned-action", severity: "moderate", message: "actions/checkout is referenced by a tag, not a commit", file: `${HOME}/code/acme/web/.github/workflows/ci.yml`, line: 12 },
  ], [{ agent: null }, { agent: null }])],
};

export const folders = {
  roots: [
    { path: `${HOME}/code`, depth: 5, exists: true, trackedProjects: 34 },
    { path: `${HOME}/lab`, depth: 3, exists: true, trackedProjects: 8 },
    { path: `${HOME}/Desktop/old`, depth: 2, exists: false, trackedProjects: 0 },
  ],
  exclude: [`${HOME}/code/vendor-mirror`],
  ignored: [{ path: `${HOME}/code/archive`, at: at(60 * 24 * 20) }],
  suggestions: [`${HOME}/Projects`, `${HOME}/src`],
};

export const machines = {
  machines: [
    { name: "devbox", host: "devbox.tail1234.ts.net", port: null, transport: "share", mode: "restricted", scope: "~/src", trackedProjects: 6,
      status: { error: null, errorCode: null, lastSync: at(14), os: "Linux", roots: [{ path: "/home/dev/src", ok: true }] },
      roots: [{ path: "~/src", depth: 4 }], exclude: [] },
    { name: "build-01", host: "build-01.internal", port: 2222, transport: "ssh", mode: "restricted", scope: "~", trackedProjects: 0,
      status: { error: "ssh: connect to host build-01.internal port 2222: Operation timed out", errorCode: "unreachable", lastSync: null, os: null, roots: [] },
      roots: [{ path: "~/workspace", depth: 3 }], exclude: ["~/workspace/tmp"] },
  ],
};

export const share = {
  enabled: true, answering: true, addresses: ["100.101.102.103"], port: 7787, tailscale: { ok: true },
  requests: [],
  grants: [{ id: "g1", name: "studio", hostName: "Studio.local", scope: "~/code", lastSeen: at(25) }],
  suggestions: [{ path: "~/code", depth: 5 }],
};

export const peers = {
  tailscale: { ok: true },
  self: { name: "macbook" },
  peers: [
    { nodeId: "n1", name: "devbox", dnsName: "devbox.tail1234.ts.net", os: "linux", online: true, lastSeen: at(1), share: { version: "0.16.0" }, sshPort: 22, tailscaleSsh: false, action: "added", added: "devbox" },
    { nodeId: "n2", name: "studio", dnsName: "studio.tail1234.ts.net", os: "macOS", online: true, lastSeen: at(1), share: { version: "0.16.0" }, sshPort: null, tailscaleSsh: false, action: "connect", added: null },
    { nodeId: "n3", name: "nas", dnsName: "nas.tail1234.ts.net", os: "linux", online: false, lastSeen: at(60 * 24 * 3), share: null, sshPort: null, tailscaleSsh: false, action: "offline", added: null },
  ],
};

export const app = { loginItem: true, mascotAlerts: true, commandLine: { available: true, installed: false } };
export const everywhere = { running: false, result: null, error: null };
