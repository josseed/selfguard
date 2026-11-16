// Shared by the sources tests: a fake OSV server and a fake extractor (tests only).
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import type { SourceExtractor } from "../src/sources/types.ts";

const GHA = "GitHub Actions";

export const VULNS: Record<string, unknown> = {
  "GHSA-mrrh-fwg8-r2c3": {
    id: "GHSA-mrrh-fwg8-r2c3", modified: "2026-01-01T00:00:00Z", summary: "changed-files compromised", database_specific: { severity: "HIGH" },
    affected: [{ package: { ecosystem: GHA, name: "tj-actions/changed-files" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "46.0.1" }] }] }],
  },
  "MAL-2026-7": {
    id: "MAL-2026-7", modified: "2026-01-01T00:00:00Z", summary: "Malicious code in evil/action",
    affected: [{ package: { ecosystem: GHA, name: "evil/action" }, versions: ["1.0.0"] }],
  },
  "GHSA-aaaa-bbbb-cccc": {
    id: "GHSA-aaaa-bbbb-cccc", modified: "2026-01-01T00:00:00Z", summary: "Command injection in lodash", database_specific: { severity: "HIGH" },
    affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
  },
};

/** "ecosystem:name@version" ("@*" for name-only queries) -> advisory ids. */
export const MATCHES: Record<string, string[]> = {
  "GitHub Actions:tj-actions/changed-files@*": ["GHSA-mrrh-fwg8-r2c3"],
  "GitHub Actions:evil/action@*": ["MAL-2026-7"],
  "npm:lodash@4.17.20": ["GHSA-aaaa-bbbb-cccc"],
  "npm:lodash@*": ["GHSA-aaaa-bbbb-cccc"],
};

export const osv = { bodies: [] as any[], fail: false };

const read = (req: IncomingMessage) =>
  new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });

export async function startOsv(): Promise<Server> {
  const server = createServer(async (req, res) => {
    res.setHeader("content-type", "application/json");
    if (osv.fail) {
      res.statusCode = 400; // fatal: no retries
      res.end("{}");
      return;
    }
    if (req.method === "POST" && req.url === "/v1/querybatch") {
      const body = JSON.parse(await read(req));
      osv.bodies.push(body);
      const results = body.queries.map((q: any) => {
        const ids = MATCHES[`${q.package.ecosystem}:${q.package.name}@${q.version ?? "*"}`] ?? [];
        return ids.length ? { vulns: ids.map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) } : {};
      });
      res.end(JSON.stringify({ results }));
      return;
    }
    const m = /^\/v1\/vulns\/(.+)$/.exec(req.url ?? "");
    if (m && VULNS[decodeURIComponent(m[1]!)]) {
      res.end(JSON.stringify(VULNS[decodeURIComponent(m[1]!)]));
      return;
    }
    res.statusCode = 404;
    res.end("{}");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_OSV_API = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`;
  return server;
}

/**
 * Reads `<root>/fake-ci.json`: { refs: [...], warnings: [...], skipped }, as a real extractor
 * would return them (it may also return junk: the core must sanitize it).
 */
export const FAKE_CI: SourceExtractor = {
  id: "fake-ci",
  kind: "ci",
  files: (t) => (t.scope === "repo" ? [join(t.root, "fake-ci.json")] : []),
  watch: (t) => (t.scope === "repo" ? [join(t.root, "fake-ci.json"), join(t.root, ".github")] : []),
  extract: (_file, text) => JSON.parse(text),
};

/** Machine-wide agent configs: `<home>/fake-agents.json`. */
export const FAKE_AGENTS: SourceExtractor = {
  id: "fake-agents",
  kind: "agents",
  files: (t) => (t.scope === "machine" ? [join(t.root, "fake-agents.json")] : []),
  extract: (_file, text) => JSON.parse(text),
};
