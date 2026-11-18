// Preview harness for the dashboard (development only, never shipped): serves src/ui/static
// over http://127.0.0.1 with a stub of the Mac app's message handler answering from
// fixtures.mjs, under the page's real CSP. Usage: node scripts/dashboard-preview/server.mjs [port]
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import * as F from "./fixtures.mjs";

const STATIC = fileURLToPath(new URL("../../src/ui/static/", import.meta.url));
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json" };

const data = {
  overview: F.overview, packages: { packages: F.packages }, sources: F.sources, repoSources: F.repoSources,
  folders: F.folders, machines: F.machines, share: F.share, peers: F.peers, app: F.app, everywhere: F.everywhere,
  mascot: JSON.parse(readFileSync(join(STATIC, "mascot/manifest.json"), "utf8")),
  repos: Object.fromEntries(F.overview.repos.map((r) => [r.key, F.repoDetail(r.key)])),
};

// Runs in the page before app.js: window.webkit.messageHandlers.selfguard, answering from the fixtures.
const stub = `(() => {
  const D = ${JSON.stringify(data)};
  const GET = {
    "/api/overview": () => D.overview, "/api/packages": () => D.packages, "/api/sources": () => D.sources,
    "/api/repo/sources": () => D.repoSources, "/api/folders": () => D.folders, "/api/machines": () => D.machines,
    "/api/share": () => D.share, "/api/machines/peers": () => D.peers, "/api/app": () => D.app,
    "/api/everywhere/status": () => D.everywhere, "/api/mascot": () => D.mascot,
    "/api/repo": (q) => D.repos[q.get("key")] || D.repos.web,
    "/api/repo/markdown": () => ({ markdown: "# web\\n\\n- lodash 4.17.20 → 4.17.21", packages: 4 }),
  };
  const POST = {
    "/api/sync": () => ({ projects: 42, discovered: [], news: [] }),
    "/api/app": (b) => Object.assign(D.app, b),
  };
  window.webkit = { messageHandlers: { selfguard: { postMessage: async ({ method, path, body }) => {
    const u = new URL(path, location.origin);
    const f = (method === "GET" ? GET : POST)[u.pathname];
    await new Promise((r) => setTimeout(r, 20));
    if (!f) return method === "POST" ? { status: 200, data: {} } : { status: 404, error: { code: "not_found", message: "no such endpoint" } };
    return { status: 200, data: f(u.searchParams, body) };
  } } } };
})();`;

const port = Number(process.argv[2] || 4790);
createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const headers = { "content-security-policy": CSP, "cache-control": "no-store" };
  if (url.pathname === "/__preview/stub.js") {
    res.writeHead(200, { ...headers, "content-type": "text/javascript" });
    return res.end(stub);
  }
  const rel = url.pathname === "/" ? "index.html" : normalize(url.pathname).replace(/^\/+/, "");
  const file = join(STATIC, rel);
  if (!file.startsWith(STATIC) || !existsSync(file) || statSync(file).isDirectory()) {
    res.writeHead(404, headers);
    return res.end("not found");
  }
  let body = readFileSync(file);
  if (rel === "index.html") body = body.toString().replace("<script type=\"module\"", "<script src=\"/__preview/stub.js\"></script>\n  <script type=\"module\"");
  res.writeHead(200, { ...headers, "content-type": TYPES[extname(file)] || "application/octet-stream" });
  res.end(body);
}).listen(port, "127.0.0.1", () => console.log(`dashboard preview: http://127.0.0.1:${port}/`));
