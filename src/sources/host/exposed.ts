/**
 * Exposed local services (docs/host.md): a developer service listening on all interfaces or a
 * LAN address instead of 127.0.0.1/::1, reachable by anyone on the same network. A snapshot of
 * the listening sockets, not a file: see SourceExtractor.snapshot.
 */
import { clean } from "../../sanitize.ts";
import type { ExtractResult, SourceExtractor, SourceTarget } from "../types.ts";
import { NONE } from "./fs.ts";
import { listening, socketsDisabled } from "./listening.ts";
import type { Listener } from "./sockets.ts";

interface Risky {
  what: string;
  /** Full control of the machine or the browser: announced even on the first check. */
  urgent?: boolean;
  /** How to bind it to 127.0.0.1. */
  fix: string;
}

/** Ports whose services are dangerous when reachable from the network (any process). */
export const RISKY_PORTS: ReadonlyMap<number, Risky> = new Map<number, Risky>([
  [9222, { what: "Chrome/Electron remote debugging (full browser takeover)", urgent: true, fix: "drop --remote-debugging-address=0.0.0.0 (the default is 127.0.0.1)" }],
  [9229, { what: "Node.js inspector (remote code execution)", urgent: true, fix: "use --inspect=127.0.0.1:9229, never --inspect=0.0.0.0" }],
  [6277, { what: "MCP Inspector proxy (remote code execution, CVE-2025-49596)", urgent: true, fix: "update @modelcontextprotocol/inspector to 0.14.1+ and set HOST=127.0.0.1" }],
  [6274, { what: "MCP Inspector UI (CVE-2025-49596)", fix: "update @modelcontextprotocol/inspector to 0.14.1+ and set HOST=127.0.0.1" }],
  [2375, { what: "Docker API without TLS (root on this machine)", urgent: true, fix: "remove the tcp://0.0.0.0:2375 host from the Docker daemon, or use an SSH context" }],
  [11434, { what: "Ollama API (no authentication)", fix: "set OLLAMA_HOST=127.0.0.1" }],
  [8888, { what: "Jupyter (code execution)", fix: "start it with --ip=127.0.0.1" }],
  [8265, { what: "Ray dashboard (job submission runs code)", fix: "start it with --dashboard-host=127.0.0.1" }],
  [6379, { what: "Redis", fix: "set `bind 127.0.0.1 -::1` in redis.conf" }],
  [5432, { what: "PostgreSQL", fix: "set listen_addresses = 'localhost'" }],
  [3306, { what: "MySQL", fix: "set bind-address = 127.0.0.1" }],
  [27017, { what: "MongoDB", fix: "set net.bindIp: 127.0.0.1" }],
  [9200, { what: "Elasticsearch", fix: "set network.host: 127.0.0.1" }],
  [11211, { what: "memcached", fix: "start it with -l 127.0.0.1" }],
]);

/**
 * Processes that are system or desktop daemons: they listen on all interfaces on purpose (or by
 * design) and aren't developer services. Skipped, except on a risky port (RISKY_PORTS).
 */
export const SYSTEM_PROCESSES: ReadonlySet<string> = new Set(
  [
    "launchd", "rapportd", "controlcenter", "sharingd", "identityservicesd", "airplayxpchelper", "airplayuiagent", "remoted",
    "mdnsresponder", "netbiosd", "cupsd", "sshd", "smbd", "systemd", "systemd-resolve", "systemd-resolved", "avahi-daemon", "cupsd",
    "dnsmasq", "chronyd", "rpcbind", "sunrpcd", "tailscaled", "tailscale", "ssh-agent", "apsd", "assistantd", "universalaccessd",
  ].map((n) => n.toLowerCase()),
);

/** Developer runtimes and tools: any of them on all interfaces is worth a low-key note. */
const DEV_PROCESSES = /^(node|nodejs|bun|deno|npm|npx|pnpm|yarn|vite|next-server|webpack|python[\d.]*|uvicorn|gunicorn|flask|ruby|rails|puma|java|php|php-fpm|go|cargo|dotnet|ollama|jupyter[\w-]*|ray[\w:-]*|mcp[\w-]*|redis-server|postgres|mysqld|mongod|docker-proxy|com\.docker\.backend)$/;

const isDevProcess = (name: string): boolean => DEV_PROCESSES.test(name.toLowerCase());
const isSystem = (name: string): boolean => SYSTEM_PROCESSES.has(name.toLowerCase());
const exposed = (l: Listener): boolean => l.reach === "wildcard" || l.reach === "lan";

type Warning = ExtractResult["warnings"][number];

/** Warnings for these sockets: one per process and port (IPv4 and IPv6 are the same service). */
export function exposureWarnings(listeners: Listener[]): Warning[] {
  const out = new Map<string, Warning>();
  for (const l of listeners) {
    if (!exposed(l)) continue;
    const proc = l.command ?? "";
    const risky = RISKY_PORTS.get(l.port);
    // A risky port is never hidden behind a system-looking name (any binary can be called sharingd).
    if (isSystem(proc) && !risky) continue;
    const who = proc ? clean(proc, 40) : "a process";
    const key = `${l.port}/${proc || "?"}`;
    if (out.has(key)) continue;
    const where = l.reach === "wildcard" ? "all network interfaces" : "a LAN address";
    if (risky) {
      out.set(key, {
        rule: "exposed-dev-service",
        severity: "high",
        notify: true,
        ...(risky.urgent ? { urgent: true } : {}),
        key,
        line: 0,
        message: `${who} listens on ${where}, port ${l.port} (${risky.what}): anyone on the same network can reach it. Bind it to 127.0.0.1: ${risky.fix}.`,
      });
    } else if (proc && isDevProcess(proc)) {
      out.set(key, {
        rule: "exposed-local-service",
        severity: "low",
        key,
        line: 0,
        message: `${who} listens on ${where}, port ${l.port}: anyone on the same Wi-Fi can reach it. If it is a dev server, bind it to 127.0.0.1 (drop --host or 0.0.0.0).`,
      });
    }
  }
  return [...out.values()];
}

/** Listening sockets as warnings; none when they can't be read. Machine scope only. */
function snapshot(target: SourceTarget): ExtractResult {
  if (target.scope !== "machine") return NONE;
  // Off (SELFGUARD_NO_SOCKETS=1) or unsupported system: nothing to report, so old warnings resolve.
  if (socketsDisabled()) return NONE;
  const sockets = listening();
  // Unreadable (lsof missing or timed out): throw, so the core keeps the last snapshot's warnings
  // (for a week at most).
  if (!sockets) throw new Error("listening sockets unavailable");
  return { refs: [], warnings: exposureWarnings(sockets), skipped: 0 };
}

export const EXPOSED_SERVICES: SourceExtractor = {
  id: "exposed-services",
  kind: "host",
  files: () => [],
  markers: () => [],
  snapshot,
  extract: () => NONE,
};
