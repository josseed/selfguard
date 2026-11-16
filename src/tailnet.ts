/**
 * What Tailscale says about this machine and its peers. Read-only calls to the local
 * `tailscale` CLI (`status --json`, `whois --json <ip>`); nothing goes over the network here.
 * SELFGUARD_TAILSCALE points at another binary (tests use a fake one).
 */
import { execFile, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { SSH_HOST_RE } from "./config.ts";
import { clean } from "./sanitize.ts";

export function tailscaleBin(): string | null {
  const override = process.env.SELFGUARD_TAILSCALE;
  if (override) return existsSync(override) ? override : null;
  for (const p of ["/usr/local/bin/tailscale", "/opt/homebrew/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale", "/usr/bin/tailscale", "/usr/sbin/tailscale"]) {
    if (existsSync(p)) return p;
  }
  return null;
}

type Json = Record<string, unknown>;

function rawStatus(): Json | null {
  const bin = tailscaleBin();
  if (!bin) return null;
  try {
    const raw = JSON.parse(execFileSync(bin, ["status", "--json"], { encoding: "utf8", timeout: 5000, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] }));
    return raw && typeof raw === "object" ? (raw as Json) : null;
  } catch {
    return null;
  }
}

const ipsOf = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && /^[0-9a-fA-F.:]+$/.test(x)) : []);
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const dns = (v: unknown): string => str(v).replace(/\.$/, "");

export type TailnetState =
  | { ok: true }
  | { ok: false; reason: "not_installed" | "not_running"; message: string };

export interface TailnetSelf {
  nodeId: string;
  name: string;
  dnsName: string;
  ips: string[];
  /** Login of the Tailscale user owning this machine (to pair only with your own machines). */
  login: string | null;
}

export interface TailnetPeer {
  /** Stable node ID (survives IP changes). */
  nodeId: string;
  name: string;
  dnsName: string;
  os: string;
  online: boolean;
  /** When the coordination server last saw it (null if online or unknown). */
  lastSeen: string | null;
  ips: string[];
  /** Login of its Tailscale user. */
  login: string | null;
  /** Tailscale SSH is enabled on it (it advertises SSH host keys). */
  tailscaleSsh: boolean;
}

export interface Tailnet {
  state: TailnetState;
  self: TailnetSelf | null;
  peers: TailnetPeer[];
}

/** This machine and its peers (the machine itself excluded), online first. */
export function tailnet(): Tailnet {
  if (!tailscaleBin()) return { state: { ok: false, reason: "not_installed", message: "Tailscale isn't installed on this machine." }, self: null, peers: [] };
  const st = rawStatus();
  const backend = str(st?.BackendState);
  if (!st || (backend && backend !== "Running")) {
    return { state: { ok: false, reason: "not_running", message: `Tailscale isn't running${backend ? ` (${clean(backend, 40)})` : ""}. Open Tailscale and log in.` }, self: null, peers: [] };
  }
  const users = (st.User && typeof st.User === "object" ? st.User : {}) as Record<string, Json>;
  const loginOf = (id: unknown): string | null => {
    const u = users[String(id)];
    return u && typeof u.LoginName === "string" ? u.LoginName : null;
  };
  const s = (st.Self ?? {}) as Json;
  const self: TailnetSelf = {
    nodeId: str(s.ID),
    name: clean(str(s.HostName) || dns(s.DNSName).split(".")[0] || "this machine", 64),
    dnsName: dns(s.DNSName),
    ips: ipsOf(s.TailscaleIPs),
    login: loginOf(s.UserID),
  };
  const peers: TailnetPeer[] = [];
  for (const p of Object.values((st.Peer ?? {}) as Record<string, Json>)) {
    if (!p || typeof p !== "object") continue;
    const dnsName = dns(p.DNSName);
    if (!dnsName || !SSH_HOST_RE.test(dnsName) || str(p.ID) === self.nodeId) continue;
    const online = p.Online === true;
    const seen = str(p.LastSeen);
    peers.push({
      nodeId: str(p.ID),
      name: clean(str(p.HostName) || dnsName.split(".")[0]!, 64),
      dnsName,
      os: clean(str(p.OS), 20),
      online,
      lastSeen: !online && seen && !seen.startsWith("0001-") && !Number.isNaN(Date.parse(seen)) ? new Date(seen).toISOString() : null,
      ips: ipsOf(p.TailscaleIPs),
      login: loginOf(p.UserID),
      tailscaleSsh: Array.isArray(p.SSH_HostKeys) && p.SSH_HostKeys.length > 0,
    });
  }
  peers.sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
  return { state: { ok: true }, self, peers };
}

export interface Whois {
  nodeId: string;
  login: string | null;
  name: string;
}

/**
 * Who is behind a tailnet IP. Tells apart "not a machine of this tailnet" (`unknown`) from
 * "couldn't ask right now" (`error`: tailscaled restarting, timeout, bad output), so callers
 * never treat a hiccup as an answer.
 */
export type WhoisResult = { ok: true; who: Whois } | { ok: false; reason: "unknown" | "error" };

export function whoisDetailed(ip: string): Promise<WhoisResult> {
  const bin = tailscaleBin();
  if (!bin) return Promise.resolve({ ok: false, reason: "error" });
  if (!/^[0-9a-fA-F.:]+$/.test(ip)) return Promise.resolve({ ok: false, reason: "unknown" });
  return new Promise((resolve) => {
    execFile(bin, ["whois", "--json", ip], { encoding: "utf8", timeout: 5000, maxBuffer: 2 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        // `tailscale whois` says "no match for IP" for addresses that aren't tailnet peers.
        return resolve({ ok: false, reason: /no match|not found|unknown peer/i.test(`${stderr}`) ? "unknown" : "error" });
      }
      try {
        const j = JSON.parse(stdout) as Json;
        const node = (j.Node ?? {}) as Json;
        const user = (j.UserProfile ?? {}) as Json;
        const nodeId = str(node.StableID);
        if (!nodeId) return resolve({ ok: false, reason: "error" });
        const host = (node.Hostinfo ?? {}) as Json;
        resolve({
          ok: true,
          who: {
            nodeId,
            login: typeof user.LoginName === "string" ? user.LoginName : null,
            name: clean(str(host.Hostname) || str(node.ComputedName) || dns(node.Name).split(".")[0] || nodeId, 64),
          },
        });
      } catch {
        resolve({ ok: false, reason: "error" });
      }
    });
  });
}

/** Who is behind a tailnet IP (null: unknown or couldn't ask). */
export async function whois(ip: string): Promise<Whois | null> {
  const r = await whoisDetailed(ip);
  return r.ok ? r.who : null;
}

/** "100.1.2.3" or "[fd7a::1]" for URLs and Host headers. */
export const urlHost = (ip: string): string => (ip.includes(":") ? `[${ip}]` : ip);

/** "::ffff:100.1.2.3" → "100.1.2.3". */
export const plainIp = (addr: string | undefined): string => (addr ?? "").replace(/^::ffff:/, "");
