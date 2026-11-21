/**
 * Pure parsers for listening TCP sockets: `lsof -F pcn` (macOS) and /proc/net/tcp{,6} (Linux).
 * Addresses are classified on the spot and dropped: only the class (loopback, wildcard, LAN,
 * tailnet), the port and the owning process are kept, never an address.
 */
import { basename } from "node:path";
import { clean } from "../../sanitize.ts";

/** wildcard: 0.0.0.0 or ::. lan: any other non-loopback address. tailnet: Tailscale's own range. */
export type Reach = "loopback" | "wildcard" | "lan" | "tailnet";

export interface Listener {
  port: number;
  reach: Reach;
  /** Sanitized basename of the process; absent when it can't be seen. */
  command?: string;
}

const MAX_LISTENERS = 2000;

function reach4(o: number[]): Reach {
  if (o[0] === 127) return "loopback";
  if (o.every((n) => n === 0)) return "wildcard";
  if (o[0] === 100 && o[1]! >= 64 && o[1]! <= 127) return "tailnet";
  return "lan";
}

function reach6(g: number[]): Reach {
  if (g.slice(0, 5).every((n) => n === 0) && g[5] === 0xffff) return reach4([g[6]! >> 8, g[6]! & 255, g[7]! >> 8, g[7]! & 255]);
  if (g.slice(0, 7).every((n) => n === 0)) return g[7] === 1 ? "loopback" : g[7] === 0 ? "wildcard" : "lan";
  if (g[0] === 0xfd7a && g[1] === 0x115c && g[2] === 0xa1e0) return "tailnet";
  return "lan";
}

/** Groups of an IPv6 text address (`::`, `fe80::1`, `::ffff:1.2.3.4`), or null. */
function groups6(text: string): number[] | null {
  let t = text.split("%")[0]!;
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(t);
  if (v4) {
    const o = v4.slice(1).map(Number);
    if (o.some((n) => n > 255)) return null;
    t = `${t.slice(0, v4.index)}${((o[0]! << 8) | o[1]!).toString(16)}:${((o[2]! << 8) | o[3]!).toString(16)}`;
  }
  const halves = t.split("::");
  if (halves.length > 2) return null;
  const parse = (s: string): number[] | null => {
    if (s === "") return [];
    const parts = s.split(":");
    return parts.every((p) => /^[0-9a-fA-F]{1,4}$/.test(p)) ? parts.map((p) => parseInt(p, 16)) : null;
  };
  const head = parse(halves[0]!);
  const tail = halves.length === 2 ? parse(halves[1]!) : [];
  if (!head || !tail) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - tail.length;
  return fill >= 1 ? [...head, ...Array<number>(fill).fill(0), ...tail] : null;
}

/** Reach of an address as lsof prints it: `*`, `1.2.3.4`, `[::1]`, `[fe80::1%en0]`. Null: unknown. */
export function reachOfText(host: string): Reach | null {
  if (host === "*") return "wildcard";
  const v4 = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(host);
  if (v4) {
    const o = v4.slice(1).map(Number);
    return o.some((n) => n > 255) ? null : reach4(o);
  }
  const m = /^\[(.+)\]$/.exec(host);
  const g = m ? groups6(m[1]!) : null;
  return g ? reach6(g) : null;
}

/** "name:port" of a lsof `n` field (`*:8080`, `[::1]:3000`); `->` connections never appear for LISTEN. */
export function parseLsofName(name: string): { port: number; reach: Reach } | null {
  const i = name.lastIndexOf(":");
  if (i < 1 || name.includes("->")) return null;
  const port = Number(name.slice(i + 1));
  const reach = reachOfText(name.slice(0, i));
  return Number.isInteger(port) && port > 0 && port < 65536 && reach ? { port, reach } : null;
}

/** Process name for messages: basename, no control characters, bounded. */
export function commandName(raw: string): string | undefined {
  const c = clean(basename(raw.replace(/\\x([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)))), 40);
  return c || undefined;
}

/**
 * `lsof -F pcn` output: `p<pid>` starts a process, `c<command>` names it, `f<fd>` starts a file,
 * `n<name>` is its socket. Anything that isn't understood is skipped.
 */
export function parseLsof(out: string): Listener[] {
  const list: Listener[] = [];
  let command: string | undefined;
  for (const line of out.split("\n")) {
    if (list.length >= MAX_LISTENERS) break;
    const tag = line[0];
    const value = line.slice(1);
    if (tag === "p") command = undefined;
    else if (tag === "c") command = commandName(value);
    else if (tag === "n") {
      const s = parseLsofName(value);
      if (s) list.push({ ...s, ...(command ? { command } : {}) });
    }
  }
  return list;
}

/** One /proc/net/tcp{,6} address: 8 hex digits (IPv4) or 32 (IPv6), each 32-bit word little-endian. */
function procReach(hex: string): Reach | null {
  if (!/^[0-9A-Fa-f]+$/.test(hex)) return null;
  const words = hex.match(/.{8}/g) ?? [];
  const bytes = words.flatMap((w) => (w.match(/../g) ?? []).reverse().map((b) => parseInt(b, 16)));
  if (hex.length === 8) return reach4(bytes);
  if (hex.length !== 32) return null;
  return reach6(Array.from({ length: 8 }, (_, i) => (bytes[2 * i]! << 8) | bytes[2 * i + 1]!));
}

/** Listening sockets of a /proc/net/tcp or tcp6 file (state 0A), with their socket inode. */
export function parseProcNet(text: string): Array<{ port: number; reach: Reach; inode: string }> {
  const out: Array<{ port: number; reach: Reach; inode: string }> = [];
  for (const line of text.split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10 || f[3] !== "0A") continue;
    const [addr, hexPort] = (f[1] ?? "").split(":");
    const port = parseInt(hexPort ?? "", 16);
    const reach = procReach(addr ?? "");
    if (reach && port > 0 && port < 65536 && out.length < MAX_LISTENERS) out.push({ port, reach, inode: f[9]! });
  }
  return out;
}
