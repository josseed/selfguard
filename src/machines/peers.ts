/** Tailnet peers: finding them, probing SSH and sharing, and explaining an SSH that is off. */
import { execFileSync } from "node:child_process";
import { connect } from "node:net";
import { DEFAULT_SHARE_PORT, loadConfig, type Machine } from "../config.ts";
import { probeShare } from "../share/client.ts";
import { tailnet, type TailnetPeer, type TailnetState } from "../tailnet.ts";
import { machineNameFor } from "./access.ts";
import { MachineError } from "./core.ts";

/** Find a tailnet peer by name, DNS name or address. */
export function findPeer(query: string): TailnetPeer | null {
  const q = query.trim().toLowerCase().replace(/\.$/, "");
  return tailnet().peers.find((p) =>
    p.dnsName.toLowerCase() === q || p.dnsName.toLowerCase().split(".")[0] === q || p.name.toLowerCase() === q || machineNameFor(p.name) === q || p.ips.includes(q),
  ) ?? null;
}

/** The address to reach a peer at (IPv4 first). */
export const peerAddress = (p: Pick<TailnetPeer, "ips">): string | null => p.ips.find((ip) => ip.includes(".")) ?? p.ips[0] ?? null;

export interface PeerInfo extends TailnetPeer {
  /** Name of the machine already added for it (null: not added). */
  added: string | null;
  /** selfguard sharing answers on it (version and whether it accepts pairing). */
  share: { version: string; name: string; pairing: boolean } | null;
  /** Its SSH port answers over the tailnet. */
  sshPort: boolean;
  /** What to offer: connect (pairing), turn on sharing there, SSH, or nothing (offline / added). */
  action: "added" | "offline" | "connect" | "enable-share" | "ssh";
}

export interface PeersResult {
  tailscale: TailnetState;
  self: { name: string; dnsName: string } | null;
  peers: PeerInfo[];
}

function tcpOpen(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host, port, timeout: timeoutMs });
    const done = (ok: boolean): void => {
      sock.destroy();
      resolve(ok);
    };
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

export type SshProbe = "open" | "refused" | "timeout" | "unknown";

/**
 * Whether the machine's SSH port takes connections, without logging in. Uses `ssh -G` to see
 * where the host really points (aliases, HostName, Port in ~/.ssh/config); hosts behind a
 * ProxyJump or ProxyCommand, or names that don't resolve, are "unknown" and never blocked.
 */
export async function probeSsh(host: string, port?: number, timeoutMs = 2500): Promise<SshProbe> {
  let target = host.replace(/^[^@]*@/, "");
  let p = port ?? 22;
  if (!process.env.SELFGUARD_SSH) {
    try {
      const args = ["-G", ...(port ? ["-p", String(port)] : []), "--", host];
      const cfg = execFileSync("ssh", args, { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] });
      const get = (k: string): string => cfg.match(new RegExp(`^${k} (.+)$`, "m"))?.[1]?.trim() ?? "";
      const via = [get("proxyjump"), get("proxycommand")].filter((v) => v && v !== "none");
      if (via.length) return "unknown";
      target = get("hostname") || target;
      const cp = Number(get("port"));
      if (Number.isInteger(cp) && cp > 0 && cp < 65536) p = cp;
    } catch {
      /* no ssh -G: use the host as typed */
    }
  }
  return new Promise((resolve) => {
    const sock = connect({ host: target, port: p });
    const timer = setTimeout(() => done("timeout"), timeoutMs);
    function done(r: SshProbe): void {
      clearTimeout(timer);
      sock.destroy();
      resolve(r);
    }
    sock.once("connect", () => done("open"));
    sock.once("error", (e: NodeJS.ErrnoException) => done(e.code === "ECONNREFUSED" ? "refused" : e.code === "ETIMEDOUT" || e.code === "EHOSTUNREACH" ? "timeout" : "unknown"));
  });
}

/**
 * What to tell someone whose machine refuses SSH: Remote Login is off there. For a tailnet
 * peer, suggests selfguard sharing (no SSH at all), or Connect if sharing already answers.
 */
export async function sshOffHint(host: string, port?: number, machine?: string): Promise<string> {
  const bare = host.replace(/^[^@]*@/, "");
  const peer = findPeer(bare);
  const label = peer?.name ?? bare;
  const ip = peer ? peerAddress(peer) : null;
  const share = ip ? await probeShare(ip, DEFAULT_SHARE_PORT, 1500) : null;
  const os = (peer?.os ?? "").toLowerCase();
  const turnOn =
    os === "macos"
      ? `turn on Remote Login there (System Settings → General → Sharing → Remote Login)`
      : os === "linux"
      ? `start sshd there (sudo systemctl enable --now ssh)`
      : `turn on SSH there (macOS: System Settings → General → Sharing → Remote Login; Linux: sudo systemctl enable --now ssh)`;
  const head = `${label} refuses SSH connections${port && port !== 22 ? ` on port ${port}` : ""}: Remote Login (SSH) is off there, so ${machine ? "selfguard can't read it over SSH" : "nothing was installed"}.`;
  const connect = machine ? `press Switch to sharing on its card (or selfguard machines migrate ${machine} --via share)` : `Machines → Connect, or selfguard machines add ${bare} --via share`;
  if (share) return `${head} selfguard sharing is on there: use it instead, no SSH needed (${connect}).`;
  if (peer) return `${head} If it runs selfguard, skip SSH: there, open Settings → Let my other machines see this one → Turn on, then ${machine ? "Switch to sharing" : "Connect"} from here. Or ${turnOn}.`;
  return `${head} To use SSH, ${turnOn}.`;
}

/** An SSH machine that can't be reached because its SSH port refuses: say Remote Login is off. */
export async function explainUnreachable(m: Machine, err: MachineError): Promise<MachineError> {
  if (m.transport !== "ssh" || err.code !== "unreachable") return err;
  if ((await probeSsh(m.host, m.port)) !== "refused") return err;
  return new MachineError("ssh_off", await sshOffHint(m.host, m.port, m.name));
}

/** Tailnet peers with what they can do, probed in parallel (about 1.5 s at most). */
export async function machinePeers(opts: { timeoutMs?: number; sharePort?: number } = {}): Promise<PeersResult> {
  const t = tailnet();
  const machines = loadConfig().machines;
  const timeout = opts.timeoutMs ?? 1500;
  const port = opts.sharePort ?? DEFAULT_SHARE_PORT;
  const peers = await Promise.all(
    t.peers.map(async (p): Promise<PeerInfo> => {
      const added =
        machines.find((m) => p.ips.includes(m.host) || m.host.toLowerCase() === p.dnsName.toLowerCase() || m.host.replace(/^[^@]*@/, "").toLowerCase() === p.dnsName.split(".")[0]!.toLowerCase())?.name ?? null;
      const ip = peerAddress(p);
      const [share, sshPort] = p.online && ip ? await Promise.all([probeShare(ip, port, timeout), tcpOpen(ip, 22, timeout)]) : [null, false];
      const action: PeerInfo["action"] = added ? "added" : !p.online ? "offline" : share ? "connect" : sshPort || p.tailscaleSsh ? "ssh" : "enable-share";
      return { ...p, added, share, sshPort, action };
    }),
  );
  return { tailscale: t.state, self: t.self ? { name: t.self.name, dnsName: t.self.dnsName } : null, peers };
}
