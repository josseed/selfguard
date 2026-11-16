import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const FAKE_TAILSCALE = fileURLToPath(new URL("./bin/fake-tailscale", import.meta.url));

export interface FakeNode {
  id: string;
  name: string;
  ips: string[];
  login?: string;
  online?: boolean;
  os?: string;
  tailscaleSsh?: boolean;
}

/** A fake tailnet for test/bin/fake-tailscale: this machine, its peers and whois answers. */
export function fakeTailnet(self: FakeNode, peers: FakeNode[] = [], dir = mkdtempSync(join(tmpdir(), "sg-tailnet-"))): {
  dir: string;
  /** node: who is there; null: not a tailnet address; "error": whois fails (tailscaled hiccup). */
  whois(ip: string, node: FakeNode | null | "error"): void;
  write(): void;
} {
  mkdirSync(dir, { recursive: true });
  const logins = [...new Set([self, ...peers].map((n) => n.login ?? "me@example.com"))];
  const uid = (n: FakeNode): number => 100 + logins.indexOf(n.login ?? "me@example.com");
  const node = (n: FakeNode) => ({
    ID: n.id,
    HostName: n.name,
    DNSName: `${n.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.tail1234.ts.net.`,
    OS: n.os ?? "macOS",
    UserID: uid(n),
    TailscaleIPs: n.ips,
    Online: n.online ?? true,
    LastSeen: n.online === false ? "2026-11-01T10:00:00Z" : "0001-01-01T00:00:00Z",
    ...(n.tailscaleSsh ? { SSH_HostKeys: ["ssh-ed25519 AAAA"] } : {}),
  });
  const write = (): void => {
    writeFileSync(join(dir, "status.json"), JSON.stringify({
      BackendState: "Running",
      Self: node(self),
      Peer: Object.fromEntries(peers.map((p) => [`key-${p.id}`, node(p)])),
      User: Object.fromEntries(logins.map((l, i) => [String(100 + i), { LoginName: l, DisplayName: l }])),
    }));
  };
  write();
  return {
    dir,
    write,
    whois(ip, n) {
      const file = join(dir, `whois-${ip}.json`);
      if (n === null) {
        rmSync(file, { force: true });
        return;
      }
      if (n === "error") {
        writeFileSync(file, "ERROR\n");
        return;
      }
      writeFileSync(file, JSON.stringify({ Node: { StableID: n.id, Name: `${n.name}.tail1234.ts.net.`, Hostinfo: { Hostname: n.name } }, UserProfile: { LoginName: n.login ?? "me@example.com" } }));
    },
  };
}
