/**
 * Other machines, over SSH (e.g. dev servers on your tailnet).
 *
 * Two modes, same read-only code:
 *
 * - restricted (default): a dedicated key that the machine accepts only for the selfguard
 *   reader, a fixed POSIX sh script installed at ~/.selfguard-reader/reader.sh and pinned in
 *   authorized_keys with `restrict,command="…"`. Requests travel on stdin as data
 *   ("SGREQ1 list" + folder lines); the reader refuses anything outside the folder it was
 *   installed for. Even if that key leaked, it could only list and read lockfiles there.
 * - ssh: your own SSH access (keys or Tailscale SSH); the same functions are piped into
 *   `/bin/sh -s` with values as single-quoted literals.
 *
 * Either way the remote side only uses find, stat, sed, sort, head, wc, cat and gzip. It
 * never writes (except when you install/revoke the reader), never runs git, a package
 * manager or anything from a project. What comes back is treated as untrusted.
 */
import type { Root } from "./config.ts";
import { isReader, MAX_FETCH_BYTES, MAX_LIST_BYTES, type Target } from "./remote/core.ts";
import { firstLine, parseBrowse, parseFetch, parseHeader, parseList, type BrowseResult, type Header, type ListResult } from "./remote/parse.ts";
import { browseRequest, fetchRequest, listRequest, openScript } from "./remote/script.ts";
import { runRemote } from "./remote/transport.ts";
import { tailnet, type TailnetPeer } from "./tailnet.ts";

export { FETCHABLE, isReader, MAX_FILE_BYTES, READER_PATH, READER_PROTOCOL, RemoteError, shq, SKIP, type Target } from "./remote/core.ts";
export { sshArgs, runRemote } from "./remote/transport.ts";
export { readerScript, listRequest, fetchRequest, browseRequest } from "./remote/script.ts";
export { authorizedLine, installScript, revokeScript, runInstall } from "./remote/install.ts";
export {
  parseHeader,
  parseList,
  parseFetch,
  parseBrowse,
  type RemoteProject,
  type Header,
  type ListResult,
  type BrowseResult,
} from "./remote/parse.ts";

// ---------- operations ----------

export async function listMachine(t: Target, roots: Root[]): Promise<ListResult> {
  return parseList(await runRemote(t, listRequest(t, roots), { maxBytes: MAX_LIST_BYTES, timeoutMs: 120_000 }), t);
}

export async function fetchFiles(t: Target, files: string[]): Promise<Map<string, Buffer | null>> {
  const out = new Map<string, Buffer | null>();
  // Several smaller batches keep each answer well under the cap.
  for (let i = 0; i < files.length; i += 200) {
    const batch = files.slice(i, i + 200);
    const got = parseFetch(await runRemote(t, fetchRequest(t, batch), { maxBytes: MAX_FETCH_BYTES, timeoutMs: 300_000 }), t);
    for (const f of batch) out.set(f, got.get(f) ?? null);
  }
  return out;
}

export async function browseMachine(t: Target, path: string): Promise<BrowseResult> {
  return parseBrowse(await runRemote(t, browseRequest(t, path), { maxBytes: 2 * 1024 * 1024, timeoutMs: 30_000 }), t);
}

/** Connection test: the remote home, OS and (restricted) allowed folder. */
export async function testHost(t: Target): Promise<Header> {
  const input = isReader(t) ? "SGREQ1 ping\n" : openScript({}, "");
  const [first] = firstLine(await runRemote(t, input, { maxBytes: 64 * 1024, timeoutMs: 20_000 }));
  return parseHeader(first, t);
}

// ---------- tailscale ----------

export type { TailnetPeer } from "./tailnet.ts";

/** Machines on your tailnet (if Tailscale is installed), to pick from when adding one. */
export function tailnetPeers(): TailnetPeer[] {
  return tailnet().peers;
}

/**
 * This Mac's tailnet addresses, when `host` is reached over the tailnet: the dedicated key is
 * then pinned to them (authorized_keys from="…"), so it is useless from anywhere else.
 */
export function tailnetSourceIps(host: string): string[] {
  const t = tailnet();
  if (!t.self) return [];
  const bare = host.replace(/^[^@]*@/, "").replace(/\.$/, "").toLowerCase();
  const viaTailnet =
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(bare) ||
    /^fd7a:115c:a1e0:/i.test(bare) ||
    t.peers.some((p) => {
      const d = p.dnsName.toLowerCase();
      return bare === d || bare === d.split(".")[0] || bare === p.name.toLowerCase() || p.ips.includes(bare);
    });
  return viaTailnet ? t.self.ips : [];
}
