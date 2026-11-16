import { randomBytes } from "node:crypto";
import { posix } from "node:path";
import { isReader, READER_COMMAND, READER_PATH, RemoteError, shq, type Target } from "./core.ts";
import { runRemote } from "./transport.ts";

// ---------- install / revoke (run once with your own SSH access) ----------

/** The authorized_keys line for the dedicated key. */
export function authorizedLine(publicKey: string, marker: string, from: string[] = []): string {
  const key = publicKey.trim().split(/\s+/);
  if (key.length < 2 || key[0] !== "ssh-ed25519" || !/^[A-Za-z0-9+/]+=*$/.test(key[1]!)) throw new RemoteError("protocol", "unexpected public key");
  if (!/^selfguard:[a-z0-9-]+@[a-z0-9-]+$/.test(marker)) throw new RemoteError("protocol", "bad key marker");
  for (const ip of from) if (!/^[0-9a-fA-F.:]+$/.test(ip)) throw new RemoteError("protocol", "bad address");
  const opts = [`restrict`, `command="${READER_COMMAND}"`, ...(from.length ? [`from="${from.join(",")}"`] : [])];
  return `${opts.join(",")} ssh-ed25519 ${key[1]} ${marker}`;
}

/**
 * Installs the reader and the key line. Idempotent: replaces the reader and any previous
 * line with the same marker; leaves the rest of authorized_keys untouched (rewritten in
 * place, so permissions and SELinux labels stay).
 */
export function installScript(reader: string, line: string, marker: string): string {
  const eof = `SG_READER_EOF_${randomBytes(8).toString("hex")}`;
  if (reader.includes(eof)) throw new RemoteError("protocol", "bad reader");
  return `set -eu
umask 077
d="$HOME/${posix.dirname(READER_PATH)}"
mkdir -p "$d"
cat > "$d/reader.sh.new" <<'${eof}'
${reader}
${eof}
chmod 500 "$d/reader.sh.new"
mv -f "$d/reader.sh.new" "$d/reader.sh"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
ak="$HOME/.ssh/authorized_keys"
[ -f "$ak" ] || : > "$ak"
grep -v -F -- ${shq(` ${marker}`)} "$ak" > "$d/ak.tmp" || true
cat "$d/ak.tmp" > "$ak"
rm -f "$d/ak.tmp"
printf '%s\\n' ${shq(line)} >> "$ak"
chmod 600 "$ak"
printf 'SGOK\\n'
`;
}

/** Removes the key line; removes the reader when no selfguard key is left. */
export function revokeScript(marker: string): string {
  return `set -eu
ak="$HOME/.ssh/authorized_keys"
d="$HOME/${posix.dirname(READER_PATH)}"
if [ -f "$ak" ]; then
  grep -v -F -- ${shq(` ${marker}`)} "$ak" > "$ak.sgtmp" || true
  cat "$ak.sgtmp" > "$ak"
  rm -f "$ak.sgtmp"
fi
if ! grep -q -F ' selfguard:' "$ak" 2>/dev/null; then rm -rf "$d"; fi
printf 'SGOK\\n'
`;
}

export async function runInstall(t: Target, script: string): Promise<void> {
  if (isReader(t)) throw new RemoteError("protocol", "install needs your own SSH access");
  const out = (await runRemote(t, script, { maxBytes: 64 * 1024, timeoutMs: 30_000 })).toString("utf8");
  if (!out.includes("SGOK")) throw new RemoteError("failed", "the install script did not finish");
}
