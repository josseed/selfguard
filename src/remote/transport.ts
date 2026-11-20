import { spawn } from "node:child_process";
import { DEFAULT_SHARE_PORT, SSH_HOST_RE } from "../config.ts";
import { program } from "../paths.ts";
import { clean } from "../sanitize.ts";
import { urlHost } from "../tailnet.ts";
import { notReader, RemoteError, type Target } from "./core.ts";

// ---------- transport ----------

/**
 * ssh options: never prompt, no agent/X11/port forwarding, bounded waits; host key checks
 * stay as you configured them. Restricted mode offers only the dedicated key.
 */
export function sshArgs(t: Target): string[] {
  if (!SSH_HOST_RE.test(t.host)) throw new RemoteError("protocol", `invalid host: ${t.host}`);
  const args = [
    "-T", "-a", "-x",
    "-o", "BatchMode=yes",
    "-o", "ClearAllForwardings=yes",
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=2",
    "-o", "LogLevel=ERROR",
  ];
  if (t.port !== undefined) {
    if (!Number.isInteger(t.port) || t.port < 1 || t.port > 65535) throw new RemoteError("protocol", "invalid port");
    args.push("-p", String(t.port));
  }
  if (t.key) {
    args.push("-i", t.key, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no");
  }
  // In restricted mode the machine ignores the command and runs the reader (forced command).
  args.push("--", t.host, t.key ? "selfguard-reader" : "/bin/sh -s");
  return args;
}

const sshBin = (): string => program("SELFGUARD_SSH", "ssh", "/usr/bin/ssh");

/** Send `input` on stdin (a script, or a reader request); resolves with stdout (capped). */
export function runRemote(t: Target, input: string, opts: { maxBytes: number; timeoutMs: number }): Promise<Buffer> {
  if (t.transport === "share") return shareRead(t, input, opts);
  return new Promise((resolve, reject) => {
    const child = spawn(sshBin(), sshArgs(t), { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, LC_ALL: "C" } });
    const chunks: Buffer[] = [];
    let size = 0;
    let stderr = "";
    let failure: RemoteError | null = null;
    const timer = setTimeout(() => {
      failure = new RemoteError("unreachable", `timed out after ${Math.round(opts.timeoutMs / 1000)}s`);
      child.kill("SIGKILL");
    }, opts.timeoutMs);
    child.stdout.on("data", (c: Buffer) => {
      size += c.length;
      if (size > opts.maxBytes) {
        failure ??= new RemoteError("too_large", `answer larger than ${Math.round(opts.maxBytes / 1048576)} MB`);
        child.kill("SIGKILL");
        return;
      }
      chunks.push(c);
    });
    child.stderr.on("data", (c: Buffer) => {
      if (stderr.length < 4096) stderr += c.toString("utf8");
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(new RemoteError("unreachable", `could not run ssh: ${clean(e.message, 200)}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (failure) return reject(failure);
      const msg = clean(stderr.trim().split("\n").slice(-2).join(" "), 300);
      if (code === 255) {
        const auth = /permission denied|authentication|host key verification|tailscale ssh/i.test(stderr);
        return reject(new RemoteError(auth ? "auth" : "unreachable", msg || "ssh connection failed"));
      }
      if (code !== 0) {
        if (t.key && /selfguard-reader|not found/i.test(stderr)) return reject(notReader());
        return reject(new RemoteError("failed", msg || `remote side exited with ${code}`));
      }
      resolve(Buffer.concat(chunks));
    });
    child.stdin.on("error", () => {
      /* ssh exited early; reported on close */
    });
    child.stdin.end(input);
  });
}

/** The same request, sent to another selfguard over the tailnet (POST /read with the credential). */
async function shareRead(t: Target, input: string, opts: { maxBytes: number; timeoutMs: number }): Promise<Buffer> {
  if (!t.credential) throw new RemoteError("not_installed", "not paired with this machine yet");
  if (!/^[0-9a-fA-F.:]+$/.test(t.host)) throw new RemoteError("protocol", "invalid tailnet address");
  let res: Response;
  try {
    res = await fetch(`http://${urlHost(t.host)}:${t.port ?? DEFAULT_SHARE_PORT}/read`, {
      method: "POST",
      headers: { authorization: `Bearer ${t.credential}`, "content-type": "text/plain; charset=utf-8" },
      body: input,
      redirect: "error",
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
  } catch (e) {
    const timeout = (e as Error).name === "TimeoutError";
    throw new RemoteError("unreachable", timeout ? `timed out after ${Math.round(opts.timeoutMs / 1000)}s` : "the machine didn't answer (offline, or sharing turned off there)");
  }
  if (res.status === 401 || res.status === 403) throw new RemoteError("auth", "the machine no longer accepts this one (access revoked): pair again");
  if (res.status === 503) {
    const code = await res.json().then((j) => (j as { error?: { code?: unknown } } | null)?.error?.code, () => null);
    throw new RemoteError(
      "unreachable",
      code === "off" ? "sharing is turned off on that machine" : "that machine couldn't check this one with Tailscale right now; it will be retried",
    );
  }
  if (res.status !== 200) throw new RemoteError("failed", `the machine answered ${res.status}`);
  const chunks: Buffer[] = [];
  let size = 0;
  if (res.body) {
    for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
      size += chunk.length;
      if (size > opts.maxBytes) throw new RemoteError("too_large", `answer larger than ${Math.round(opts.maxBytes / 1048576)} MB`);
      chunks.push(Buffer.from(chunk));
    }
  }
  return Buffer.concat(chunks);
}
