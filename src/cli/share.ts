// `selfguard share`: let other machines see this one over Tailscale.
import { parseArgs } from "node:util";
import * as api from "../api.ts";
import { loadConfig } from "../config.ts";
import { paint } from "../report.ts";
import { clean } from "../sanitize.ts";
import { startShareServer } from "../share.ts";
import { tailnet } from "../tailnet.ts";
import { emit, JSON_OPT, out, usage } from "./output.ts";

function printShare(st: api.ShareStatus): void {
  const c = paint(out);
  if (!st.tailscale.ok) out.write(`${c.yellow("!")} ${st.tailscale.message}\n`);
  if (!st.enabled) out.write(`Sharing is ${c.bold("off")}: other machines can't see this one. Turn it on with ${c.bold("selfguard share on")}.\n`);
  else {
    const where = st.addresses.map((a) => `${a}:${st.port}`).join(", ") || "no tailnet address";
    out.write(`Sharing is ${c.green("on")}${st.answering ? "" : c.yellow(" (not answering yet)")}: ${c.dim(where)}\n`);
    if (st.allowOtherUsers) out.write(c.yellow("  Machines of other Tailscale users of the tailnet may ask to pair.\n"));
  }
  for (const r of st.requests) {
    out.write(`${c.yellow("?")} ${c.bold(clean(r.name))} ${c.dim(`(${clean(r.hostName)}${r.login ? `, ${clean(r.login)}` : ""})`)} wants to see your repos. Code ${c.bold(`${r.code.slice(0, 3)} ${r.code.slice(3)}`)}\n`);
    out.write(c.dim(`    selfguard share approve ${r.id} [--scope ~/code]   ·   selfguard share reject ${r.id}\n`));
  }
  if (st.grants.length) out.write("Machines that can see this one:\n");
  for (const g of st.grants) {
    out.write(`  ${c.bold(clean(g.name))} ${c.dim(`${clean(g.hostName)} · reads ${clean(g.scope)} · ${g.lastSeen ? `last seen ${g.lastSeen.slice(0, 16).replace("T", " ")} UTC` : "never connected"}`)}\n`);
  }
}

/** `selfguard share serve`: the service. Waits for a tailnet address and follows IP changes. */
async function serveShare(): Promise<number> {
  const log = (m: string): void => void out.write(`${new Date().toISOString()} share: ${m}\n`);
  let running: Awaited<ReturnType<typeof startShareServer>> | null = null;
  let current = "";
  let stopping = false;
  const stop = async (): Promise<void> => {
    stopping = true;
    await running?.close();
    process.exit(0);
  };
  process.once("SIGTERM", () => void stop());
  process.once("SIGINT", () => void stop());
  for (;;) {
    if (stopping) return 0;
    const cfg = loadConfig();
    if (!cfg.share.enabled) {
      log("sharing is off; exiting");
      await running?.close();
      return 0;
    }
    const ips = tailnet().self?.ips ?? [];
    const key = `${ips.join(",")}:${cfg.share.port}`;
    if (key !== current) {
      await running?.close();
      running = null;
      current = key;
      if (ips.length) {
        try {
          running = await startShareServer({ hosts: ips, port: cfg.share.port });
          log(`listening on ${running.addresses.map((a) => `${a.host}:${a.port}`).join(", ")}`);
          for (const f of running.failed) log(`skipped ${f.host}: ${f.error}`);
        } catch (e) {
          log(`can't listen: ${clean((e as Error).message, 200)}`);
          current = "";
        }
      } else log("no Tailscale address yet (is Tailscale running and logged in?); retrying");
    }
    await new Promise((r) => setTimeout(r, 30_000));
  }
}

export async function cmdShare(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { ...JSON_OPT, scope: { type: "string" }, root: { type: "string", multiple: true }, depth: { type: "string" }, port: { type: "string" }, "allow-other-users": { type: "boolean" } },
  });
  const [action, a1] = positionals;
  const c = paint(out);
  switch (action) {
    case "serve":
      return serveShare();
    case "on":
    case "off": {
      const port = values.port === undefined ? undefined : Number(values.port);
      const st = await api.setShare({ enabled: action === "on", port, ...(values["allow-other-users"] !== undefined ? { allowOtherUsers: values["allow-other-users"] } : {}) });
      if (values.json) emit(st);
      else if (action === "off") out.write("Sharing is off. Machines paired with this one can't read anything until you turn it on again.\n");
      else {
        if (!st.tailscale.ok) out.write(`${c.yellow("!")} ${st.tailscale.message} Sharing starts as soon as Tailscale is up.\n`);
        else out.write(`${c.green("✓")} Your other machines can now ask to see this one (${st.addresses.join(", ")}, port ${st.port}). Only your Tailscale user's machines, and only after you approve.\n`);
      }
      return 0;
    }
    case undefined:
    case "status": {
      const st = await api.shareStatus();
      if (values.json) emit(st);
      else printShare(st);
      return 0;
    }
    case "requests": {
      const list = api.listShareRequests();
      if (values.json) emit({ requests: list });
      else if (list.length === 0) out.write("No pairing requests waiting.\n");
      else printShare({ ...(await api.shareStatus()), grants: [] });
      return 0;
    }
    case "approve": {
      if (!a1) usage("usage: selfguard share approve <id> [--scope DIR] [--root DIR]... [--depth N]");
      const depth = values.depth === undefined ? 5 : Number(values.depth);
      const roots = values.root?.length ? values.root.map((path) => ({ path, depth })) : api.shareSuggestions();
      const g = await api.approveShareRequest(a1, { scope: values.scope ?? "~", roots });
      if (values.json) emit(g);
      else out.write(`${c.green("✓")} ${c.bold(clean(g.name))} can now read lockfiles under ${clean(g.scope)}. Revoke with ${c.bold(`selfguard share revoke ${g.name}`)}.\n`);
      return 0;
    }
    case "reject": {
      if (!a1) usage("usage: selfguard share reject <id>");
      const r = await api.rejectShareRequest(a1);
      if (values.json) emit(r);
      else out.write(r.rejected ? "Rejected.\n" : "No such pending request.\n");
      return 0;
    }
    case "list": {
      const grants = api.listGrants();
      if (values.json) emit({ grants });
      else if (grants.length === 0) out.write("No machine can see this one.\n");
      else printShare({ ...(await api.shareStatus()), requests: [] });
      return 0;
    }
    case "revoke": {
      if (!a1) usage("usage: selfguard share revoke <name>");
      const r = await api.revokeShareGrant(a1);
      if (values.json) emit(r);
      else out.write(r.revoked ? `${clean(a1)} can no longer see this machine.\n` : `No machine called ${clean(a1)} can see this one.\n`);
      return 0;
    }
    default:
      usage("usage: selfguard share [on | off | status | requests | approve <id> | reject <id> | list | revoke <name>]");
  }
}
