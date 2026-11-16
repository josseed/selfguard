// `selfguard machines`: other machines reached over SSH or selfguard sharing.
import { parseArgs } from "node:util";
import { maybeRemind } from "../announce.ts";
import * as api from "../api.ts";
import { DEFAULT_SHARE_PORT } from "../config.ts";
import { machineNameFor, peerAddress } from "../machines.ts";
import { paint, tildify } from "../report.ts";
import { clean } from "../sanitize.ts";
import { updateRemoteAgent } from "../schedule.ts";
import { probeShare } from "../share.ts";
import { withSpinner } from "../tui.ts";
import { emit, err, JSON_OPT, out, usage } from "./output.ts";

/** Show the code, wait for the approval on the other machine, then report. */
async function finishPairingCli(start: api.PairingStart, opts: { name?: string; replace?: string; json: boolean }): Promise<number> {
  const c = paint(out);
  const code = `${start.session.code.slice(0, 3)} ${start.session.code.slice(3)}`;
  if (opts.json) err.write(`pairing code ${code}: approve it on ${start.peer.name}\n`);
  else {
    out.write(`Asked ${c.bold(clean(start.peer.name))} to share its repos with this machine.\n`);
    out.write(`Check that it shows the same code:  ${c.bold(c.cyan(code))}\n`);
    out.write(c.dim(`Approve it there: dashboard → Machines, or selfguard share approve. Waiting up to 5 minutes…\n`));
  }
  const m = await withSpinner("Waiting for approval…", () => api.finishPairing(start, { name: opts.name, replace: opts.replace }));
  refreshRemoteAgent();
  if (opts.json) {
    emit(m);
    return 0;
  }
  out.write(`${c.green("✓")} ${opts.replace ? "Switched" : "Added"} ${c.bold(m.name)} through selfguard sharing (no SSH). It may read ${clean(m.scope)}.\n`);
  if (m.roots.length) out.write(`Folders: ${m.roots.map((r) => clean(r.path)).join(", ")}. Run ${c.bold(`selfguard machines sync ${m.name}`)} to scan it now.\n`);
  else out.write(`Now choose its folders: ${c.bold(`selfguard machines roots ${m.name} add ~/code`)}\n`);
  return 0;
}

function refreshRemoteAgent(): void {
  try {
    updateRemoteAgent(api.hasMachines());
  } catch (e) {
    err.write(`selfguard: could not update the background agent: ${clean((e as Error).message, 200)}\n`);
  }
}

function printMachines(list: api.MachineInfo[]): void {
  const c = paint(out);
  if (list.length === 0) {
    out.write(`No other machines yet. Add one with ${c.bold("selfguard machines add <host>")} (see ${c.bold("selfguard machines peers")}).\n`);
    return;
  }
  for (const m of list) {
    const st = m.status;
    const state = st.error ? c.yellow(`! ${clean(st.error, 120)}`) : st.lastSync ? c.green(`synced ${clean(st.lastSync.slice(0, 16).replace("T", " "))} UTC`) : c.dim("never synced");
    const how = m.mode === "restricted" ? `restricted to ${clean(m.scope)}` : "your SSH access";
    out.write(`${c.bold(m.name)} ${c.dim(`ssh ${m.host}${m.port ? `:${m.port}` : ""}${st.os ? ` · ${clean(st.os)}` : ""} · ${how}`)}  ${m.trackedProjects} project(s)  ${state}\n`);
    for (const r of m.roots) out.write(`  ${clean(r.path)} ${c.dim(`(depth ${r.depth})`)}\n`);
    if (m.roots.length === 0) out.write(c.dim(`  no folders yet: selfguard machines roots ${m.name} add ~/code\n`));
  }
}

export async function cmdMachines(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      ...JSON_OPT,
      name: { type: "string" },
      root: { type: "string", multiple: true },
      depth: { type: "string" },
      scope: { type: "string" },
      port: { type: "string" },
      mode: { type: "string" },
      manual: { type: "boolean" },
      "keep-remote": { type: "boolean" },
      background: { type: "boolean" },
      via: { type: "string" },
    },
  });
  const [action, a1, a2, a3] = positionals;
  const depth = values.depth === undefined ? undefined : Number(values.depth);
  if (depth !== undefined && !Number.isInteger(depth)) usage("--depth must be an integer");
  const c = paint(out);
  switch (action) {
    case undefined:
    case "list": {
      const list = api.listMachines();
      if (values.json) emit({ machines: list });
      else printMachines(list);
      return 0;
    }
    case "peers": {
      const r = await api.machinePeers();
      if (values.json) {
        emit(r);
        return 0;
      }
      if (!r.tailscale.ok) {
        out.write(`${c.yellow("!")} ${r.tailscale.message}\n`);
        return 2;
      }
      if (r.peers.length === 0) out.write("No other machines on your tailnet.\n");
      const what: Record<api.PeerInfo["action"], string> = {
        added: "added",
        offline: "offline",
        connect: "selfguard sharing on: selfguard machines add <name> (no SSH needed)",
        "enable-share": "turn on sharing there (Settings → Let my other machines see this one), or enable SSH",
        ssh: "SSH available: selfguard machines add <name> --via ssh",
      };
      for (const p of r.peers) {
        const dot = p.online ? c.green("●") : c.dim("○");
        const caps = [p.share ? `selfguard ${p.share.version} sharing` : null, p.sshPort ? "ssh :22" : null, p.tailscaleSsh ? "Tailscale SSH" : null].filter(Boolean).join(", ");
        const seen = !p.online && p.lastSeen ? ` · last seen ${p.lastSeen.slice(0, 10)}` : "";
        out.write(`${dot} ${c.bold(clean(p.name))} ${c.dim(`${p.dnsName} · ${p.os}${seen}`)}${p.added ? c.dim(` · added as ${p.added}`) : ""}\n`);
        if (p.online) out.write(c.dim(`    ${caps || "nothing answering"} → ${what[p.action].replace("<name>", machineNameFor(p.name))}\n`));
      }
      return 0;
    }
    case "migrate": {
      if (!a1 || (values.via !== "share" && values.via !== "ssh")) usage("usage: selfguard machines migrate <name> --via share|ssh");
      if (values.via === "ssh") {
        const m = api.listMachines().find((x) => x.name === a1);
        if (!m) usage(`unknown machine: ${a1}`);
        const peer = api.findPeer(m.host);
        const r = await api.addMachine(a1, peer?.dnsName ?? m.host, { mode: "restricted", scope: m.scope });
        if (values.json) emit(r);
        else out.write(r.installed ? `${c.green("✓")} ${a1} now uses a restricted SSH key.\n` : `${c.yellow("!")} Switched ${a1} to SSH, but the reader isn't installed: selfguard machines setup ${a1}\n`);
        return r.installed ? 0 : 2;
      }
      const start = await api.migrateToShare(a1);
      return finishPairingCli(start, { replace: a1, json: values.json ?? false });
    }
    case "test": {
      if (!a1) usage("usage: selfguard machines test <host>");
      const r = await api.testMachine(a1);
      if (values.json) emit(r);
      else out.write(`${c.green("✓")} ${clean(a1)} answers: ${clean(r.os)}, home ${clean(r.home)}\n`);
      return 0;
    }
    case "add": {
      if (!a1) usage("usage: selfguard machines add <peer|host> [--via share|ssh] [--name N] [--root DIR]... [--depth N] [--scope DIR] [--port N] [--manual] [--mode restricted|ssh]");
      if (values.via !== undefined && values.via !== "share" && values.via !== "ssh") usage("--via must be share or ssh");
      // SSH-only options mean SSH, as before 0.8. Otherwise, without --via: selfguard sharing
      // if that machine answers, else SSH.
      const sshFlags = ["mode", "root", "depth", "scope", "port", "manual"].filter((k) => values[k as keyof typeof values] !== undefined);
      if (values.via === "share" && sshFlags.length) usage(`--${sshFlags[0]} is for SSH machines; with --via share the other machine chooses its folders when it approves`);
      let via = values.via ?? (sshFlags.length ? "ssh" : undefined);
      if (!via) {
        const peer = api.findPeer(a1);
        const ip = peer ? peerAddress(peer) : null;
        via = ip && (await probeShare(ip, DEFAULT_SHARE_PORT, 1500)) ? "share" : "ssh";
        if (!values.json && via === "share") out.write(c.dim(`${clean(peer?.name ?? a1)} has selfguard sharing on: pairing without SSH.\n`));
      }
      if (via === "share") {
        const start = await api.startPairing(a1, { name: values.name });
        return finishPairingCli(start, { name: values.name, json: values.json ?? false });
      }
      const name = values.name ?? api.suggestName(a1);
      const port = values.port === undefined ? undefined : Number(values.port);
      if (port !== undefined && !Number.isInteger(port)) usage("--port must be an integer");
      if (values.mode !== undefined && values.mode !== "restricted" && values.mode !== "ssh") usage("--mode must be restricted or ssh");
      const r = await api.addMachine(name, a1, {
        mode: values.mode as "restricted" | "ssh" | undefined,
        port,
        scope: values.scope,
        roots: (values.root ?? []).map((path) => ({ path, depth })),
        install: !values.manual,
      });
      refreshRemoteAgent();
      if (values.json) {
        emit(r);
        return r.installed ? 0 : 2;
      }
      const m = r.machine;
      if (r.installed) {
        const how = m.mode === "restricted" ? `restricted key, reader limited to ${clean(m.scope)}` : "your SSH access";
        out.write(`${c.green("✓")} Added ${c.bold(m.name)} (${clean(m.status.os ?? "")}, ${how}).\n`);
        if (r.setup?.pinnedTo.length) out.write(c.dim(`  The key only works from this Mac's tailnet address (${r.setup.pinnedTo.join(", ")}).\n`));
        if (m.roots.length === 0) out.write(`Now choose its folders: ${c.bold(`selfguard machines roots ${m.name} add ~/code`)}\n`);
        else out.write(`Run ${c.bold(`selfguard machines sync ${m.name}`)} to scan it now.\n`);
        return 0;
      }
      out.write(`${c.yellow("!")} Saved ${c.bold(m.name)}, but the reader isn't installed yet.\n`);
      if (r.installError) out.write(c.dim(`  ${clean(r.installError, 300)}\n`));
      out.write(`Install it by hand: ${c.bold(`selfguard machines setup ${m.name}`)} shows what to paste on the machine; then ${c.bold(`selfguard machines verify ${m.name}`)}.\n`);
      return 2;
    }
    case "setup": {
      if (!a1) usage("usage: selfguard machines setup <name>");
      const st = api.machineSetup(a1);
      if (values.json) emit(st);
      else {
        out.write(`${c.bold(`# Install the selfguard reader on ${st.host}`)}\n`);
        out.write(c.dim(`# Paste this in a terminal on that machine (as the user selfguard connects as). It writes\n# ~/.selfguard-reader/reader.sh and adds one line to ~/.ssh/authorized_keys:\n#   ${st.authorizedKeysLine}\n# Then run: selfguard machines verify ${st.name}\n\n`));
        out.write(`sh -s <<'SELFGUARD_INSTALL'\n${st.installScript}SELFGUARD_INSTALL\n`);
      }
      return 0;
    }
    case "install":
    case "verify": {
      if (!a1) usage(`usage: selfguard machines ${action} <name>`);
      const m = action === "install" ? await api.installMachine(a1) : await api.verifyMachine(a1);
      if (values.json) emit(m);
      else out.write(`${c.green("✓")} ${c.bold(m.name)} answers${m.mode === "restricted" ? " through the restricted reader" : ""} (${clean(m.status.os ?? "")}).\n`);
      return 0;
    }
    case "remove": {
      if (!a1) usage("usage: selfguard machines remove <name> [--keep-remote]");
      const r = await api.removeMachine(a1, { revoke: !values["keep-remote"] });
      refreshRemoteAgent();
      if (values.json) emit(r);
      else if (!r.removed) out.write(`No machine named ${clean(a1)}.\n`);
      else {
        out.write(`Removed ${clean(a1)}, its results and its key.\n`);
        if (r.revoked) out.write(c.dim("  Key line and reader removed from the machine.\n"));
        else if (r.revoked === false) out.write(c.dim(`  Couldn't clean up the machine (${clean(r.revokeError ?? "", 200)}). The key line there is useless now; remove the "selfguard:" line from ~/.ssh/authorized_keys when you can.\n`));
      }
      return 0;
    }
    case "roots": {
      if (!a1 || (a2 !== "add" && a2 !== "remove") || !a3) usage("usage: selfguard machines roots <name> add <dir> [--depth N] | remove <dir>");
      const m = a2 === "add" ? api.addMachineRoot(a1, a3, depth) : api.removeMachineRoot(a1, a3);
      if (values.json) emit(m);
      else for (const r of m.roots) out.write(`${clean(r.path)} ${c.dim(`(depth ${r.depth})`)}\n`);
      return 0;
    }
    case "sync":
    case "check": {
      let r: api.MachinesCheckResult;
      try {
        r = await api.checkMachines({ notify: true, only: a1 ? [a1] : undefined });
      } catch (e) {
        if (values.background && e instanceof api.ApiError && e.code === "busy") return 0;
        throw e;
      }
      if (values.background) {
        const bad = r.machines.filter((m) => !m.ok);
        out.write(`${new Date().toISOString()} machines: ${r.machines.map((m) => `${m.name} ${m.ok ? `${m.rescanned} re-scanned` : "unreachable"}`).join(", ")}\n`);
        for (const m of bad) out.write(`  ${m.name}: ${clean(m.error ?? "")}\n`);
        await maybeRemind(api.getAttention);
      } else if (values.json) emit(r);
      else {
        for (const m of r.machines) {
          out.write(m.ok
            ? `${c.green("✓")} ${c.bold(m.name)}: ${m.projects} project(s), ${m.discovered} new, ${m.rescanned} re-scanned\n`
            : `${c.yellow("!")} ${c.bold(m.name)}: ${clean(m.error ?? "")}\n`);
        }
        for (const p of r.news) {
          const pkgs = p.packages.map((g) => `${clean(g.name)}@${clean(g.version)}`);
          out.write(`  ${c.bold(`${p.machine}:${tildify(p.path)}`)}: ${c.red(pkgs.join(", "))}\n`);
        }
        if (r.machines.length === 0) printMachines([]);
      }
      return r.machines.some((m) => !m.ok) && !values.background ? 2 : 0;
    }
    default:
      usage("usage: selfguard machines [list | peers | test <host> | add <host> | setup|install|verify <name> | roots <name> add|remove <dir> | sync [name] | remove <name>]");
  }
}
