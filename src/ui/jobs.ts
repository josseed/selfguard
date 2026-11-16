/** Long-running dashboard jobs, polled by the page: pairing with a machine, "find my projects". */
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import * as api from "../api.ts";
import { updateRemoteAgent } from "../schedule.ts";

// Pairing with another machine: waits (up to 5 minutes) for the approval over there.
interface PairJob {
  id: string;
  code: string;
  peerName: string;
  expiresAt: string;
  status: "waiting" | "done" | "failed";
  machine: string | null;
  error: string | null;
  cancelled: boolean;
}
export const pairJobs = new Map<string, PairJob>();

export function startPairJob(start: api.PairingStart, opts: { replace?: string; name?: string }): Omit<PairJob, "cancelled"> {
  const job: PairJob = {
    id: randomBytes(9).toString("base64url"),
    code: start.session.code,
    peerName: start.peer.name,
    expiresAt: start.session.expiresAt,
    status: "waiting",
    machine: null,
    error: null,
    cancelled: false,
  };
  pairJobs.set(job.id, job);
  if (pairJobs.size > 20) pairJobs.delete(pairJobs.keys().next().value!);
  api
    .finishPairing(start, { replace: opts.replace, name: opts.name, isCancelled: () => job.cancelled })
    .then((m) => {
      job.status = "done";
      job.machine = m.name;
      try {
        updateRemoteAgent(api.hasMachines());
      } catch {
        /* best effort */
      }
    })
    .catch((e: unknown) => {
      job.status = "failed";
      job.error = job.cancelled ? "cancelled" : e instanceof Error ? e.message : String(e);
    });
  const { cancelled: _c, ...rest } = job;
  return rest;
}

export function pairStatus(id: string): Omit<PairJob, "cancelled"> {
  const job = pairJobs.get(id);
  if (!job) throw new api.ApiError("not_found", "no such pairing");
  const { cancelled: _c, ...rest } = job;
  return rest;
}

// "Find my projects" runs for a while: one job at a time, progress polled by the page.
export const everywhere: {
  running: boolean;
  cancelled: boolean;
  progress: { visited: number; found: number; current: string } | null;
  result: api.EverywhereScan | null;
  error: string | null;
  startedAt: string | null;
} = { running: false, cancelled: false, progress: null, result: null, error: null, startedAt: null };

export function everywhereStatus(): unknown {
  const { cancelled: _c, ...rest } = everywhere;
  return rest;
}

export function startEverywhere(): unknown {
  if (everywhere.running) return everywhereStatus();
  Object.assign(everywhere, { running: true, cancelled: false, progress: { visited: 0, found: 0, current: "" }, result: null, error: null, startedAt: new Date().toISOString() });
  api
    .findEverywhere({
      onProgress: (pr) => {
        everywhere.progress = { visited: pr.visited, found: pr.found, current: pr.current.replace(homedir(), "~") };
      },
      isCancelled: () => everywhere.cancelled,
    })
    .then((r) => {
      everywhere.result = r;
    })
    .catch((e: unknown) => {
      everywhere.error = e instanceof Error ? e.message : String(e);
    })
    .finally(() => {
      everywhere.running = false;
    });
  return everywhereStatus();
}
