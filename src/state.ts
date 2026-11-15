/** Small runtime state that isn't configuration (e.g. when the last reminder was sent). */
import { atomicWrite, isObject, readJsonFile } from "./fsutil.ts";
import { stateFile } from "./paths.ts";

export interface RuntimeState {
  lastReminder?: string;
  lastSync?: string;
  lastCheck?: string;
  /** Last "find my projects" over the whole home folder. */
  lastEverywhere?: string;
  /** Watched folders the user removed: automatic discovery never adds them back. */
  dismissedPlaces?: string[];
  /** Update check (see update.ts). */
  lastUpdateCheck?: string;
  latestVersion?: string;
  latestProvenance?: boolean;
  /** Last version we sent an "update available" notification for. */
  notifiedVersion?: string;
}

export function loadState(): RuntimeState {
  const raw = readJsonFile<RuntimeState>(stateFile());
  if (!raw || !isObject(raw)) return {};
  const out: RuntimeState = {};
  for (const k of ["lastReminder", "lastSync", "lastCheck", "lastEverywhere", "lastUpdateCheck", "latestVersion", "notifiedVersion"] as const) {
    if (typeof raw[k] === "string") out[k] = raw[k];
  }
  if (typeof raw.latestProvenance === "boolean") out.latestProvenance = raw.latestProvenance;
  if (Array.isArray(raw.dismissedPlaces)) out.dismissedPlaces = raw.dismissedPlaces.filter((x): x is string => typeof x === "string").slice(-500);
  return out;
}

export function updateState(patch: Partial<RuntimeState>): RuntimeState {
  const next = { ...loadState(), ...patch };
  atomicWrite(stateFile(), JSON.stringify(next));
  return next;
}
