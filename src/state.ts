/** Small runtime state that isn't configuration (e.g. when the last reminder was sent). */
import { atomicWrite, isObject, readJsonFile } from "./fsutil.ts";
import { stateFile } from "./paths.ts";

export interface RuntimeState {
  lastReminder?: string;
  lastSync?: string;
  lastCheck?: string;
}

export function loadState(): RuntimeState {
  const raw = readJsonFile<RuntimeState>(stateFile());
  if (!raw || !isObject(raw)) return {};
  const out: RuntimeState = {};
  for (const k of ["lastReminder", "lastSync", "lastCheck"] as const) {
    if (typeof raw[k] === "string") out[k] = raw[k];
  }
  return out;
}

export function updateState(patch: Partial<RuntimeState>): RuntimeState {
  const next = { ...loadState(), ...patch };
  atomicWrite(stateFile(), JSON.stringify(next));
  return next;
}
