/**
 * The four browser extension rules, over an already parsed extension (no file access here).
 * Every string is hostile: names are cleaned and truncated, ids validated by the parsers.
 */
import { clean } from "../../sanitize.ts";
import type { SourceWarning } from "../types.ts";
import { DENYLIST } from "./extensions-browser-data.ts";

export interface BrowserExtension {
  id: string;
  name: string;
  version: string | null;
  /** Why it isn't a normal store install ("loaded unpacked"…), or null. */
  unpacked: string | null;
  /** Turned off: still installed, but its permissions aren't in use. */
  disabled: boolean;
  /** API permissions granted ("debugger", "cookies"…) and host patterns ("<all_urls>"). */
  apis: string[];
  hosts: string[];
}

export type Warning = Omit<SourceWarning, "file">;

/** Host patterns that match every site. */
const BROAD = new Set(["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/", "*://*.*/*"]);
export const isBroadHost = (h: string): boolean => BROAD.has(h.trim());

/**
 * Permissions that give full control of the browser or the machine:
 * - debugger: the DevTools protocol on any tab (read pages, cookies, inject, click);
 * - nativeMessaging: talks to a program outside the browser sandbox;
 * - proxy: reroutes all traffic;
 * - webRequestBlocking with a broad host: sees and rewrites every request;
 * - cookies with a broad host: reads and writes every site's cookies, sessions included.
 * Password managers (Bitwarden, 1Password: nativeMessaging for the desktop app, cookies) hit
 * these by design: moderate and never "notify", so they are reviewed once, not announced.
 * Not counted: `tabs`, `history`, `storage`, `webRequest` alone, plain content-script hosts.
 */
export function powers(ext: BrowserExtension): string[] {
  const has = (p: string) => ext.apis.includes(p);
  const broad = ext.hosts.some(isBroadHost);
  const out: string[] = [];
  if (has("debugger")) out.push("debugger (controls any tab)");
  if (has("nativeMessaging")) out.push("nativeMessaging (talks to a program on this machine)");
  if (has("proxy")) out.push("proxy (reroutes your traffic)");
  if (has("webRequestBlocking") && broad) out.push("webRequestBlocking on all sites (rewrites every request)");
  if (has("cookies") && broad) out.push("cookies on all sites (reads every session)");
  return out;
}

export function extensionWarnings(browser: string, profile: string, ext: BrowserExtension): Warning[] {
  const key = `${browser}|${profile}|${ext.id}`;
  const name = clean(ext.name, 60) || ext.id;
  const where = `${browser} profile "${clean(profile, 40)}"`;
  const label = `"${name}" (${ext.id})`;
  const out: Warning[] = [];
  const denied = Object.hasOwn(DENYLIST, ext.id) ? DENYLIST[ext.id]! : null;
  const listed = denied && (!denied.versions || (ext.version !== null && denied.versions.includes(ext.version)));
  if (denied && listed) {
    const what = denied.versions ? `version ${clean(ext.version, 30)} was published by attackers (a hijacked extension)` : "was publicly reported as malicious";
    out.push({
      rule: "malicious-browser-extension",
      severity: "high",
      key,
      line: 0,
      notify: true,
      urgent: true,
      message: `Malicious browser extension ${label} in ${where}: it ${what}. Remove it, and change passwords and tokens used in this browser.`,
    });
  }
  if (ext.unpacked) {
    out.push({
      rule: "unpacked-browser-extension",
      severity: "moderate",
      key,
      line: 0,
      notify: true,
      message: `Browser extension ${label} in ${where} ${ext.unpacked}: nothing reviewed it, and it can change without notice.`,
    });
  }
  const power = ext.disabled ? [] : powers(ext);
  if (power.length) {
    out.push({
      rule: "powerful-browser-extension",
      severity: "moderate",
      key,
      line: 0,
      message: `Browser extension ${label} in ${where} has full-control permissions: ${power.join("; ")}. Keep only extensions you trust with this.`,
    });
  }
  out.push({
    rule: "browser-extension",
    severity: "low",
    key,
    line: 0,
    notify: true,
    message: `Browser extension ${label}${ext.version ? ` ${clean(ext.version, 30)}` : ""} installed in ${where}${ext.disabled ? " (disabled)" : ""}`,
  });
  return out;
}
