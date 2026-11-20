/**
 * Plaintext credentials posture: tokens that infostealers and worms (Shai-Hulud, s1ngularity)
 * read straight from well-known files. Presence only: a warning says which kind of credential
 * sits where and the safer alternative, never the value, its length or a hash of it.
 */
import { join } from "node:path";
import type { ExtractResult, SourceExtractor, SourceTarget, SourceWarning } from "../types.ts";
import { home, NONE } from "./fs.ts";

interface CredentialFile {
  path: string;
  what: string;
  instead: string;
  /** 1-based line of the first credential, 0 for "somewhere in the file", null: none. */
  find: (text: string) => number | null;
}

/** First line matching `re` whose value isn't an environment reference (${NPM_TOKEN}). */
const lineMatching = (re: RegExp) => (text: string): number | null => {
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line.startsWith("#") || line.startsWith(";")) continue;
    const m = re.exec(line);
    if (m && !/^["']?\$\{?\w+\}?["']?$/.test((m[1] ?? "").trim())) return i + 1;
  }
  return null;
};

function json(text: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(text) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function dockerAuth(text: string): number | null {
  const cfg = json(text);
  if (!cfg || typeof cfg.credsStore === "string") return null;
  const auths = cfg.auths && typeof cfg.auths === "object" ? (cfg.auths as Record<string, unknown>) : {};
  const helpers = cfg.credHelpers && typeof cfg.credHelpers === "object" ? (cfg.credHelpers as Record<string, unknown>) : {};
  const stored = Object.entries(auths).some(
    ([host, v]) => !Object.hasOwn(helpers, host) && !!v && typeof v === "object" && typeof (v as Record<string, unknown>).auth === "string" && ((v as Record<string, unknown>).auth as string).length > 0,
  );
  return stored ? 0 : null;
}

function gcloudAdc(text: string): number | null {
  const cfg = json(text);
  return cfg && (typeof cfg.refresh_token === "string" || typeof cfg.private_key === "string") ? 0 : null;
}

export const CREDENTIAL_FILES: CredentialFile[] = [
  {
    path: ".npmrc",
    what: "an npm token",
    instead: "use a short-lived granular token from an environment variable (${NPM_TOKEN}) or `npm login` only when publishing",
    find: lineMatching(/(?:^|:)_(?:authToken|auth|password)\s*=\s*(.*)$/),
  },
  {
    path: ".aws/credentials",
    what: "an AWS secret access key",
    instead: "use `aws sso login` or a credential_process (aws-vault) so no long-lived key sits on disk",
    find: lineMatching(/^aws_secret_access_key\s*=\s*(\S.*)$/i),
  },
  {
    path: ".config/gh/hosts.yml",
    what: "a GitHub token",
    instead: "run `gh auth login` again and keep its default, which stores the token in the system keychain",
    find: lineMatching(/^oauth_token:\s*(\S.*)$/),
  },
  {
    path: ".docker/config.json",
    what: "a container registry password",
    instead: 'set "credsStore" (osxkeychain, desktop or secretservice) and log in again',
    find: dockerAuth,
  },
  {
    path: ".netrc",
    what: "a password",
    instead: "use your tools' credential helpers or the keychain instead of ~/.netrc",
    find: lineMatching(/\bpassword\s+(\S+)/),
  },
  {
    path: ".git-credentials",
    what: "git passwords or tokens",
    instead: "use a keychain credential helper (osxkeychain, manager or libsecret) and delete this file",
    find: lineMatching(/^\w[\w+.-]*:\/\/[^/\s]*:([^@\s]+)@/),
  },
  {
    path: ".pypirc",
    what: "a PyPI password or token",
    instead: "use keyring or trusted publishing from CI instead of a stored token",
    find: lineMatching(/^password\s*[=:]\s*(\S.*)$/i),
  },
  {
    path: ".kube/config",
    what: "a Kubernetes token or client key",
    instead: "use an exec credential plugin (aws, gcloud, kubelogin) that fetches short-lived tokens",
    find: lineMatching(/^-?\s*(?:token|client-key-data|password):\s*(\S.*)$/),
  },
  {
    path: ".config/gcloud/application_default_credentials.json",
    what: "a Google Cloud refresh token or service account key",
    instead: "revoke it with `gcloud auth application-default revoke` when you don't need it, and prefer impersonation over key files",
    find: gcloudAdc,
  },
];

const pathOf = (rel: string): string => join(home(), ...rel.split("/"));
const files = (target: SourceTarget): string[] => (target.scope === "machine" ? CREDENTIAL_FILES.map((c) => pathOf(c.path)) : []);

export function extractCredentials(file: string, text: string): ExtractResult {
  const entry = CREDENTIAL_FILES.find((c) => pathOf(c.path) === file);
  const line = entry ? entry.find(text) : null;
  if (!entry || line === null) return NONE;
  const warning: Omit<SourceWarning, "file"> = {
    rule: "plaintext-credential",
    severity: "moderate",
    key: entry.path,
    line,
    message: `~/${entry.path} holds ${entry.what} in plain text: any package install script or stealer can read it. Safer: ${entry.instead}.`,
  };
  return { refs: [], warnings: [warning], skipped: 0 };
}

export const PLAINTEXT_CREDENTIALS: SourceExtractor = {
  id: "host-credentials",
  kind: "host",
  files,
  markers: files,
  // Posture, not an event: sync re-reads them; no need to wake the watcher on every login.
  watch: () => [],
  extract: (file, text, target) => (target.scope === "machine" ? extractCredentials(file, text) : NONE),
};
