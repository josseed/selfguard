/**
 * "Let my other machines see this one": selfguard ↔ selfguard over the tailnet, no SSH.
 *
 * Machine B (the one being looked at) runs `selfguard share serve` (a launchd / systemd user
 * agent). It listens only on B's own Tailscale addresses, never on 0.0.0.0 or the LAN, and
 * answers the same read-only reader requests as the SSH reader (see reader.ts) to machines it
 * paired with.
 *
 * Pairing, from machine A (the one looking):
 *  1. A sends POST /pair/request with its name and an ephemeral X25519 public key.
 *  2. B checks who is calling with `tailscale whois` (same tailnet, and by default the same
 *     Tailscale user), keeps the request pending for 5 minutes and notifies.
 *  3. Both sides show the same 6-digit code, derived from both public keys. The user checks
 *     they match and approves on B, choosing the folder A may read.
 *  4. B creates a random credential, stores only its hash, bound to A's Tailscale node ID, and
 *     seals it for A with the X25519 shared secret (AES-256-GCM). Only A can open it.
 *  5. A polls /pair/status, opens the credential and stores it in ~/.selfguard (0600).
 * Every later request needs the credential AND must come from that node ID (checked with
 * whois). A mismatch revokes the grant. `share off` stops answering at once.
 */
export { PAIR_TTL_MS, ShareError, accessLogFile, loadGrants, type Grant, type PendingRequest } from "./share/store.ts";
export { findGrant, newEphemeralKey, pairingCode, seal, unseal, validPublicKey, type EphemeralKey } from "./share/crypto.ts";
export {
  approveShareRequest,
  listGrants,
  listShareRequests,
  rejectShareRequest,
  revokeGrant,
  type GrantInfo,
  type PairPayload,
  type ShareRequestInfo,
} from "./share/grants.ts";
export { startShareServer, type RunningShare, type ShareServerOptions } from "./share/server.ts";
export { pollPairing, probeShare, requestPairing, unpair, waitForPairing, type Hello, type PairPoll, type PairSession } from "./share/client.ts";
