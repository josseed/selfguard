# Security policy

selfguard is a security tool, so vulnerabilities in it matter twice.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub private vulnerability reporting](https://github.com/josseed/selfguard/security/advisories/new).

Include what you found, how to reproduce it, and the impact you expect. You'll get an answer
within a few days, and credit in the advisory if you want it.

## Scope

In scope, for example:
- Code execution when entering, scanning or discovering a hostile project (selfguard must never
  execute project code).
- Terminal escape or notification injection through package names or advisory text.
- Leaking anything beyond package names and versions to the network.
- Prompt-injection paths through the MCP server that lead to actions the user didn't ask for.
- Supply-chain issues in how selfguard is built or published.

## Supported versions

Only the latest release gets fixes.

## Audits

- [November 2026, internal review of 0.18.2](docs/security-audit-2026-11.md): no critical or
  high findings; 6 medium and 15 low, all fixed.

## Verifying releases

Every npm version and Mac app DMG carries a signed provenance attestation. See
[Verify your download](docs/verify.md).
