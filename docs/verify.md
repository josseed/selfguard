# Verify your download

You don't have to take selfguard's word for how it is built. Every release can be checked
independently, with public tools, against public transparency logs. This page shows how.

## The npm package (CLI)

Each version is built and published by this repository's GitHub Actions with npm Trusted
Publishing and carries an npm [provenance](https://docs.npmjs.com/generating-provenance-statements)
attestation, signed with Sigstore and recorded in the public Rekor transparency log.

```sh
# After installing: checks the registry signatures and provenance of everything installed
npm audit signatures

# Before installing: shows the attestations of a version
npm view selfguard@<version> dist.attestations
```

On [npmjs.com/package/selfguard](https://www.npmjs.com/package/selfguard#provenance) the
"Provenance" section links the version to the exact commit and workflow run that built it.

## The Mac app (DMG)

Each DMG attached to a [release](https://github.com/josseed/selfguard/releases) is:

1. **Signed with Developer ID and notarized by Apple**, with the hardened runtime.
2. **Attested by GitHub Actions** ([artifact attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)):
   a signed SLSA provenance statement says which repository, workflow and commit produced
   exactly that file. The attestation is also attached to the release as
   `selfguard-<version>-<arch>.dmg.sigstore.json`.
3. **Published with its SHA-256** (`.dmg.sha256`).

```sh
# Provenance: built by this repo's release workflow (needs the GitHub CLI)
gh attestation verify selfguard-<version>-<arch>.dmg \
  --repo josseed/selfguard \
  --signer-workflow josseed/selfguard/.github/workflows/release.yml

# Offline, with the bundle attached to the release
gh attestation verify selfguard-<version>-<arch>.dmg \
  --repo josseed/selfguard \
  --bundle selfguard-<version>-<arch>.dmg.sigstore.json

# Checksum
shasum -a 256 -c selfguard-<version>-<arch>.dmg.sha256

# Apple: signature and notarization of the app, once copied to /Applications
codesign --verify --strict --deep --verbose=2 /Applications/selfguard.app
spctl --assess --type execute --verbose /Applications/selfguard.app
```

`spctl` should say `source=Notarized Developer ID`.

Updates installed by the app (Sparkle) are checked three times before they are applied: the
EdDSA signature of the update feed, the EdDSA signature of the DMG, and Apple's signature of the
new app, which must come from the same developer as the running one.

## SBOM

Each release also carries a [CycloneDX](https://cyclonedx.org) SBOM of the npm package,
`selfguard-v<version>.cdx.json`, with its own attestation (`.cdx.json.sigstore.json`).
selfguard has **zero runtime dependencies**, so the SBOM lists only selfguard itself. The
release fails if that ever changes.

```sh
gh attestation verify selfguard-v<version>.cdx.json --repo josseed/selfguard
```

## Continuous, public checks

| Check | What it shows | Where |
|---|---|---|
| [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/josseed/selfguard) | An independent score of the repo's security practices, recomputed weekly | Badge in the README |
| CodeQL | Static analysis of the TypeScript sources and the workflows | Security tab → Code scanning |
| [zizmor](https://docs.zizmor.sh) | Security lint of every GitHub Actions workflow, on every change | Pull request checks |
| CI | Tests on macOS and Linux (Node 22 and 24, smoke test on Node 20), zero runtime dependencies enforced | Actions tab |

How selfguard is designed to be safe, what it sends and what it never does is described in the
[security model](security-model.md). To report a vulnerability, see [SECURITY.md](../SECURITY.md).
