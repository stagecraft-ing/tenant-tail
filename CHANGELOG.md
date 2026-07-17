# Changelog

All notable changes to tenant-tail are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version
is below 1.0, a breaking change bumps the minor.

## [0.4.0] - 2026-07-08

### Added

- `verify-certificate` now carries and adjudicates the certificate's
  `agenticPostureBinding` (OAP spec 210). The binding is round-tripped through the
  typed certificate struct so the self-hash and Ed25519 signature stay intact,
  then adjudicated three ways: internal consistency (a `governed` posture must
  declare surfaces; a `none` posture must not), a cross-check of a declared `none`
  against the produced-app SBOM under `--sbom-dir` (an agentic-SDK dependency
  contradicts the declaration), and a top-level governance-envelope shape check
  (spec 210 FR-004). (#12, spec 001)
- The agentic-SDK watchlist is ecosystem-scoped, so an npm `openai` is not matched
  against a `pkg:pypi/openai` coordinate, and the purl match anchors on the
  package-name segment rather than a bare substring; the SBOM cross-check is
  skipped when internal consistency already failed, so an unknown posture no longer
  emits a contradictory notice. (#13, spec 001)

## [0.3.0] - 2026-07-03

### Breaking

- `verify-certificate` now **requires a verified platform seal by default.** An
  unsealed certificate, or a sealed one presented without a JWKS to adjudicate it
  against, exits `1` instead of `0`. The old `--require-sealed` flag is now the
  default and is accepted as a deprecated, hidden no-op. (#7, spec 001)

  **Migration for pinned tenants:** a `verify-certificate <cert.json>` invocation
  that exited `0` against an unsealed certificate will start exiting `1` after
  upgrading. Choose one:
  - supply `--platform-jwks <jwks.json>` so the platform countersign can actually
    be verified (the intended posture), or
  - pass the new `--allow-unsealed` flag to keep the prior behavior, which demotes
    a missing or unadjudicated seal to a visible notice rather than a failure.

  Because this ships as a minor bump under 0.x, tenants pinned to `0.2.0` (or a
  `~0.2`/`^0.2` range) do not cross this boundary until they deliberately move to
  `0.3`.

### Added

- Release builds now assert the manylinux_2_17 glibc floor. The Linux archives
  are cross-linked against glibc 2.17, and the release job fails if any produced
  binary references a `GLIBC_x.y` symbol newer than 2.17, so the npm and PyPI
  glibc platform tag cannot silently become untruthful. (#6, spec 003)

### Fixed

- Hardened the two verify cores, the exit-code contract (`0` verified/ok, `1`
  verification failed or a fail-closed flag fired, `2` usage or I/O error), and
  the release pipeline. (#5)

## [0.2.0] - 2026-07-01

### Added

- `verify-certificate` verifies the produced-app SBOM binding via `--sbom-dir`
  (OAP spec 203 FR-003). (#3)
- Docusaurus documentation website. (#1, #2)

## [0.1.0] - 2026-06-16

### Added

- Initial release of the verify-only `tenant-tail` CLI: `verify-certificate`
  (offline governance-certificate chain, self-hash re-derivation, Ed25519
  signature, platform countersign against a saved JWKS, inter-stage manifest
  chain) and `verify-provenance` (the read-only claim-provenance audit).
  Prebuilt-binary distribution via npm and PyPI; the repository dogfoods
  spec-spine governance over its own `specs/` corpus.

[0.4.0]: https://github.com/statecrafting/tenant-tail/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/statecrafting/tenant-tail/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/statecrafting/tenant-tail/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/statecrafting/tenant-tail/releases/tag/v0.1.0
