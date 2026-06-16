# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tenant-tail` is a **verify-only** CLI: a produced application pins it (one exact-version
npm devDependency, next to `spec-spine`) to re-check the run-side paperwork a factory
asserted about its build, with **no trust in the producer** (the spec 102
do-not-trust-the-producer posture, turned tenant-ward). It is offline-capable,
identity-free, and read-only.

**Status: SCAFFOLD.** The structure is in place; the verify cores are not yet
implemented. The CLI binary currently prints a notice and exits `70` (EX_SOFTWARE).
The cores are extracted from OAP's AGPL-3.0 factory-engine and relicensed Apache-2.0;
they are added by subsequent specs in this repo's corpus as the extraction lands.
Governing decision: OAP spec `219-tenant-tail-verifier-toolkit`.

The planned verbs:
- `verify-certificate` -- governance certificate (Ed25519 signature, certificate
  self-hash, stage artifact hashes, inter-stage manifest chain, optional platform
  countersign).
- `verify-provenance` -- the pure `validate()` claim-provenance validator.
- `verify-sbom` -- staged, not yet shipped (its core, OAP spec 203, does not exist yet).

## Hard invariants (do not violate)

- **Verify-only by construction.** Never add an emitter verb (`build-certificate`), an
  emitter dependency, signing-key handling, or any network/identity surface. The
  boundary is structural, not documentary. `unsafe_code = "forbid"` is set workspace-wide.
- **The npm wrapper mirrors `spec-spine`'s `npm/` shape exactly.** `bin/tenant-tail.js`,
  `lib/platform.js`, and `scripts/generate-platform-packages.js` each say "Mirror of
  spec-spine's ...". If the launcher/packaging contract changes, diff against that
  canonical source rather than diverging.
- **One platform-targets fact, three copies, kept in lockstep:** the `SUPPORTED` map in
  `npm/lib/platform.js`, the `TARGETS` map in `npm/scripts/generate-platform-packages.js`,
  and the build matrix in `.github/workflows/release.yml`. The five targets are
  `darwin-arm64`, `darwin-x64`, `linux-x64` (glibc), `linux-arm64` (glibc), `win32-x64`.
  musl Linux is intentionally unsupported (falls back to `cargo install`).
- **The cert-verify `validate_spec_id_resolution` seam stays feature-gated OFF** in this
  vended build. It is warn-only and changes no verdict; it is the one `spec-spine`
  coupling that must not become a hard dependency here.

## Architecture

Three-crate Cargo workspace (`Cargo.toml`), mirroring `spec-spine`'s types/core/cli shape:

- `crates/tenant-tail-types` -- shared verify-surface DTOs (certificate + provenance
  carrier types). Serde-only, no logic.
- `crates/tenant-tail-core` -- the verify engines (certificate verify, provenance verify).
  Crypto + serde only (`sha2`, `ed25519-dalek`, `base64`, `chrono`, `unicode-normalization`).
- `crates/tenant-tail-cli` -- the `tenant-tail` binary that wires the verbs over the core.

`npm/` is a prebuilt-binary distribution wrapper (no Rust toolchain needed by consumers):
the main `tenant-tail` package carries a thin exec-forward launcher; each
`@tenant-tail/cli-<os>-<cpu>` optional dependency carries exactly one prebuilt binary, so
npm installs only the one matching the host. Platform packages and binaries are assembled
from release archives at publish time and are **never committed** (`/npm/dist/` is ignored).

## Governance (this repo dogfoods spec-spine)

This repo's own `specs/` corpus is governed by the **pinned `spec-spine` library**, the
same self-governance pattern spec-spine and OAP follow. Config lives in `spec-spine.toml`
(metadata namespace `tenant-tail`; `domain`/`kind` validation disabled). Every crate
declares its owning spec via `[package.metadata.tenant-tail].spec = "NNN-slug"`; the npm
package uses the `"tenant-tail": { "spec": "..." }` key. New code must be claimed by a
spec in `specs/` or the coupling gate fails. Authoring template:
`standards/spec/templates/spec-template.md`.

Governance commands (require `spec-spine` pinned in a root `package.json`, which the worker
adds when wiring governance; not present yet in the scaffold):

```sh
npx --no-install spec-spine compile          # compile/validate the spec registry
npx --no-install spec-spine index check      # committed index must be current
npx --no-install spec-spine lint --fail-on-warn
npx --no-install spec-spine couple --base <sha> --head HEAD --pr-body <file>
```

Note: `.derived/` (compiler/indexer output) is deliberately **committed** so the coupling
gate and staleness check can compare against current inputs; only `build-meta.json` is
ignored (it carries a wall-clock timestamp).

## Common commands

```sh
# Build / test the whole workspace
cargo build --workspace
cargo test --workspace
cargo test -p tenant-tail-core <test_name>   # a single test

# The exact gates CI runs (mirror these before pushing)
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

Toolchain is pinned to Rust `1.92.0` (`rust-toolchain.toml`); edition 2024, MSRV 1.85.

npm wrapper scripts (`npm/package.json`): `npm test` (node test runner over `test/*.test.js`),
`npm run generate` (assemble platform packages), `npm run smoke`. The `test/` dir and
smoke script are not present in the scaffold yet.

## CI / release

- `.github/workflows/ci.yml` -- `test` job (fmt/clippy/build/test, all `--locked`) plus a
  `dogfood` job that runs the pinned spec-spine over this corpus (skeleton until the pin lands).
- `.github/workflows/release.yml` -- tag-gated (`v*`): builds a per-triple archive (with a
  `.sha256` sidecar, a per-target CycloneDX SBOM, and a SLSA build-provenance attestation)
  for all five targets, creates the GitHub Release, and publishes crates + npm packages.
  `publish-crates` and `publish-npm` are idempotent (skip versions already live);
  `publish-npm` is a clean no-op without the `NPM_TOKEN` secret.
