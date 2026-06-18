# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tenant-tail` is a **verify-only** CLI: a produced application pins it (one exact-version
npm devDependency, next to `spec-spine`) to re-check the run-side paperwork a factory
asserted about its build, with **no trust in the producer** (the spec 102
do-not-trust-the-producer posture, turned tenant-ward). It is offline-capable,
identity-free, and read-only down to the package boundary.

Both verify cores are implemented and tested. They are extracted from OAP's AGPL-3.0
factory-engine and relicensed Apache-2.0 by the sole copyright holder (see `NOTICE`).
Governing decision: OAP spec `219-tenant-tail-verifier-toolkit`.

The verbs (see `crates/tenant-tail-cli/src/main.rs`):

- `verify-certificate <cert.json>` -- governance certificate verification. Re-derives
  the certificate self-hash, checks the Ed25519 signature (the authoritative provenance
  check, FR-008.4), optionally re-derives stage artifact hashes (`--artifact-dir`),
  replays the inter-stage manifest chain, and adjudicates the optional platform
  countersign against a saved JWKS (`--platform-jwks`; `--require-sealed` fails closed
  on an unsealed/unadjudicated seal).
- `verify-provenance --project <dir>` -- the claim-provenance audit (`audit()` over the
  pure `validate()`). The markdown report goes to **stdout** (never written into the
  audited project); `--corpus` overrides the corpus path; `--fail-on-rejected` exits 1
  on any rejected claim (OAP's in-tree audit is diagnostic-only and always exits 0).
- `verify-sbom` -- **deliberately absent, not stubbed.** Its core (OAP spec 203) does
  not exist yet; the verb joins under the same one-pin model when that core is built.

**Exit-code convention:** `0` verified/ok, `1` verification failed or a fail-closed flag
fired, `2` usage or I/O error (unreadable/invalid input).

## Hard invariants (do not violate)

- **Verify-only by construction.** Never add an emitter verb (`build-certificate`), an
  emitter dependency, signing-key handling, or any network/identity surface. The
  boundary is structural, not documentary. `unsafe_code = "forbid"` is set workspace-wide.
  The whole dependency graph is crypto + serde only; the provenance validator in
  particular MUST NOT gain an LLM client dependency (it must not be foolable by the same
  model that minted the claims it checks).
- **No network fetch.** The cert verb's platform-seal check reads a saved JWKS file
  (`--platform-jwks`); OAP's `--jwks-url` network fetch is intentionally omitted
  (tenant-tail links no HTTP client).
- **The npm wrapper mirrors `spec-spine`'s `npm/` shape exactly.** `bin/tenant-tail.js`,
  `lib/platform.js`, and `scripts/generate-platform-packages.js` each say "Mirror of
  spec-spine's ...". If the launcher/packaging contract changes, diff against that
  canonical source rather than diverging.
- **One platform-targets fact, four copies, kept in lockstep:** the `SUPPORTED` map in
  `npm/lib/platform.js`, the `TARGETS` map in `npm/scripts/generate-platform-packages.js`,
  the `TARGETS` map in `py/src/tenant_tail/platform_map.py`, and the build matrix in
  `.github/workflows/release.yml`. The five targets are
  `darwin-arm64`, `darwin-x64`, `linux-x64` (glibc), `linux-arm64` (glibc), `win32-x64`.
  musl Linux is intentionally unsupported (npm/PyPI fall back to the sdist refusal or
  `cargo install`).
- **The cert-verify `validate_spec_id_resolution` seam stays feature-gated OFF** in this
  vended build (behind the off-by-default `spec-id-resolution` Cargo feature, in
  `certificate.rs`). It is warn-only and changes no verdict; it is the one `spec-spine`
  coupling that must not become a hard dependency here. Enabling it would also require
  adding `open_agentic_spec_registry_reader`, which tenant-tail deliberately does not do.
- **Behavior parity with OAP.** The cert DTOs are preserved verbatim so deserialization
  and the recomputed self-hash stay byte-identical to OAP's; the platform countersign is
  zeroed before canonicalisation so sealing never invalidates the offline chain. Don't
  reorder fields or change serde attributes without re-confirming the parity tests.

## Architecture

Three-crate Cargo workspace (`Cargo.toml`), mirroring `spec-spine`'s types/core/cli shape.
All three crates declare `[package.metadata.tenant-tail].spec = "000-tenant-tail-bootstrap"`.

- `crates/tenant-tail-types` -- shared verify-surface DTOs and contracts (serde-only, no
  logic): `provenance.rs` (carrier types, `anchor_hash`/`quote_hash` with NFC
  normalization), `knowledge.rs` (corpus fingerprinting), `budget.rs` (`AssumptionBudget`).
- `crates/tenant-tail-core` -- the verify engines (crypto + serde):
  - `certificate.rs` -- the `GovernanceCertificate` DTOs, `verify_certificate` (offline
    chain), and `verify_certificate_with_platform` (adds seal adjudication).
    `CERTIFICATE_VERSION` is the only accepted version; older fixtures pass via
    `skip_serializing_if`-guarded optional fields.
  - `inter_stage_manifest.rs` -- the signed inter-stage manifest chain (spec 170 FR-007).
  - `platform_jws.rs` -- offline compact-JWS verification against a `PlatformJwks`.
  - `provenance/` -- `validator.rs` (`validate`/`audit`/`render_audit_report`),
    `allowlist.rs`, `citation.rs`, `corpus.rs`, `manifest.rs`. The validator is pure and
    byte-deterministic; `audit()` is the read-only retroactive walk an app re-checks
    itself with.
- `crates/tenant-tail-cli` -- the `tenant-tail` binary wiring the verbs over the core.

`npm/` is a prebuilt-binary distribution wrapper (no Rust toolchain needed by consumers):
the main `tenant-tail` package carries a thin exec-forward launcher; each
`@tenant-tail/cli-<os>-<cpu>` optional dependency carries exactly one prebuilt binary, so
npm installs only the one matching the host. Platform packages and binaries are assembled
from release archives at publish time and are **never committed** (`/npm/dist/` is ignored).

`py/` is the parallel PyPI channel, a faithful mirror of spec-spine's `py/` (spec-spine 008):
one `tenant-tail` PyPI project shipping the same prebuilt binary as five per-platform wheels
(the wheel platform tag is the selector) plus an sdist whose only entry point is the
unsupported-host refusal (`_refuse.py`). `scripts/generate_wheels.py` assembles
byte-reproducible, version-locked wheels from the same release archives (no second Rust
build), the exact analogue of npm's `generate-platform-packages.js`. `platform_map.py` is
the Python copy of the five-target fact (see the lockstep invariant). `py/dist/` is ignored.

### Parity tests

`crates/tenant-tail-core/tests/` holds the cross-implementation parity checks (the analogue
of OAP's schema-parity-walker):

- `certificate_parity.rs` against `tests/fixtures/cert-run/` -- a real certificate minted by
  OAP's in-tree emitter must verify here, and tampering must be caught. Regenerate the
  fixture with OAP's `build-certificate` when the certificate format changes (regeneration
  command is in the test's header comment).
- `provenance_parity.rs` against `tests/fixtures/provenance-project/` -- exercises the full
  `audit()` path (BRD discovery, claim parsing, corpus loading, validation). Per-rule logic
  parity lives in OAP's own validator unit tests, ported in-crate and run unchanged.

## Governance (this repo dogfoods spec-spine)

This repo's own `specs/` corpus is governed by the **pinned `spec-spine` library** (the
self-governance pattern spec-spine and OAP follow). The pin has landed: the repo-root
`package.json` declares `spec-spine` as a devDependency (currently `0.7.0`), installed via
`npm ci` from the committed `package-lock.json`. Config is `spec-spine.toml` (metadata
namespace `tenant-tail`; `domain`/`kind` validation disabled). New code must be claimed by
a spec in `specs/` or the coupling gate fails. The corpus: `000-tenant-tail-bootstrap`
(the workspace + crates), `001-certificate-verify-core`, `002-provenance-verify-core`,
`003-distribution` (the npm package owns this one). Authoring template:
`standards/spec/templates/spec-template.md`.

Governance commands (the root `package.json` also wraps these as `spec:*` npm scripts):

```sh
npx --no-install spec-spine compile            # compile/validate the spec registry
npx --no-install spec-spine index check        # committed index must be current
npx --no-install spec-spine lint --fail-on-warn
npx --no-install spec-spine couple --base <sha> --head HEAD --pr-body <file>
npm run spec:check                             # compile && index check && lint, in one
```

Note: `.derived/` (compiler/indexer output, sharded by spec-spine 0.5.0 into
`spec-registry/by-spec/*.json` and `codebase-index/by-spec,by-package/*.json`) is
deliberately **committed** so the coupling gate and the staleness check can compare
committed against current. Only `build-meta.json` is ignored
(it carries a wall-clock timestamp). Two `.githooks/` scripts install a merge driver that
regenerates `.derived/` on merge conflicts.

## Common commands

```sh
# Build / test the whole workspace
cargo build --workspace
cargo test --workspace
cargo test -p tenant-tail-core <test_name>     # a single test (e.g. a parity test)

# The exact gates CI's `test` job runs (mirror these before pushing)
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked

# npm wrapper (cd npm/)
npm test            # node --test over test/*.test.js (platform-resolution tests)
npm run generate    # assemble the per-platform packages from release archives
npm run smoke       # scripts/smoke-test.sh
```

Toolchain is pinned to Rust `1.92.0` (`rust-toolchain.toml`); edition 2024, MSRV 1.85.

## CI / release

`ci.yml` runs three jobs aggregated by a single required status check, **`ci-gate`** (set
branch protection / the merge queue to require just that one name, not the enumerated list):

- `test` -- fmt/clippy/build/test, all `--locked`.
- `self_governance` -- `npm ci` then the pinned spec-spine over this corpus: `compile`,
  `index check`, `lint --fail-on-warn`, and (pull_request only) `couple` against the PR
  base SHA. The coupling gate reads the `Spec-Drift-Waiver:` line from the PR body, which a
  push to `main` and `merge_group` runs do not carry, so it is PR-gated.
- `determinism` (reusable workflow `determinism.yml`) -- regenerates `.derived/` on four
  triples (Linux x86_64/aarch64, macOS aarch64, Windows x86_64) and asserts the
  `spec-registry/` and `codebase-index/` shard-tree digests are byte-identical across all
  of them, proving the committed artifacts are platform-independent. `build-meta.json` is
  excluded.

`release.yml` is tag-gated (`v*`): builds a per-triple archive (with a `.sha256` sidecar, a
per-target CycloneDX SBOM, and a SLSA build-provenance attestation) for all five targets,
creates the GitHub Release, and publishes crates + npm + PyPI (three publish legs mirroring
spec-spine, all assembled from the same archives, no second Rust build). `publish-crates`,
`publish-npm`, and `publish-pypi` are idempotent (skip versions already live); `publish-npm`
is a clean no-op without the `NPM_TOKEN` secret, and `publish-pypi` a clean no-op unless the
`PYPI_TRUSTED_PUBLISHING` repo variable is `true` (OIDC Trusted Publishing, no stored token).
