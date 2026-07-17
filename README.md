# [tenant-tail](https://statecrafting.github.io/tenant-tail/) [![CI](https://github.com/statecrafting/tenant-tail/actions/workflows/ci.yml/badge.svg)](https://github.com/statecrafting/tenant-tail/actions/workflows/ci.yml)
![Tenant Tail Verification Surface](.github/img/tenant-tail-github-banner.jpg)

**The vended tenant verification surface. Spine to tail: spec-spine compiles the
corpus, tenant-tail verifies the factory's run-side paperwork.**

tenant-tail is a verify-only CLI a produced application pins (one exact-version
npm devDependency, next to `spec-spine`) to re-check the run-side artifacts the
factory asserted about its build, with no trust in the producer (the spec 102
do-not-trust-the-producer posture, turned tenant-ward). It is offline-capable,
identity-free, and read-only all the way down to the package boundary.

## Verbs

- `verify-certificate` -- the governance certificate (artifact-hash chain,
  Ed25519 signature, platform countersign, inter-stage manifest chain).
- `verify-provenance` -- the claim-provenance validator over factory-written
  claims.
- `verify-sbom` -- **staged, not yet shipped.** Its core does not exist yet
  (OAP spec 203 is an unimplemented draft, and by its own design the verify side
  extends the certificate core). It joins as a third verb under the same one-pin
  model when that core is built.

The emitter (`build-certificate`) is deliberately NOT here: it is
identity-bearing, non-reproducible, and harness-bound, and ships with its firing
in a separate emit spec. tenant-tail is verify-only by construction (no emitter
verb, no emitter dependency).

## Status: SCAFFOLD

This repository is currently a structural skeleton mirroring spec-spine's
repo/crate/npm shape. The verify cores are extracted and implemented by the
tenant-tail worker agent. Governing artifacts:

- **OAP spec 219-tenant-tail-verifier-toolkit** -- the decision to vend, the
  scope, and the OAP-side extraction source.
- **`residuals-certificate-attestation-architecture.md`** (OAP, "R-1 read")
  -- the coupling read confirming both cores extract cleanly.
- **This repo's `specs/` corpus** -- governs tenant-tail's own code, compiled by
  the pinned `spec-spine` library (see `spec-spine.toml`).

## Layout

```
crates/
  tenant-tail-types/   shared verify-surface DTOs (carrier types)
  tenant-tail-core/    the verify engines (certificate, provenance)
  tenant-tail-cli/     the `tenant-tail` binary (verbs)
npm/                   prebuilt-binary npm wrapper (mirror of spec-spine's)
specs/                 this repo's spec corpus (governed by spec-spine)
standards/spec/        authoring templates
.github/workflows/     ci (dogfood) + release (per-triple binaries + npm)
```

## License

Apache-2.0 (matching spec-spine). The verify cores are extracted from OAP's
AGPL-3.0 factory-engine; relicensing the extracted verify-only source to
Apache-2.0 is the prerogative of the sole copyright holder and is an explicit,
authorized act (see the tenant-tail handoff).
