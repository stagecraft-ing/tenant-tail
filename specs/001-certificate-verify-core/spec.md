---
id: "001-certificate-verify-core"
title: "Certificate verify core (offline governance-certificate verification)"
status: draft
created: "2026-06-16"
authors: ["tenant-tail"]
kind: verify-core
implementation: complete
risk: medium
summary: >
  The governance-certificate verify engine, extracted verify-only from OAP's
  factory-engine and relicensed Apache-2.0 (see NOTICE). Re-derives the
  certificate self-hash, verifies the Ed25519 engine signature, re-checks stage
  artifact hashes against files on disk, replays the signed inter-stage manifest
  chain, and adjudicates the optional platform countersign offline. The emitter
  (builder, signing-key handling, generation) is excluded by construction; the
  one spec-spine seam is feature-gated OFF so the vended build links no
  spec-spine crate.
depends_on: ["000-tenant-tail-bootstrap"]
establishes:
  - { kind: file, path: "crates/tenant-tail-core/src/certificate.rs" }
  - { kind: file, path: "crates/tenant-tail-core/src/inter_stage_manifest.rs" }
  - { kind: file, path: "crates/tenant-tail-core/src/platform_jws.rs" }
  - { kind: file, path: "crates/tenant-tail-core/tests/certificate_parity.rs" }
references:
  - { unit: { kind: file, path: "NOTICE" }, role: context }
---

# 001: Certificate verify core

## 1. Purpose

A produced application must be able to re-check the governance certificate the
factory asserted about its build, with no trust in the producer and no network.
This spec governs the verify-only certificate engine that does so: it is the
tenant-ward half of OAP's `verify_certificate` path, extracted standalone and
relicensed Apache-2.0.

## 2. Territory

- `crates/tenant-tail-core/src/certificate.rs`: the certificate data types and
  the verify functions (`verify_certificate`, `verify_certificate_with_platform`,
  `compute_certificate_hash`, the Ed25519 signature check).
- `crates/tenant-tail-core/src/inter_stage_manifest.rs`: the inter-stage
  manifest types and `verify_manifest` (replayed by the certificate verifier).
- `crates/tenant-tail-core/src/platform_jws.rs`: compact-JWS verification for
  the platform countersign.
- `crates/tenant-tail-core/tests/certificate_parity.rs`: the cross-implementation
  parity test against a certificate minted by OAP's own emitter.

## 3. Behavior

- Verification MUST be offline and read-only: no network, no signing, no
  mutation of the inputs.
- The signature check (spec 102 FR-008.4) is the authoritative provenance
  check; the self-hash is defence-in-depth. A tamper-with-resign attack that
  only updates the hash MUST be caught by the signature.
- When an artifact directory is supplied, every recorded stage artifact hash
  MUST be re-derived from the file on disk and compared (spec 102 FR-005).
- A present inter-stage chain MUST replay against the embedded run key chain;
  a tampered or cross-run manifest MUST surface as a distinct error.
- An absent platform countersign is `verifiable-but-unsealed`: a visible notice,
  exit 0, never silently equivalent to sealed. `--require-sealed` promotes it to
  an error.
- Behavior parity: a certificate emitted by OAP's in-tree emitter MUST verify
  here unchanged (the parity test is the gate).

## 4. Out of scope

- The emitter (certificate builder, signing-key resolution, `build-certificate`,
  `generate_certificate*`): excluded by construction, never ported.
- The spec-spine `validate_spec_id_resolution` seam: feature-gated OFF
  (`spec-id-resolution`), warn-only, changes no verdict; the vended build links
  no spec-spine crate.
- The `--jwks-url` network fetch from OAP's in-tree verifier: tenant-tail is
  offline-only and reads a saved JWKS file instead. Owned by 003-distribution's
  CLI surface.
