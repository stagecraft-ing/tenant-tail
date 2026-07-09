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
  chain, adjudicates the optional platform countersign offline, checks the
  optional corpus binding by reference (spec 218), and adjudicates the optional
  agentic-posture binding (spec 210: internal consistency, plus a SBOM watchlist
  cross-check under `--sbom-dir`). The emitter
  (builder, signing-key handling, generation) is excluded by construction; the
  one spec-spine seam is feature-gated OFF so the vended build links no
  spec-spine crate.
depends_on: ["000-tenant-tail-bootstrap"]
establishes:
  - { kind: file, path: "crates/tenant-tail-core/src/certificate.rs" }
  - { kind: file, path: "crates/tenant-tail-core/src/data/agentic-sdk-watchlist.json" }
  - { kind: file, path: "crates/tenant-tail-core/src/inter_stage_manifest.rs" }
  - { kind: file, path: "crates/tenant-tail-core/src/platform_jws.rs" }
  - { kind: file, path: "crates/tenant-tail-core/src/lib.rs" }
  - { kind: file, path: "crates/tenant-tail-core/tests/certificate_parity.rs" }
  - { kind: directory, path: "crates/tenant-tail-core/tests/fixtures/cert-run" }
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

- `crates/tenant-tail-core/src/certificate.rs`: the certificate data types
  (including the additive `CorpusBinding`, `SbomArtifactBinding`, and
  `AgenticPostureBinding` / `CertAgenticSurface`, byte-identical to the emitter's)
  and the verify functions (`verify_certificate`, `verify_certificate_with_platform`,
  `compute_certificate_hash`, the Ed25519 signature check, and the
  corpus/SBOM/posture adjudicators `adjudicate_corpus_binding_state` /
  `adjudicate_sbom_binding_state` / `adjudicate_agentic_posture` +
  `agentic_posture_binding_inconsistencies`).
- `crates/tenant-tail-core/src/data/agentic-sdk-watchlist.json`: the agent/LLM SDK
  watchlist (spec 210 FR-003), embedded via `include_str!` so the verifier stays
  self-contained and adds no YAML dependency. Mirrors OAP's
  `standards/schemas/factory/agentic-sdk-watchlist.yaml` (same package names).
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
- A platform countersign that cannot be verified fails closed by default. The
  countersign is what binds the run to its admission contract, so the trust-nobody
  posture MUST reject (exit 1) a certificate that carries none, or that carries one
  with no JWKS supplied to adjudicate it. `--allow-unsealed` opts out, demoting the
  rejection to a visible `verifiable-but-unsealed` notice (exit 0) that is never
  silently equivalent to sealed. The offline chain is verified either way; only the
  seal verdict differs. (The deprecated `--require-sealed`, now the default, is
  accepted as a no-op.)
- The corpus binding (spec 218) is adjudicated by reference, never by recompute.
  When the certificate carries a `corpusBinding`, the claimed
  `corpusAttestationHash` is checked against the SHA-256 of a supplied
  attestation (`--corpus-attestation`); verifying the attestation's own truth is
  delegated to spec-spine's `verify-attestation`, never performed here. The four
  states are legible and never skip-as-pass (spec 218 FR-004): `unbound` (no
  binding), `present-but-unverified` (binding, no attestation supplied), and
  `verified` are visible notices with exit 0; only a hash `mismatch` is an error.
  The field is additive and optional, so an unbound certificate serialises
  byte-identically to a pre-binding payload and the parity fixture is unaffected.
- The SBOM artifact binding (spec 203) is adjudicated by reference, never by
  recompute. When the certificate carries a `sbomArtifactBinding`, the claimed
  `bomHash` and `auditHash` are re-derived by SHA-256 over the on-disk
  `<root>/.factory/{sbom.cdx.json,audit.json}` supplied via `--sbom-dir` and
  compared; the BOM is never regenerated. The states mirror the corpus binding's
  legible, never-skip-as-pass model (`adjudicate_sbom_binding_state`): `unbound`,
  `present-but-unverified` (binding, no `--sbom-dir`), and `verified` are visible
  notices, while a `bom`/`audit` hash mismatch or an unreadable artifact is an
  error. The field is additive and optional, so an unbound certificate serialises
  byte-identically and the parity fixture is unaffected.
- The agentic-posture binding (spec 210) MUST be carried and adjudicated. It is
  carried first for HASH PARITY: `compute_certificate_hash` round-trips the
  certificate through the typed struct, so a `agenticPostureBinding` the verifier
  did not know would be dropped on re-serialisation and the re-derived hash (and
  the signature check) would diverge from the emitter's. Beyond carrying it, the
  verifier adjudicates the binding in two parts:
  (a) INTERNAL CONSISTENCY (no BOM needed, `agentic_posture_binding_inconsistencies`):
  `none` must enumerate no surfaces; `declared`/`governed` must enumerate at least
  one; a `governed` surface must carry a `governance_envelope` that shape-validates
  as a spec-198 envelope (FR-004); an unknown posture is an error. A validly-signed
  but self-inconsistent binding is rejected. When (a) finds an inconsistency (e.g.
  an unknown posture string), the cross-check (b) is skipped: its outcome would
  otherwise fold a non-`none` posture into a reassuring notice that contradicts the
  error on the same binding.
  (b) SBOM CROSS-CHECK (`--sbom-dir`, `adjudicate_agentic_posture`): only a `none`
  posture (authored OR defaulted) is falsifiable this way. A `none` whose CycloneDX
  BOM carries a watchlisted agent/LLM SDK dependency is CONTRADICTED (an error
  naming the package); `declared`/`governed` acknowledge agency and never fail on a
  match. The watchlist is ecosystem-scoped: a purl match requires the BOM
  component's purl `<type>` to equal the entry's `ecosystem`, so an npm `openai`
  entry never matches a `pkg:pypi/openai` on a mixed-language BOM. A watchlist MISS
  is a stated-residual notice, never a silent pass; a
  missing `--sbom-dir` is a `present-but-unverified` notice (the posture is already
  bound + internally consistency-checked; the BOM is optional falsifiability
  evidence). The field is additive and optional, so an unbound certificate
  serialises byte-identically and the parity fixture is unaffected.
  The FR-004 governed-envelope check is a TOP-LEVEL shape check (recognised
  `schema_version` + required spec-198 sections present with correct JSON types),
  not the full nested `factory_contracts::GovernanceEnvelope` validation OAP's
  in-tree verifier performs; tenant-tail (Apache-2.0) does not vendor that type.
- Behavior parity: a certificate emitted by OAP's in-tree emitter MUST verify
  here unchanged (the parity test is the gate). A certificate emitted by
  `tenant-emit` carrying an `agenticPostureBinding` MUST likewise verify here (the
  hash re-derives through the carried field); tampering the bound posture MUST fail
  the signature + hash check (spec 210 AC-2).

## 4. Out of scope

- The emitter (certificate builder, signing-key resolution, `build-certificate`,
  `generate_certificate*`): excluded by construction, never ported.
- The spec-spine `validate_spec_id_resolution` seam: feature-gated OFF
  (`spec-id-resolution`), warn-only, changes no verdict; the vended build links
  no spec-spine crate.
- The `--jwks-url` network fetch from OAP's in-tree verifier: tenant-tail is
  offline-only and reads a saved JWKS file instead. Owned by 003-distribution's
  CLI surface.
