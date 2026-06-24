---
id: reference
title: Reference
sidebar_position: 6
---

# Reference

## Exit Codes

- `0`: Verified successfully.
- `1`: Verification failed, or a fail-closed flag fired (e.g., `--require-sealed` or `--fail-on-rejected`).
- `2`: Usage or I/O error (e.g., unreadable or invalid input file).

## Error Messages and Diagnostics

`tenant-tail` provides specific error messages for verification failures:
- **Artifact hash mismatch:** "artifact hash mismatch" indicates a file on disk does not match the hash recorded in the certificate.
- **Signature invalid:** Fails the Ed25519 signature check.
- **Platform countersign invalid:** The provided JWKS could not verify the JWS seal, or the seal binds a different certificate hash.
- **Validator panic:** A fail-closed panic in the provenance validator records all claims as rejected with the panic reason.

## Certificate Schema

The verifier strictly accepts certificate format version `1.5.0`. Older fixtures may pass via optional fields, but the core engine validates against the `1.5.0` DTOs.

## Provenance Report Format

The markdown report written to `stdout` by `verify-provenance` contains:
- **Metadata:** `schemaVersion`, `provenanceSchemaVersion`, `validatorVersion`, `synthesizedCorpus`, `brdNotFound`, `corpusEmpty`, `corpusSource`, `extractedCorpusHash`, `allowlistVersionHash`.
- **Summary Table:** Counts for `derived`, `derivedWeak`, `assumption`, `assumptionOrphaned`, and `rejected`, plus a `provenanceHealth` percentage.
- **Findings:** A detailed breakdown per claim (`anchorHash`, `entityCandidates`, `corpusSearchSummary`).
- **Suggested Next Actions:** Actionable advice for rejected or orphaned claims.

## Corpus Formats

The corpus can be supplied in two formats:
1. **Typed JSON:** Spec-120 `ExtractionOutput` JSON files (e.g., `<project>/.artifacts/corpus/*.json`).
2. **Legacy `.txt`:** Synthesized into `ExtractionOutput`s. The audit report will explicitly mark `synthesizedCorpus: true`.
