---
id: ecosystem
title: Ecosystem
sidebar_position: 9
---

# Ecosystem

`tenant-tail` exists within a broader ecosystem of governance and verification tools, acting as the verify-only counterpart to `tenant-emit`.

## The Emit/Verify Boundary

- **`tenant-emit`:** Produces governance certificates and provenance claims. It is identity-bearing, non-reproducible, and harness-bound.
- **`tenant-tail`:** Verifies those artifacts offline with no trust in the producer.

This boundary is deliberate. The two are separate distributables, ensuring that the verifier cannot be compromised by the same environment or keys that produced the assertions. The single `spec-spine` seam in the code (`validate_spec_id_resolution`) is feature-gated OFF in the vended build and changes no verdict.

## Relicensing

The verify cores (`tenant-tail-core` and `tenant-tail-types`) were extracted from the upstream Open Agentic Platform (OAP) factory engine. 

While the OAP factory engine is licensed under `AGPL-3.0`, the extracted verify-only source was explicitly relicensed to **Apache-2.0** by the sole copyright holder. This allows `tenant-tail` to be freely embedded and used by produced applications without imposing copyleft obligations on the tenant's build or deployment environment.
