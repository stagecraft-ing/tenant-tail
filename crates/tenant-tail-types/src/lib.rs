//! tenant-tail-types: shared DTOs for the vended verify surface.
//!
//! SCAFFOLD ONLY. The carrier types for the two verify cores are implemented by
//! the tenant-tail worker agent:
//!   * certificate types (extracted from OAP
//!     `crates/factory-engine/src/governance_certificate.rs` and its
//!     `inter_stage_manifest` / `platform_jws` siblings),
//!   * provenance carrier types (the bounded `provenance` + `knowledge` slice of
//!     OAP `crates/factory-contracts`, plus `AssumptionBudget`).
//!
//! See OAP spec 219-tenant-tail-verifier-toolkit and the "R-1 read" section of
//! OAP's residuals-certificate-attestation-architecture.md for the extraction
//! map and the import classification per core.
