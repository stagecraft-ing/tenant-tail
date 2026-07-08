//! tenant-tail-core: the verify engines.
//!
//! Two cores, extracted standalone from OAP and kept in behavior parity with
//! their in-tree counterparts, relicensed Apache-2.0 from AGPL-3.0 by the sole
//! copyright holder (see NOTICE):
//!
//!   * certificate verify -- the producer-untrusted offline chain (Ed25519
//!     signature, certificate self-hash, stage artifact hashes, inter-stage
//!     manifest chain, optional platform countersign). The one spec-spine seam,
//!     `validate_spec_id_resolution`, is feature-gated OFF for this vended build
//!     (it is warn-only and changes no verdict; see `certificate`).
//!   * provenance verify -- the pure `validate()` plus the read-only `audit()`
//!     from OAP's standalone `provenance-validator`.
//!
//! The emitter is excluded by construction: no certificate builder, no signing
//! key handling, no identity. The cores are verify-only and offline.

pub mod certificate;
pub mod inter_stage_manifest;
pub mod platform_jws;
pub mod provenance;

// Cert verify surface, re-exported at the crate root for the CLI verbs.
pub use certificate::{
    AgenticPostureBinding, CERTIFICATE_VERSION, CertAgenticSurface, CorpusBinding,
    CorpusBindingState, GovernanceCertificate, PostureCrossCheckOutcome, SbomArtifactBinding,
    SbomBindingState, VerificationResult, adjudicate_agentic_posture,
    adjudicate_corpus_binding_state, adjudicate_sbom_binding_state,
    agentic_posture_binding_inconsistencies, verify_certificate, verify_certificate_with_platform,
};
pub use platform_jws::PlatformJwks;
