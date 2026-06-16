//! tenant-tail-core: the verify engines.
//!
//! SCAFFOLD ONLY. Two cores, extracted standalone and kept in behavior parity
//! with their OAP in-tree counterparts (warn-only diff acceptable), implemented
//! by the tenant-tail worker agent:
//!
//!   * certificate verify -- the `verify_certificate` path (Ed25519 signature,
//!     certificate self-hash, stage artifact hashes, inter-stage manifest chain,
//!     optional platform countersign). The one spec-spine seam,
//!     `validate_spec_id_resolution`, is feature-gated OFF for this vended build
//!     (it is warn-only and changes no verdict).
//!   * provenance verify -- the pure `validate()` from OAP
//!     `crates/provenance-validator` (already a standalone crate; sheds clean).
//!
//! The emitter is excluded by construction: no `build-certificate`, no signing
//! key handling, no identity. See OAP spec 219.
