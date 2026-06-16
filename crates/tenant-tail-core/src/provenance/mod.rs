//! Provenance verify core: the claim-provenance validator, extracted from OAP's
//! standalone `provenance-validator` crate (spec 121) and relicensed Apache-2.0
//! from AGPL-3.0 by the sole copyright holder (see NOTICE). It is the read-only
//! "data and matching" layer plus the `validate()` / `audit()` entry points:
//!
//!   - the project allowlist derivation pipeline,
//!   - the corpus view and inventory hash for drift detection,
//!   - citation verification against the typed extraction corpus,
//!   - the external-entity plausibility heuristic,
//!   - `validate()` (pure, byte-deterministic) and `audit()` (the read-only
//!     retroactive walk a produced app re-checks itself with).
//!
//! ## LLM independence
//!
//! The validator MUST NOT depend on any LLM client crate: it must not be
//! foolable by the same model that minted the claims it validates. tenant-tail's
//! whole dependency graph is crypto + serde only, which preserves this by
//! construction.

pub mod allowlist;
pub mod citation;
pub mod corpus;
pub mod manifest;
pub mod validator;

pub use allowlist::{
    Allowlist, CapitalizationHeuristic, EntityPlausibility, ProjectContext,
    derive as derive_allowlist, detect_external_entities,
};
pub use citation::{
    CitationHit, CitationResult, EntitySearchSummary, search_entity, verify_citation,
};
pub use corpus::{Corpus, CorpusEntry, extracted_corpus_hash};
pub use manifest::{
    ParsedAssumptionEntry, append_pending_promotion, assumption_manifest_body,
    emit_assumption_manifest, parse_assumption_manifest,
};
pub use validator::{
    AuditReport, ClaimRecord, CorpusSource, VALIDATION_REPORT_VERSION, ValidationReport,
    ValidationSummary, audit, audit_with_options, render_audit_report, validate,
};

// Re-export the Phase 1 hash functions and the budget contract so
// consumers of this crate get a single import path.
pub use tenant_tail_types::AssumptionBudget;
pub use tenant_tail_types::provenance::{anchor_hash, quote_hash};
