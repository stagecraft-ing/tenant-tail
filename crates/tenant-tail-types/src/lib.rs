//! tenant-tail-types: shared DTOs for the vended verify surface.
//!
//! The provenance verify core (`tenant-tail-core`) consumes its carrier types
//! through this crate, the same way OAP's `provenance-validator` consumes
//! `factory-contracts`. The bounded slice extracted here is the `provenance` +
//! `knowledge` + `budget` surface those validators touch; nothing else from
//! `factory-contracts` is in scope, so the heavy `agent-frontmatter` / `ts-rs`
//! leaf is left behind and the dependency graph stays crypto + serde only.
//!
//! Relicensed Apache-2.0 from OAP's AGPL-3.0 `crates/factory-contracts` by the
//! sole copyright holder (see NOTICE). The cert verify carrier types live with
//! their engine in `tenant-tail-core`, not here: they are one cohesive extracted
//! unit and splitting their mutually-referencing items across the crate boundary
//! buys nothing.

pub mod budget;
pub mod knowledge;
pub mod provenance;

pub use budget::AssumptionBudget;
pub use provenance::{PROVENANCE_SCHEMA_VERSION, anchor_canonical_tokens, anchor_hash, quote_hash};

/// Re-export of `chrono::DateTime`, `Utc`, and `TimeZone` so the verify core can
/// name them without adding `chrono` to its own `[dependencies]`, mirroring
/// `factory-contracts`'s re-export (which the ported validator imports as
/// `factory_contracts::{DateTime, Utc, TimeZone}`).
pub use chrono::{DateTime, TimeZone, Utc};

/// Wall-clock timestamp helper for callers that need `now` without pulling
/// `chrono` into their own `[dependencies]`. Used by the ported provenance
/// validator's audit path.
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}
