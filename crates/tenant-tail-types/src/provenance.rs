//! Rust contract types for claim provenance enforcement (spec 121).
//!
//! Every Phase-1 claim minted by the Factory carries a `ProvenanceMode` and,
//! if it names external reality, a verbatim `Citation` against the typed
//! extraction corpus produced by spec 120. Claims that name external entities
//! with no citation and no `ASSUMPTION` tag are `Rejected`; the QG-13 gate
//! blocks the pipeline.
//!
//! `anchor_hash` is the load-bearing function for stable IDs across
//! regeneration: a charter reword that preserves the underlying concept must
//! produce the same hash so `BR-007` does not renumber and obliterate
//! downstream Stage-4/5 hand-fixes.
//!
//! The reserved TS mirror lives at
//! `platform/services/stagecraft/api/governance/provenancePolicy.ts`. When
//! that file lands, `tools/oap/schema-parity-check` will compare its fingerprint
//! against `provenance_schema_fingerprint()`. Until then, the parity check
//! records the Rust-side fingerprint to `build/schema-parity/` so the
//! comparison is ready on first TS-side commit.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use unicode_normalization::UnicodeNormalization;

/// Shared schema version. Mirrored verbatim by `PROVENANCE_SCHEMA_VERSION`
/// in `provenancePolicy.ts` once the TS mirror lands.
pub const PROVENANCE_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Typed wrappers
// ---------------------------------------------------------------------------

/// Stable identifier for a claim, e.g. `BR-007`, `STK-13`, `INT-003`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClaimId(pub String);

impl From<&str> for ClaimId {
    fn from(s: &str) -> Self {
        ClaimId(s.to_string())
    }
}

impl std::fmt::Display for ClaimId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// SHA-256 hex of normalised claim text. See [`anchor_hash`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnchorHash(pub String);

impl AnchorHash {
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AnchorHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// SHA-256 hex of an NFC + whitespace-normalised quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteHash(pub String);

impl QuoteHash {
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ClaimKind -- the full set the spec allows Stage 1 (and later) to mint.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimKind {
    #[serde(rename = "BR")]
    Br,
    #[serde(rename = "STK")]
    Stk,
    #[serde(rename = "SN")]
    Sn,
    #[serde(rename = "UC")]
    Uc,
    #[serde(rename = "TC")]
    Tc,
    #[serde(rename = "INT")]
    Int,
    #[serde(rename = "FS")]
    Fs,
    #[serde(rename = "SYSREQ")]
    Sysreq,
    #[serde(rename = "STREQ")]
    Streq,
    #[serde(rename = "SWREQ")]
    Swreq,
    #[serde(rename = "USRREQ")]
    Usrreq,
}

impl ClaimKind {
    /// The two- to seven-letter token used as the prefix in `<KIND>-<NNN>`
    /// claim IDs. Matches the JSON serialisation exactly.
    pub fn prefix(&self) -> &'static str {
        match self {
            ClaimKind::Br => "BR",
            ClaimKind::Stk => "STK",
            ClaimKind::Sn => "SN",
            ClaimKind::Uc => "UC",
            ClaimKind::Tc => "TC",
            ClaimKind::Int => "INT",
            ClaimKind::Fs => "FS",
            ClaimKind::Sysreq => "SYSREQ",
            ClaimKind::Streq => "STREQ",
            ClaimKind::Swreq => "SWREQ",
            ClaimKind::Usrreq => "USRREQ",
        }
    }
}

// ---------------------------------------------------------------------------
// ProvenanceMode -- discriminated union; tag = "mode" matches Zod conventions.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum ProvenanceMode {
    /// Verbatim citation against the corpus.
    Derived,
    /// Citation points at an `ASSUMPTION`-tagged extraction (uncertain source);
    /// passes the gate but surfaces in the report.
    DerivedWeak,
    /// Carries an `AssumptionTag` and consumes a budget slot.
    Assumption,
    /// Was `Derived`; corpus drift orphaned the citation. Promoted to budget.
    AssumptionOrphaned,
    /// External entity named, no citation, no assumption -- gate blocks in
    /// STRICT mode.
    Rejected { reason: String },
}

// ---------------------------------------------------------------------------
// Citation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Citation {
    /// Path of the cited extracted source (relative to artifact-store root).
    pub source: PathBuf,
    /// Inclusive `(start, end)` line range within the source.
    pub line_range: (u32, u32),
    /// Exact verbatim quote, before NFC + whitespace normalisation.
    pub quote: String,
    /// SHA-256 hex of NFC + whitespace-normalised `quote`.
    pub quote_hash: QuoteHash,
}

// ---------------------------------------------------------------------------
// AssumptionTag
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssumptionTag {
    /// Non-empty human owner of record (FR-031).
    pub owner: String,
    /// Why this assumption is plausible.
    pub rationale: String,
    /// Treated as `Rejected` on next gate eval if past (FR-030).
    pub expires_at: DateTime<Utc>,
    /// When the assumption was tagged. Default 30 days; max 90 from this.
    pub tagged_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// CandidatePromotion -- recorded when a citation arrives that *would* back
// an `Assumption`. Operator must approve; the validator never auto-promotes.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidatePromotion {
    pub citation: Citation,
    pub pending_operator_review: bool,
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    pub id: ClaimId,
    pub kind: ClaimKind,
    /// Phase-1 stage that minted the claim (1 for `s1_business_requirements`).
    pub stage: u8,
    pub minted_at: DateTime<Utc>,
    /// Verbatim claim text as emitted by the minter.
    pub text: String,
    pub anchor_hash: AnchorHash,
    /// Wire-format field name: `provenanceMode`. The discriminator inside
    /// the nested object is named `mode` (Zod `discriminatedUnion("mode", ...)`).
    /// The TS mirror MUST keep this nested -- flattening would drop the
    /// `provenanceMode` field name and break field-level parity.
    pub provenance_mode: ProvenanceMode,
    pub citations: Vec<Citation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assumption: Option<AssumptionTag>,
    /// Whether the validator detected an external-entity reference in `text`.
    pub names_external_entity: bool,
    /// External-entity surface forms detected in `text` (for the Stage 4/5
    /// cascade's substring scan).
    pub extracted_entity_candidates: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_promotion: Option<CandidatePromotion>,
}

// ---------------------------------------------------------------------------
// AssumptionManifestEntry / PendingPromotionEntry -- Phase 5 cross-stage
// cascade contracts (FR-010, FR-032, FR-035).
// ---------------------------------------------------------------------------

/// One row in `assumption-only-manifest.md`. Stage 4/5 cascade keys on
/// `anchor_hash`, so renaming the claim ID does not silently revive
/// emission for the same underlying concept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssumptionManifestEntry {
    pub id: ClaimId,
    pub kind: ClaimKind,
    pub anchor_hash: AnchorHash,
    pub owner: String,
    pub rationale: String,
    pub expires_at: DateTime<Utc>,
    /// External-entity surface forms. The cascade CI check (FR-034)
    /// greps generated artifacts for any of these strings; a hit
    /// outside `pending-promotion.md` FAILs the stage.
    pub extracted_entity_candidates: Vec<String>,
    /// Where the would-have-been-emitted artifacts get logged. Always
    /// `pending-promotion.md` (relative to the manifest file).
    pub pending_promotion_path: String,
}

/// One spec-only artifact that Stage 4 or Stage 5 skipped emitting
/// because its origin claim was tagged `Assumption` /
/// `AssumptionOrphaned`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingEmission {
    /// 4 (Stage 4 -- DDL / data model) or 5 (Stage 5 -- UI / tests).
    pub stage: u8,
    /// `ddl_table` | `service_stub` | `ui_binding` | `test_fixture`.
    pub artifact_kind: String,
    /// Human placeholder describing what would be emitted on promotion.
    pub description: String,
}

/// One record in `pending-promotion.md` for a claim that survived as
/// `Assumption` / `AssumptionOrphaned`. Operators read this to know
/// what cascade work is parked behind the assumption.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPromotionEntry {
    pub claim_id: ClaimId,
    pub anchor_hash: AnchorHash,
    pub kind: ClaimKind,
    pub would_emit: Vec<PendingEmission>,
}

/// FR-035 audit payload for an `Assumption -> Derived` operator-approved
/// promotion. Phase 5 provides the contract type + payload builder; the
/// transition workflow itself lives in Phase 6 (desktop UI).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromotionAuditPayload {
    /// Always `factory.provenance_promoted`.
    pub action: String,
    pub claim_id: ClaimId,
    pub from_mode: ProvenanceMode,
    pub to_mode: ProvenanceMode,
    pub citation: Citation,
    /// Operator-of-record (workspace member id / email).
    pub actor: String,
}

/// Spec 121 §5.3 audit payload: `factory.assumption_skip_emitted`. One
/// row is written per artifact that Stage 4 / Stage 5 skipped because
/// its origin claim is `Assumption` or `AssumptionOrphaned` (FR-032,
/// FR-033). Reconstructs what was deferred so audit can show the full
/// cascade picture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssumptionSkipPayload {
    /// Always `factory.assumption_skip_emitted`.
    pub action: String,
    pub project: String,
    pub claim_id: ClaimId,
    pub anchor_hash: AnchorHash,
    /// 4 (Stage 4 -- DDL / data model) or 5 (Stage 5 -- UI / tests).
    pub stage: u8,
    /// `ddl_table` | `service_stub` | `ui_binding` | `test_fixture`.
    pub artifact_kind: String,
    /// Human description of what would have been emitted.
    pub description: String,
}

// ---------------------------------------------------------------------------
// IdRegistry -- persisted as id-registry.json; keyed by AnchorHash for
// regeneration stability (FR-009, FR-013, FR-014).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRegistryEntry {
    pub claim_id: ClaimId,
    pub anchor_hash: AnchorHash,
    pub kind: ClaimKind,
    pub first_minted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regenerated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdRegistry {
    /// AnchorHash → ClaimId; the stability map.
    pub anchors: BTreeMap<AnchorHash, ClaimId>,
    /// ClaimId → entry metadata.
    pub entries: BTreeMap<ClaimId, IdRegistryEntry>,
}

// ---------------------------------------------------------------------------
// anchor_hash -- FR-011 normalisation pipeline.
//
// Steps:
//   (a) lowercase
//   (b) Unicode NFC
//   (c) strip stop tokens {a, an, the, is, are, must, may, can, will, shall}
//   (d) tokenize (split on whitespace AND ASCII hyphens, drop empties)
//   (e) sort lexicographically + dedupe
//   (f) join with single spaces
//   (g) sha256 hex
//
// NFC is applied before tokenisation so that pre-composed and decomposed
// Unicode forms produce identical hashes.
// ---------------------------------------------------------------------------

/// Stop tokens stripped from the token stream during normalisation.
/// Order matches FR-011 (articles, then connectives/modals).
const ANCHOR_STOP_TOKENS: &[&str] = &[
    "a", "an", "the", "is", "are", "must", "may", "can", "will", "shall",
];

/// Canonical token bag for a piece of claim text. Shared by
/// [`anchor_hash`] (which sha256s the joined string) and the spec-122
/// Stage CD comparator (which computes Jaccard similarity over the
/// bag for FR-018 step 3 pairing). Exposing the helper guarantees the
/// hash and the similarity scorer can never disagree about
/// canonicalisation -- they read the same token list.
pub fn anchor_canonical_tokens(text: &str) -> Vec<String> {
    let lowered: String = text.to_lowercase();
    let nfc: String = lowered.nfc().collect();

    // Tokenize: split on whitespace and ASCII hyphens. Hyphenated compound
    // words (`registered-shelter-society`) split into their component tokens
    // so reword variants align after the sort+dedupe step.
    let mut tokens: Vec<String> = nfc
        .split(|c: char| c.is_whitespace() || c == '-')
        .map(|t| t.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|t| !t.is_empty())
        .filter(|t| !ANCHOR_STOP_TOKENS.contains(&t.as_str()))
        .collect();

    tokens.sort();
    tokens.dedup();
    tokens
}

/// Compute the anchor hash of a piece of claim text. See module-level docs
/// and FR-011 for the normalisation pipeline. Internally calls
/// [`anchor_canonical_tokens`] so the hash and the spec-122 Jaccard
/// similarity scorer share canonicalisation byte-for-byte.
///
/// Edge case: input that consists entirely of whitespace, punctuation, or
/// stop tokens reduces to zero tokens and hashes the empty string -- a
/// stable, real SHA-256 (`e3b0c4...`). Two such inputs collide. Real claim
/// text never reduces to pure stop tokens, so this is a theoretical
/// degenerate case rather than a fabrication-collision risk; the validator
/// (Phase 2+) refuses to admit zero-content claims at the gate.
pub fn anchor_hash(text: &str) -> AnchorHash {
    let tokens = anchor_canonical_tokens(text);
    let joined = tokens.join(" ");

    let mut hasher = Sha256::new();
    hasher.update(joined.as_bytes());
    let digest = hasher.finalize();

    AnchorHash(hex_lower(&digest))
}

/// Compute the quote hash per FR-019: NFC + collapsed-whitespace + sha256.
/// Collapses any run of Unicode whitespace into a single ASCII space and
/// trims leading/trailing whitespace before hashing.
pub fn quote_hash(quote: &str) -> QuoteHash {
    let nfc: String = quote.nfc().collect();
    let normalised = collapse_whitespace(&nfc);
    let mut hasher = Sha256::new();
    hasher.update(normalised.as_bytes());
    QuoteHash(hex_lower(&hasher.finalize()))
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Schema fingerprint -- emits the structural shape that
// tools/oap/schema-parity-check compares against the future TS Zod mirror.
// ---------------------------------------------------------------------------

/// Canonical structural fingerprint of the provenance schema as produced by
/// the Rust types above. The matching `tools/oap/schema-parity-check` will
/// compute the same shape from `provenancePolicy.ts` once the TS mirror
/// lands and will assert equality.
///
/// Field lists at every nesting level are emitted in alphabetical order so
/// the comparison is order-independent.
pub fn provenance_schema_fingerprint() -> Value {
    let citation = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "lineRange", "required": true, "type": {
                "kind": "tuple",
                "items": [{"kind": "int"}, {"kind": "int"}],
            }},
            {"name": "quote", "required": true, "type": {"kind": "string"}},
            {"name": "quoteHash", "required": true, "type": {"kind": "string"}},
            {"name": "source", "required": true, "type": {"kind": "string"}},
        ],
    });

    let assumption_tag = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "expiresAt", "required": true, "type": {"kind": "string"}},
            {"name": "owner", "required": true, "type": {"kind": "string"}},
            {"name": "rationale", "required": true, "type": {"kind": "string"}},
            {"name": "taggedAt", "required": true, "type": {"kind": "string"}},
        ],
    });

    let candidate_promotion = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "citation", "required": true, "type": citation},
            {"name": "pendingOperatorReview", "required": true, "type": {"kind": "boolean"}},
        ],
    });

    let provenance_mode = serde_json::json!({
        "kind": "discriminatedUnion",
        "discriminator": "mode",
        "variants": [
            {"tag": "assumption", "fields": []},
            {"tag": "assumptionOrphaned", "fields": []},
            {"tag": "derived", "fields": []},
            {"tag": "derivedWeak", "fields": []},
            {"tag": "rejected", "fields": [
                {"name": "reason", "required": true, "type": {"kind": "string"}},
            ]},
        ],
    });

    let claim_kind = serde_json::json!({
        "kind": "enum",
        "values": [
            "BR", "FS", "INT", "SN", "STK", "STREQ", "SWREQ",
            "SYSREQ", "TC", "UC", "USRREQ",
        ],
    });

    let claim = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "anchorHash", "required": true, "type": {"kind": "string"}},
            {"name": "assumption", "required": false, "type": assumption_tag.clone()},
            {"name": "candidatePromotion", "required": false, "type": candidate_promotion},
            {"name": "citations", "required": true, "type": {
                "kind": "array",
                "element": citation.clone(),
            }},
            {"name": "extractedEntityCandidates", "required": true, "type": {
                "kind": "array",
                "element": {"kind": "string"},
            }},
            {"name": "id", "required": true, "type": {"kind": "string"}},
            {"name": "kind", "required": true, "type": claim_kind.clone()},
            {"name": "mintedAt", "required": true, "type": {"kind": "string"}},
            {"name": "namesExternalEntity", "required": true, "type": {"kind": "boolean"}},
            {"name": "provenanceMode", "required": true, "type": provenance_mode.clone()},
            {"name": "stage", "required": true, "type": {"kind": "int"}},
            {"name": "text", "required": true, "type": {"kind": "string"}},
        ],
    });

    let id_registry_entry = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "anchorHash", "required": true, "type": {"kind": "string"}},
            {"name": "claimId", "required": true, "type": {"kind": "string"}},
            {"name": "firstMintedAt", "required": true, "type": {"kind": "string"}},
            {"name": "kind", "required": true, "type": claim_kind.clone()},
            {"name": "regeneratedAt", "required": false, "type": {"kind": "string"}},
        ],
    });

    let id_registry = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "anchors", "required": true, "type": {
                "kind": "map",
                "key": {"kind": "string"},
                "value": {"kind": "string"},
            }},
            {"name": "entries", "required": true, "type": {
                "kind": "map",
                "key": {"kind": "string"},
                "value": id_registry_entry,
            }},
        ],
    });

    serde_json::json!({
        "version": PROVENANCE_SCHEMA_VERSION,
        "claim": claim,
        "idRegistry": id_registry,
        "provenanceMode": provenance_mode,
        "claimKind": claim_kind,
        "citation": citation,
        "assumptionTag": assumption_tag,
        "candidatePromotion": candidate_promotion,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    // The OAP-side fingerprint-to-disk test (feeding `tools/oap/schema-parity-check`
    // against the stagecraft TS mirror) is dropped in tenant-tail: there is no TS
    // mirror here, and a test that writes into the committed tree as a side effect
    // is undesirable. The pure fingerprint + drift tests are kept.

    #[test]
    fn schema_version_is_1_0_0() {
        assert_eq!(PROVENANCE_SCHEMA_VERSION, "1.0.0");
    }

    // ----- anchor_hash determinism + normalisation invariants -----

    #[test]
    fn anchor_hash_is_deterministic() {
        let h1 = anchor_hash("foo bar baz");
        let h2 = anchor_hash("foo bar baz");
        assert_eq!(h1, h2);
        assert_eq!(h1.0.len(), 64); // sha256 hex
    }

    #[test]
    fn anchor_hash_is_case_insensitive() {
        assert_eq!(anchor_hash("Foo Bar"), anchor_hash("foo bar"));
        assert_eq!(
            anchor_hash("PAYMENT REQUEST"),
            anchor_hash("payment request")
        );
    }

    #[test]
    fn anchor_hash_strips_every_article_and_modal() {
        // Strip set: a, an, the, is, are, must, may, can, will, shall.
        // Each of these tokens MUST disappear from the canonicalisation.
        // We assert both sides reduce to the bare content tokens -- the
        // "with stops" side adds each member of the strip list around
        // identical content tokens, and the "without stops" side has the
        // bare content tokens only. Equality witnesses every member of the
        // strip set being removed; a regression that adds or removes a
        // member of the strip list would break this test.
        let bare = anchor_hash("applicant payment shelter");
        let with_articles = anchor_hash("a applicant the payment an shelter");
        let with_modals = anchor_hash("applicant must may can will shall payment shelter");
        let with_copulas = anchor_hash("applicant is are payment shelter");
        assert_eq!(bare, with_articles);
        assert_eq!(bare, with_modals);
        assert_eq!(bare, with_copulas);
    }

    #[test]
    fn anchor_hash_does_not_strip_be() {
        // `be` is INTENTIONALLY not in the strip list -- it carries
        // requirement-bearing semantics ("X must be Y" → core token "be").
        // This test pins that behaviour so a future PR that adds `be` to
        // ANCHOR_STOP_TOKENS fails CI loudly rather than silently widening
        // the equivalence class and risking anchor collisions.
        let with_be = anchor_hash("applicant be registered");
        let without_be = anchor_hash("applicant registered");
        assert_ne!(with_be, without_be);
    }

    #[test]
    fn anchor_hash_is_token_order_invariant() {
        // FR-011 step (e): sort lexicographically.
        assert_eq!(
            anchor_hash("payment processing system"),
            anchor_hash("system processing payment"),
        );
    }

    #[test]
    fn anchor_hash_dedupes_repeated_tokens() {
        // FR-011 step (e): dedupe.
        assert_eq!(
            anchor_hash("payment payment payment"),
            anchor_hash("payment"),
        );
    }

    #[test]
    fn anchor_hash_splits_hyphenated_compounds() {
        // The two-line acceptance scenario for User Story 3 hinges on hyphen
        // splitting: `registered-shelter-society` must canonicalise to the
        // same token bag as `registered shelter society`.
        assert_eq!(
            anchor_hash("registered-shelter-society"),
            anchor_hash("registered shelter society"),
        );
    }

    #[test]
    fn anchor_hash_is_nfc_invariant() {
        // U+00E9 (precomposed é) and "e" + U+0301 (combining acute) must
        // produce the same hash after NFC normalisation.
        let precomposed = anchor_hash("café");
        let decomposed = anchor_hash("cafe\u{0301}");
        assert_eq!(precomposed, decomposed);
    }

    #[test]
    fn anchor_hash_property_reword_invariant() {
        // FR-011 invariant under the canonical reword fixture: article +
        // modal + ordering edits do NOT renumber the claim.
        //
        // Original: "The applicant must be a registered shelter society."
        // Reworded: "An applicant shall be the registered shelter society."
        //
        // Both reduce to the token bag {applicant, be, registered, shelter,
        // society} after the FR-011 pipeline.
        //
        // Note on the broader semantic-reword case from User Story 3
        // ("the applying organization is required to hold registered-shelter
        // -society status"): satisfying that example would require stemming
        // (applicant↔applying), modal-collapse (must↔required), and synonym
        // collapse (organization↔applicant), none of which FR-011 mandates.
        // This test asserts the algorithmic invariant FR-011 actually
        // guarantees; the broader semantic case is left as a future
        // refinement of the strip list / stemming layer.
        let original = anchor_hash("The applicant must be a registered shelter society.");
        let reworded = anchor_hash("An applicant shall be the registered shelter society.");
        assert_eq!(original, reworded);
    }

    #[test]
    fn anchor_hash_distinguishes_different_concepts() {
        assert_ne!(
            anchor_hash("payment processing system"),
            anchor_hash("identity provider service"),
        );
    }

    #[test]
    fn anchor_hash_empty_input_collapses_to_empty_hash() {
        // Pure-stop-token / whitespace / punctuation inputs reduce to zero
        // tokens and hash the empty string -- a stable degenerate case.
        // Real claim text never reduces this way; the validator refuses
        // zero-content claims at the gate (Phase 2+).
        let h_empty = anchor_hash("");
        let h_whitespace = anchor_hash("   \t\n  ");
        let h_punct = anchor_hash(",.;---...");
        let h_stops_only = anchor_hash("the a an must shall");
        assert_eq!(h_empty, h_whitespace);
        assert_eq!(h_empty, h_punct);
        assert_eq!(h_empty, h_stops_only);
        // SHA-256 of empty string.
        assert_eq!(
            h_empty.0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    // ----- quote_hash -----

    #[test]
    fn quote_hash_collapses_whitespace() {
        let a = quote_hash("hello   world");
        let b = quote_hash("hello world");
        let c = quote_hash("  hello\tworld\n");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn quote_hash_is_nfc_invariant() {
        let precomposed = quote_hash("café");
        let decomposed = quote_hash("cafe\u{0301}");
        assert_eq!(precomposed, decomposed);
    }

    // ----- serde round-trips -----

    fn sample_citation() -> Citation {
        let q = "applicant must be a registered shelter society";
        Citation {
            source: PathBuf::from("extracted/business-case.txt"),
            line_range: (21, 23),
            quote: q.to_string(),
            quote_hash: quote_hash(q),
        }
    }

    fn sample_claim() -> Claim {
        let text = "Applicant must be a registered shelter society";
        Claim {
            id: ClaimId("BR-007".into()),
            kind: ClaimKind::Br,
            stage: 1,
            minted_at: Utc.with_ymd_and_hms(2026, 4, 30, 0, 0, 0).unwrap(),
            text: text.into(),
            anchor_hash: anchor_hash(text),
            provenance_mode: ProvenanceMode::Derived,
            citations: vec![sample_citation()],
            assumption: None,
            names_external_entity: false,
            extracted_entity_candidates: vec![],
            candidate_promotion: None,
        }
    }

    #[test]
    fn claim_serde_round_trip() {
        let c = sample_claim();
        let j = serde_json::to_string(&c).unwrap();
        let back: Claim = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn claim_serde_emits_camel_case_field_names() {
        let c = sample_claim();
        let j = serde_json::to_value(&c).unwrap();
        assert!(j.get("anchorHash").is_some());
        assert!(j.get("namesExternalEntity").is_some());
        assert!(j.get("extractedEntityCandidates").is_some());
        assert!(j.get("mintedAt").is_some());
        // provenanceMode is nested (NOT flattened) so the field name is
        // preserved for the TS mirror's parity check.
        assert_eq!(
            j.get("provenanceMode")
                .and_then(|v| v.get("mode"))
                .and_then(|v| v.as_str()),
            Some("derived"),
        );
        // ClaimKind serialises as the uppercase prefix token.
        assert_eq!(j.get("kind").and_then(|v| v.as_str()), Some("BR"));
    }

    #[test]
    fn provenance_mode_rejected_round_trip() {
        let m = ProvenanceMode::Rejected {
            reason: "quote_hash_mismatch".into(),
        };
        let j = serde_json::to_value(&m).unwrap();
        assert_eq!(j.get("mode").and_then(|v| v.as_str()), Some("rejected"));
        assert_eq!(
            j.get("reason").and_then(|v| v.as_str()),
            Some("quote_hash_mismatch")
        );
        let back: ProvenanceMode = serde_json::from_value(j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn provenance_mode_assumption_orphaned_round_trip() {
        let m = ProvenanceMode::AssumptionOrphaned;
        let j = serde_json::to_value(&m).unwrap();
        assert_eq!(
            j.get("mode").and_then(|v| v.as_str()),
            Some("assumptionOrphaned")
        );
        let back: ProvenanceMode = serde_json::from_value(j).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn claim_kind_round_trips_all_variants() {
        let kinds = [
            ClaimKind::Br,
            ClaimKind::Stk,
            ClaimKind::Sn,
            ClaimKind::Uc,
            ClaimKind::Tc,
            ClaimKind::Int,
            ClaimKind::Fs,
            ClaimKind::Sysreq,
            ClaimKind::Streq,
            ClaimKind::Swreq,
            ClaimKind::Usrreq,
        ];
        for k in kinds {
            let j = serde_json::to_value(k).unwrap();
            assert_eq!(j.as_str(), Some(k.prefix()));
            let back: ClaimKind = serde_json::from_value(j).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn id_registry_serialises_in_sorted_key_order() {
        // BTreeMap must preserve sorted order for byte-deterministic output
        // (FR-002).
        let mut anchors: BTreeMap<AnchorHash, ClaimId> = BTreeMap::new();
        anchors.insert(AnchorHash("zzz".into()), ClaimId("BR-002".into()));
        anchors.insert(AnchorHash("aaa".into()), ClaimId("BR-001".into()));
        anchors.insert(AnchorHash("mmm".into()), ClaimId("BR-003".into()));

        let registry = IdRegistry {
            anchors,
            entries: BTreeMap::new(),
        };
        let j = serde_json::to_string(&registry).unwrap();

        // Find the position of each anchor key in the serialised string --
        // BTreeMap iterates in sorted order, so "aaa" appears before "mmm"
        // before "zzz".
        let pos_aaa = j.find("\"aaa\"").unwrap();
        let pos_mmm = j.find("\"mmm\"").unwrap();
        let pos_zzz = j.find("\"zzz\"").unwrap();
        assert!(pos_aaa < pos_mmm);
        assert!(pos_mmm < pos_zzz);
    }

    #[test]
    fn id_registry_round_trip() {
        let mut anchors = BTreeMap::new();
        anchors.insert(AnchorHash("abc".into()), ClaimId("BR-001".into()));
        let mut entries = BTreeMap::new();
        entries.insert(
            ClaimId("BR-001".into()),
            IdRegistryEntry {
                claim_id: ClaimId("BR-001".into()),
                anchor_hash: AnchorHash("abc".into()),
                kind: ClaimKind::Br,
                first_minted_at: Utc.with_ymd_and_hms(2026, 4, 30, 0, 0, 0).unwrap(),
                regenerated_at: None,
            },
        );
        let r = IdRegistry { anchors, entries };
        let j = serde_json::to_string(&r).unwrap();
        let back: IdRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    // ----- schema fingerprint -----

    #[test]
    fn fingerprint_carries_schema_version() {
        let fp = provenance_schema_fingerprint();
        assert_eq!(fp["version"], serde_json::json!(PROVENANCE_SCHEMA_VERSION));
    }

    #[test]
    fn fingerprint_drift_is_detected() {
        // Deliberate-drift regression: a synthetic perturbation must compare
        // not-equal. Mirrors knowledge.rs's drift_is_detected sanity check.
        let baseline = provenance_schema_fingerprint();
        let mut drifted = baseline.clone();
        drifted["claim"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "name": "syntheticDrift",
                "required": true,
                "type": {"kind": "string"},
            }));
        assert_ne!(baseline, drifted);
    }
}
