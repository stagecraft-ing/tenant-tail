//! Public validator API -- `validate()`, `audit()`, and a `catch_unwind`
//! panic guard that fails the gate closed (FR-005).
//!
//! `validate()` is pure and byte-deterministic: two invocations on the
//! same `(claims, corpus, allowlist, budget, now)` produce identical
//! `serde_json::to_string(&report)` output (FR-002, SC-010).
//!
//! `audit()` is the FR-036 retroactive entry point: it walks an existing
//! project directory for an authored BRD and an extraction corpus
//! (preferring spec-120 typed JSON, falling back to legacy `.txt`
//! files with synthesized page boundaries), runs the same validator
//! pipeline, and returns an `AuditReport`. The library function never
//! writes to disk; the binary entry point in `bin/audit.rs` is the only
//! thing that emits the markdown report.

use crate::provenance::allowlist::{
    Allowlist, CapitalizationHeuristic, ProjectContext, derive as derive_allowlist,
    detect_external_entities,
};
use crate::provenance::citation::{
    CitationResult, EntitySearchSummary, search_entity, verify_citation,
};
use crate::provenance::corpus::{Corpus, CorpusEntry, extracted_corpus_hash};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use tenant_tail_types::knowledge::{ExtractionOutput, Extractor};
use tenant_tail_types::provenance::{
    AnchorHash, Claim, ClaimId, ClaimKind, PROVENANCE_SCHEMA_VERSION, ProvenanceMode,
};
use tenant_tail_types::{AssumptionBudget, DateTime, Utc};

/// Schema version for the `ValidationReport` shape -- independent of
/// `PROVENANCE_SCHEMA_VERSION` (the wire schema for `Claim`/`ProvenanceMode`).
pub const VALIDATION_REPORT_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

/// Per-claim row in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimRecord {
    pub id: ClaimId,
    pub kind: ClaimKind,
    pub anchor_hash: AnchorHash,
    pub provenance_mode: ProvenanceMode,
    pub names_external_entity: bool,
    pub extracted_entity_candidates: Vec<String>,
    /// Per-entity corpus search summary (FR-021). Only populated when the
    /// claim was evaluated against the corpus (i.e. not duplicate-anchor
    /// rejected and not panic-rejected).
    pub entity_search: Vec<EntitySearchSummary>,
}

/// Summary counts emitted alongside the per-claim records.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationSummary {
    pub total: u32,
    pub derived_count: u32,
    pub derived_weak_count: u32,
    pub assumption_count: u32,
    pub assumption_orphaned_count: u32,
    pub rejected_count: u32,
    /// `used + new admissions`. The post-run budget consumption.
    pub assumption_slots_consumed: u32,
}

/// Top-level validator output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub schema_version: String,
    pub provenance_schema_version: String,
    pub validator_version: String,
    pub extracted_corpus_hash: String,
    pub allowlist_version_hash: String,
    pub claims: Vec<ClaimRecord>,
    pub summary: ValidationSummary,
    /// `Some` when a panic was caught. Stage gates inspect this to fail
    /// closed (FR-005). `None` on a healthy run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub panic_reason: Option<String>,
}

/// Where the audit found its corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CorpusSource {
    /// Spec-120 typed `ExtractionOutput` JSON files under
    /// `<project>/.artifacts/corpus/*.json`.
    TypedArtifactStore,
    /// Legacy `.txt` files synthesised into `ExtractionOutput`s (FR-039).
    LegacyTxt,
    /// Caller supplied an explicit `--corpus <path>` override.
    Override,
    /// No corpus was found.
    Empty,
}

/// FR-037 retroactive audit report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub validation: ValidationReport,
    /// FR-039: `true` when the corpus was synthesised from legacy `.txt`
    /// files; the audit's findings are approximate in that mode.
    pub synthesized_corpus: bool,
    pub brd_not_found: bool,
    pub corpus_empty: bool,
    /// Count of claim-shaped IDs found outside any `### KIND-NNN` header
    /// (e.g. inline in tables). V1 does not classify these; they are
    /// surfaced for operator review.
    pub unparsed_inline_count: u32,
    pub brd_path: Option<PathBuf>,
    pub corpus_source: CorpusSource,
}

// ---------------------------------------------------------------------------
// Public entry points (with panic guard)
// ---------------------------------------------------------------------------

/// FR-001: validate `claims` against `corpus` under `allowlist` + `budget`.
///
/// Pure. Byte-deterministic. On panic, returns a fail-closed report
/// whose `panic_reason` carries the original message and all claims are
/// recorded as `Rejected{reason: "qg13_validator_panic: <msg>"}`
/// (FR-005).
pub fn validate(
    claims: &[Claim],
    corpus: &Corpus,
    allowlist: &Allowlist,
    budget: &AssumptionBudget,
    now: DateTime<Utc>,
) -> ValidationReport {
    match catch_unwind(AssertUnwindSafe(|| {
        validate_inner(claims, corpus, allowlist, budget, now, false)
    })) {
        Ok(r) => r,
        Err(payload) => panic_report(claims, corpus, allowlist, &payload),
    }
}

/// FR-003 + FR-036: retroactive audit. Read-only at the library layer
/// (FR-038). The binary entry point writes the markdown report.
pub fn audit(project_dir: &Path) -> AuditReport {
    audit_with_options(project_dir, None)
}

/// FR-036 with an optional explicit corpus path override.
pub fn audit_with_options(project_dir: &Path, corpus_override: Option<&Path>) -> AuditReport {
    match catch_unwind(AssertUnwindSafe(|| {
        audit_inner(project_dir, corpus_override)
    })) {
        Ok(r) => r,
        Err(payload) => AuditReport {
            validation: panic_report(&[], &Corpus::default(), &empty_allowlist(), &payload),
            synthesized_corpus: false,
            brd_not_found: false,
            corpus_empty: true,
            unparsed_inline_count: 0,
            brd_path: None,
            corpus_source: CorpusSource::Empty,
        },
    }
}

// ---------------------------------------------------------------------------
// validate_inner -- the algorithm
// ---------------------------------------------------------------------------

fn validate_inner(
    claims: &[Claim],
    corpus: &Corpus,
    allowlist: &Allowlist,
    budget: &AssumptionBudget,
    now: DateTime<Utc>,
    inject_panic: bool,
) -> ValidationReport {
    if inject_panic {
        panic!("test injection: validator panic guard exercise");
    }

    let plausibility = CapitalizationHeuristic;

    // Step 1: anchor-hash collisions FAIL Stage 1 (User Story 3 acceptance #4).
    // Both (or all) claims sharing an anchor are rejected -- the validator
    // does NOT pick a winner.
    let mut anchor_counts: BTreeMap<&AnchorHash, u32> = BTreeMap::new();
    for c in claims {
        *anchor_counts.entry(&c.anchor_hash).or_insert(0) += 1;
    }
    let collisions: BTreeSet<&AnchorHash> = anchor_counts
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(a, _)| *a)
        .collect();

    // Step 2: per-claim classification.
    let mut records: Vec<ClaimRecord> = Vec::with_capacity(claims.len());
    let mut new_assumption_slots: u32 = 0;

    for claim in claims {
        // Detect external entities up-front so the report has the
        // `extracted_entity_candidates` field populated even when the
        // claim is rejected for a different reason.
        let entity_candidates: Vec<String> =
            detect_external_entities(&claim.text, allowlist, &plausibility);
        let names_external_entity = !entity_candidates.is_empty();

        // Step 1 result: anchor collision overrides everything else.
        if collisions.contains(&claim.anchor_hash) {
            records.push(ClaimRecord {
                id: claim.id.clone(),
                kind: claim.kind,
                anchor_hash: claim.anchor_hash.clone(),
                provenance_mode: ProvenanceMode::Rejected {
                    reason: "duplicate_anchor".into(),
                },
                names_external_entity,
                extracted_entity_candidates: entity_candidates,
                entity_search: vec![],
            });
            continue;
        }

        // Build per-entity search summary regardless of citation status --
        // operators want the "what did we look for, where, how many hits"
        // record (FR-021).
        let mut entity_search: Vec<EntitySearchSummary> = Vec::new();
        let mut total_hits: u32 = 0;
        if names_external_entity {
            for entity in &entity_candidates {
                let summaries = search_entity(corpus, entity);
                for s in summaries {
                    total_hits += s.hit_count;
                    entity_search.push(s);
                }
            }
            entity_search.sort_by(|a, b| a.source.cmp(&b.source));
        }

        // Branch: tagged ASSUMPTION takes precedence over citation walk.
        if let Some(tag) = &claim.assumption {
            if tag.expires_at < now {
                records.push(ClaimRecord {
                    id: claim.id.clone(),
                    kind: claim.kind,
                    anchor_hash: claim.anchor_hash.clone(),
                    provenance_mode: ProvenanceMode::Rejected {
                        reason: "assumption_expired".into(),
                    },
                    names_external_entity,
                    extracted_entity_candidates: entity_candidates,
                    entity_search,
                });
                continue;
            }
            if budget.used + new_assumption_slots >= budget.cap {
                records.push(ClaimRecord {
                    id: claim.id.clone(),
                    kind: claim.kind,
                    anchor_hash: claim.anchor_hash.clone(),
                    provenance_mode: ProvenanceMode::Rejected {
                        reason: "assumption_budget_exceeded".into(),
                    },
                    names_external_entity,
                    extracted_entity_candidates: entity_candidates,
                    entity_search,
                });
                continue;
            }
            new_assumption_slots += 1;
            records.push(ClaimRecord {
                id: claim.id.clone(),
                kind: claim.kind,
                anchor_hash: claim.anchor_hash.clone(),
                provenance_mode: ProvenanceMode::Assumption,
                names_external_entity,
                extracted_entity_candidates: entity_candidates,
                entity_search,
            });
            continue;
        }

        // Untagged claim with NO external entity → admit as Derived even
        // without citations (purely internal claim per §4 Edge Cases).
        if !names_external_entity {
            records.push(ClaimRecord {
                id: claim.id.clone(),
                kind: claim.kind,
                anchor_hash: claim.anchor_hash.clone(),
                provenance_mode: ProvenanceMode::Derived,
                names_external_entity: false,
                extracted_entity_candidates: vec![],
                entity_search: vec![],
            });
            continue;
        }

        // Untagged claim WITH external entity:
        //   - if no citations declared → if any corpus hits exist for any
        //     candidate entity, classify as DerivedWeak (operator should
        //     supply explicit Citation); otherwise Reject;
        //   - if citations declared → verify each, classifying as
        //     AssumptionOrphaned on quote_hash drift, Rejected on forge,
        //     Derived on clean verify.
        if claim.citations.is_empty() {
            if total_hits == 0 {
                records.push(ClaimRecord {
                    id: claim.id.clone(),
                    kind: claim.kind,
                    anchor_hash: claim.anchor_hash.clone(),
                    provenance_mode: ProvenanceMode::Rejected {
                        reason: "no_citation_for_external_entity".into(),
                    },
                    names_external_entity: true,
                    extracted_entity_candidates: entity_candidates,
                    entity_search,
                });
                continue;
            }
            // Hits exist but the operator did not pick one -- keep the
            // claim out of Stage 4/5 emission until a citation is bound.
            records.push(ClaimRecord {
                id: claim.id.clone(),
                kind: claim.kind,
                anchor_hash: claim.anchor_hash.clone(),
                provenance_mode: ProvenanceMode::Rejected {
                    reason: "citation_unbound".into(),
                },
                names_external_entity: true,
                extracted_entity_candidates: entity_candidates,
                entity_search,
            });
            continue;
        }

        // Verify every declared citation. Order is left-to-right so the
        // first failure determines the classification (deterministic).
        //
        // FR-020: a citation whose declared `quoteHash` does not match the
        // actual content at the cited `lineRange` MUST be Rejected with
        // `quote_hash_mismatch`. This catches BOTH stale citations and
        // forged ones at this verify-time check; the spec is explicit
        // that we do NOT downgrade silently.
        //
        // The §4 User Story 5 / FR-022 drift path that produces
        // AssumptionOrphaned operates differently: it triggers on
        // `extractedCorpusHash` change between runs, attempts to find the
        // quote ELSEWHERE in the new corpus, and only orphans when the
        // quote is genuinely absent. That belongs to a future drift
        // operation (separate from `validate()`'s primary job here).
        let mut verdict: Option<ProvenanceMode> = None;
        for cit in &claim.citations {
            match verify_citation(corpus, cit) {
                CitationResult::Matched => {
                    verdict = Some(ProvenanceMode::Derived);
                    // Continue verifying -- ALL must match for a clean Derived.
                }
                CitationResult::HashMismatch { .. } => {
                    verdict = Some(ProvenanceMode::Rejected {
                        reason: "quote_hash_mismatch".into(),
                    });
                    break;
                }
                CitationResult::SourceNotFound => {
                    verdict = Some(ProvenanceMode::Rejected {
                        reason: "citation_source_invalid".into(),
                    });
                    break;
                }
                CitationResult::LineRangeOutOfBounds { .. } => {
                    verdict = Some(ProvenanceMode::Rejected {
                        reason: "citation_source_invalid".into(),
                    });
                    break;
                }
            }
        }
        let mode = verdict.unwrap_or(ProvenanceMode::Rejected {
            reason: "no_citation_for_external_entity".into(),
        });

        records.push(ClaimRecord {
            id: claim.id.clone(),
            kind: claim.kind,
            anchor_hash: claim.anchor_hash.clone(),
            provenance_mode: mode,
            names_external_entity: true,
            extracted_entity_candidates: entity_candidates,
            entity_search,
        });
    }

    let summary = summarise(&records, budget.used + new_assumption_slots);
    ValidationReport {
        schema_version: VALIDATION_REPORT_VERSION.into(),
        provenance_schema_version: PROVENANCE_SCHEMA_VERSION.into(),
        validator_version: env!("CARGO_PKG_VERSION").into(),
        extracted_corpus_hash: extracted_corpus_hash(corpus),
        allowlist_version_hash: allowlist.version_hash.clone(),
        claims: records,
        summary,
        panic_reason: None,
    }
}

fn summarise(records: &[ClaimRecord], slots_consumed: u32) -> ValidationSummary {
    // The `AssumptionOrphaned` arm is intentionally retained here:
    // `validate()` itself never produces this mode (FR-020 routes
    // HashMismatch to a hard reject), but the FR-022 drift workflow --
    // when it lands as a future operation -- will produce it, and the
    // arm is needed for an exhaustive match against `ProvenanceMode`.
    // TODO(FR-022): add a drift-detection integration test once the
    // corpus-hash-change workflow is implemented.
    let mut s = ValidationSummary {
        total: records.len() as u32,
        assumption_slots_consumed: slots_consumed,
        ..Default::default()
    };
    for r in records {
        match &r.provenance_mode {
            ProvenanceMode::Derived => s.derived_count += 1,
            ProvenanceMode::DerivedWeak => s.derived_weak_count += 1,
            ProvenanceMode::Assumption => s.assumption_count += 1,
            ProvenanceMode::AssumptionOrphaned => s.assumption_orphaned_count += 1,
            ProvenanceMode::Rejected { .. } => s.rejected_count += 1,
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Panic guard helpers
// ---------------------------------------------------------------------------

fn empty_allowlist() -> Allowlist {
    derive_allowlist(&ProjectContext::default())
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn panic_report(
    claims: &[Claim],
    corpus: &Corpus,
    allowlist: &Allowlist,
    payload: &Box<dyn std::any::Any + Send>,
) -> ValidationReport {
    let msg = panic_message(payload);
    let reason = format!("qg13_validator_panic: {msg}");
    let claims_out: Vec<ClaimRecord> = if claims.is_empty() {
        // No input claims -- emit one synthetic record so consumers see a
        // non-empty rejected set rather than a confusing "0 claims, 0
        // rejections" report.
        vec![ClaimRecord {
            id: ClaimId("VALIDATOR-PANIC".into()),
            kind: ClaimKind::Br,
            anchor_hash: AnchorHash(String::new()),
            provenance_mode: ProvenanceMode::Rejected {
                reason: reason.clone(),
            },
            names_external_entity: false,
            extracted_entity_candidates: vec![],
            entity_search: vec![],
        }]
    } else {
        claims
            .iter()
            .map(|c| ClaimRecord {
                id: c.id.clone(),
                kind: c.kind,
                anchor_hash: c.anchor_hash.clone(),
                provenance_mode: ProvenanceMode::Rejected {
                    reason: reason.clone(),
                },
                names_external_entity: false,
                extracted_entity_candidates: vec![],
                entity_search: vec![],
            })
            .collect()
    };
    let summary = ValidationSummary {
        total: claims_out.len() as u32,
        rejected_count: claims_out.len() as u32,
        ..Default::default()
    };
    ValidationReport {
        schema_version: VALIDATION_REPORT_VERSION.into(),
        provenance_schema_version: PROVENANCE_SCHEMA_VERSION.into(),
        validator_version: env!("CARGO_PKG_VERSION").into(),
        extracted_corpus_hash: extracted_corpus_hash(corpus),
        allowlist_version_hash: allowlist.version_hash.clone(),
        claims: claims_out,
        summary,
        panic_reason: Some(msg),
    }
}

// ---------------------------------------------------------------------------
// audit_inner -- read-only retroactive audit (FR-036 to FR-039)
// ---------------------------------------------------------------------------

fn audit_inner(project_dir: &Path, corpus_override: Option<&Path>) -> AuditReport {
    // Step 1: locate the BRD.
    let (brd_path, brd_text) = match find_brd(project_dir) {
        Some(p) => {
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            (Some(p), text)
        }
        None => (None, String::new()),
    };
    let brd_not_found = brd_path.is_none();

    let parsed = parse_brd_claims(&brd_text);
    let unparsed_inline_count = parsed.unparsed_inline_count;
    let claims: Vec<Claim> = parsed.claims;

    // Step 2: load the corpus.
    let (corpus, corpus_source) = load_corpus(project_dir, corpus_override);
    let synthesized_corpus = matches!(corpus_source, CorpusSource::LegacyTxt);
    let corpus_empty = corpus.is_empty();

    // Step 3: derive allowlist from project context.
    let project_slug = project_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let project_name = project_slug.replace('-', " ");
    let corpus_outputs: Vec<ExtractionOutput> =
        corpus.entries().iter().map(|e| e.output.clone()).collect();
    let ctx = ProjectContext {
        corpus: &corpus_outputs,
        project_name: &project_name,
        project_slug: &project_slug,
        workspace_name: "",
        entity_model_yaml: None,
        charter_vocabulary: None,
        capitalized_token_frequency_threshold: 1,
    };
    let allowlist = derive_allowlist(&ctx);
    let budget = AssumptionBudget::default();
    let now = tenant_tail_types::now_utc();

    let validation = validate(&claims, &corpus, &allowlist, &budget, now);

    AuditReport {
        validation,
        synthesized_corpus,
        brd_not_found,
        corpus_empty,
        unparsed_inline_count,
        brd_path,
        corpus_source,
    }
}

// ---------------------------------------------------------------------------
// BRD parser (minimal V1 grammar)
// ---------------------------------------------------------------------------

/// Result of parsing a BRD markdown file.
pub(crate) struct BrdParseResult {
    pub claims: Vec<Claim>,
    pub unparsed_inline_count: u32,
}

/// Parse claim records from a BRD markdown string.
///
/// Grammar:
///   - A `### <KIND>-<NNN>` heading anywhere on a line (after optional
///     whitespace, leading numbering like `3.1`, and optional trailing
///     `:` + descriptive text) opens a new claim block.
///   - All non-header lines until the next `###`, `##`, or `#` heading
///     are concatenated as the claim's text.
///   - `KIND` ∈ {STK, INT, BR, SN, UC, TC, FS, SYSREQ, STREQ, SWREQ, USRREQ}.
///   - Inline `KIND-NNN` references that are not the entire heading
///     (e.g. in tables, prose) are counted in `unparsed_inline_count` for
///     operator visibility but not classified as claims.
///
/// V1 out-of-scope: YAML frontmatter tables, claims inside code fences.
pub(crate) fn parse_brd_claims(brd: &str) -> BrdParseResult {
    let mut claims: Vec<Claim> = Vec::new();
    let mut unparsed_inline: u32 = 0;
    let mut current: Option<(ClaimId, ClaimKind, String)> = None;
    let mut body: Vec<&str> = Vec::new();

    for line in brd.lines() {
        let trimmed = line.trim_start();
        let is_h3 = trimmed.starts_with("### ");
        let is_h2_or_h1 = trimmed.starts_with("## ") || trimmed.starts_with("# ");

        if is_h3 {
            // Close any in-progress claim.
            if let Some((id, kind, text_so_far)) = current.take() {
                let body_joined = body.join("\n").trim().to_string();
                let combined = format!("{} {}", text_so_far, body_joined)
                    .trim()
                    .to_string();
                claims.push(synthesise_claim(id, kind, combined));
                body.clear();
            }
            if let Some((id, kind, headline)) = parse_h3_claim_id(trimmed) {
                current = Some((id, kind, headline));
            } else {
                // Non-claim h3: count any inline KIND-NNN references on
                // the heading line.
                unparsed_inline += count_inline_claim_refs(trimmed);
            }
            continue;
        }

        if is_h2_or_h1 {
            // Close any open claim and stop accumulating.
            if let Some((id, kind, text_so_far)) = current.take() {
                let body_joined = body.join("\n").trim().to_string();
                let combined = format!("{} {}", text_so_far, body_joined)
                    .trim()
                    .to_string();
                claims.push(synthesise_claim(id, kind, combined));
                body.clear();
            }
            unparsed_inline += count_inline_claim_refs(trimmed);
            continue;
        }

        // Non-heading line.
        if current.is_some() {
            body.push(line);
        } else {
            unparsed_inline += count_inline_claim_refs(line);
        }
    }
    if let Some((id, kind, text_so_far)) = current.take() {
        let body_joined = body.join("\n").trim().to_string();
        let combined = format!("{} {}", text_so_far, body_joined)
            .trim()
            .to_string();
        claims.push(synthesise_claim(id, kind, combined));
    }

    BrdParseResult {
        claims,
        unparsed_inline_count: unparsed_inline,
    }
}

/// Extract a `(ClaimId, ClaimKind, descriptive_text)` from an `### ...`
/// heading line. Returns `None` if no recognised KIND-NNN token is in
/// the heading. Trailing colon + description (if any) is returned as
/// `descriptive_text` so it can be combined with the body.
fn parse_h3_claim_id(line: &str) -> Option<(ClaimId, ClaimKind, String)> {
    let after_hashes = line.trim_start_matches('#').trim_start();
    // Walk word-by-word; the first KIND-NNN-shaped token is the claim ID.
    for (i, word) in after_hashes.split_whitespace().enumerate() {
        let cleaned = word.trim_end_matches([':', '.']);
        if let Some((kind, _)) = parse_kind_nnn(cleaned) {
            // descriptive_text = everything after this word in the heading.
            let mut after: Vec<&str> = after_hashes.split_whitespace().skip(i + 1).collect();
            // Strip leading colon if the descriptive text starts with one.
            if let Some(first) = after.first().copied()
                && first == ":"
            {
                after.remove(0);
            }
            let descriptive = after.join(" ").trim_start_matches(':').trim().to_string();
            return Some((ClaimId(cleaned.to_string()), kind, descriptive));
        }
    }
    None
}

fn parse_kind_nnn(s: &str) -> Option<(ClaimKind, u32)> {
    let dash = s.find('-')?;
    let prefix = &s[..dash];
    let number_part = &s[dash + 1..];
    let kind = ClaimKind::from_prefix(prefix)?;
    let n: u32 = number_part.parse().ok()?;
    Some((kind, n))
}

fn count_inline_claim_refs(s: &str) -> u32 {
    // Count occurrences of any KIND-NNN-looking token on this line.
    let mut count: u32 = 0;
    for word in s.split(|c: char| !c.is_alphanumeric() && c != '-') {
        if parse_kind_nnn(word).is_some() {
            count += 1;
        }
    }
    count
}

fn synthesise_claim(id: ClaimId, kind: ClaimKind, text: String) -> Claim {
    // FR-014 (atomic ID counter for next-free <KIND>-<NNN>) is deferred
    // to Phase 4 (gate machinery). The audit path reads claim IDs from
    // existing BRD headers so no new IDs are minted here; the counter
    // applies when the live Stage 1 gate mints fresh claims via the
    // id-registry.
    //
    // Determinism note: `minted_at` uses wall-clock time and so this
    // Claim is NOT byte-stable across runs. That is fine -- `ClaimRecord`
    // (the report's per-claim shape) does NOT surface `minted_at`, so
    // `ValidationReport`'s serialised bytes remain deterministic per
    // FR-002 / SC-010. Adding `minted_at` to `ClaimRecord` would break
    // SC-010 in audit mode.
    let anchor = tenant_tail_types::anchor_hash(&text);
    Claim {
        id,
        kind,
        stage: 1,
        minted_at: tenant_tail_types::now_utc(),
        text,
        anchor_hash: anchor,
        provenance_mode: ProvenanceMode::Derived,
        citations: vec![],
        assumption: None,
        names_external_entity: false,
        extracted_entity_candidates: vec![],
        candidate_promotion: None,
    }
}

// Helper on ClaimKind to parse a heading prefix back to the enum.
trait ClaimKindFromPrefix {
    fn from_prefix(s: &str) -> Option<ClaimKind>;
}

impl ClaimKindFromPrefix for ClaimKind {
    fn from_prefix(s: &str) -> Option<ClaimKind> {
        Some(match s {
            "BR" => ClaimKind::Br,
            "STK" => ClaimKind::Stk,
            "SN" => ClaimKind::Sn,
            "UC" => ClaimKind::Uc,
            "TC" => ClaimKind::Tc,
            "INT" => ClaimKind::Int,
            "FS" => ClaimKind::Fs,
            "SYSREQ" => ClaimKind::Sysreq,
            "STREQ" => ClaimKind::Streq,
            "SWREQ" => ClaimKind::Swreq,
            "USRREQ" => ClaimKind::Usrreq,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Corpus loaders (typed > legacy txt > empty)
// ---------------------------------------------------------------------------

fn find_brd(project_dir: &Path) -> Option<PathBuf> {
    let primary = project_dir.join("requirements/business-requirements-document.md");
    if primary.exists() {
        return Some(primary);
    }
    let req_dir = project_dir.join("requirements");
    if !req_dir.is_dir() {
        return None;
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&req_dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("md"))
        .collect();
    entries.sort();
    entries
        .into_iter()
        .find(|path| file_starts_with_brd_heading(path))
}

fn file_starts_with_brd_heading(path: &Path) -> bool {
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in s.lines().take(50) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("---") {
            continue;
        }
        return trimmed
            .to_ascii_lowercase()
            .starts_with("# business requirements document");
    }
    false
}

fn load_corpus(project_dir: &Path, corpus_override: Option<&Path>) -> (Corpus, CorpusSource) {
    if let Some(p) = corpus_override {
        let entries = load_typed_extraction_dir(p).unwrap_or_default();
        return (Corpus::from_entries(entries), CorpusSource::Override);
    }

    let typed_dir = project_dir.join(".artifacts/corpus");
    if typed_dir.is_dir() {
        let entries = load_typed_extraction_dir(&typed_dir).unwrap_or_default();
        if !entries.is_empty() {
            return (
                Corpus::from_entries(entries),
                CorpusSource::TypedArtifactStore,
            );
        }
    }

    let legacy_dir = project_dir.join(".artifacts/extracted");
    if legacy_dir.is_dir() {
        let entries = load_legacy_txt_dir(&legacy_dir).unwrap_or_default();
        if !entries.is_empty() {
            return (Corpus::from_entries(entries), CorpusSource::LegacyTxt);
        }
    }

    (Corpus::default(), CorpusSource::Empty)
}

fn load_typed_extraction_dir(dir: &Path) -> Result<Vec<CorpusEntry>, std::io::Error> {
    let mut entries: Vec<CorpusEntry> = Vec::new();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    paths.sort();
    for path in paths {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Ok(output) = serde_json::from_slice::<ExtractionOutput>(&bytes) {
            entries.push(CorpusEntry {
                source_key: path.file_name().map(PathBuf::from).unwrap_or_default(),
                output,
            });
        }
    }
    Ok(entries)
}

fn load_legacy_txt_dir(dir: &Path) -> Result<Vec<CorpusEntry>, std::io::Error> {
    let mut entries: Vec<CorpusEntry> = Vec::new();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("txt"))
        .collect();
    paths.sort();
    for path in paths {
        let text = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        entries.push(CorpusEntry {
            source_key: path.file_name().map(PathBuf::from).unwrap_or_default(),
            output: synthesise_extraction(&text, &path),
        });
    }
    Ok(entries)
}

fn synthesise_extraction(text: &str, path: &Path) -> ExtractionOutput {
    // Heuristic page-boundary split: every 50 lines becomes a page so a
    // line range like (1024, 1026) still makes sense in terms of pages.
    const LINES_PER_PAGE: usize = 50;
    let lines: Vec<&str> = text.split('\n').collect();
    let mut pages = Vec::new();
    if lines.len() > LINES_PER_PAGE {
        for (i, chunk) in lines.chunks(LINES_PER_PAGE).enumerate() {
            pages.push(tenant_tail_types::knowledge::ExtractionPage {
                index: i as u64,
                text: chunk.join("\n"),
                bbox: None,
            });
        }
    }
    // We construct via a sorted BTreeMap then collect into the
    // `ExtractionOutput.metadata: HashMap` field. The HashMap's
    // iteration order is non-deterministic (per-process SipHash seed),
    // but it does NOT matter here: synthesized `metadata` is consumed
    // only by `search_entity`'s substring scan and is never iterated for
    // report output. The FR-002 byte-determinism guarantee binds to
    // `ValidationReport` serialisation, which excludes this field.
    let mut sorted_meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sorted_meta.insert(
        "legacySource".into(),
        serde_json::Value::String(
            path.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default(),
        ),
    );
    sorted_meta.insert("synthesizedCorpus".into(), serde_json::Value::Bool(true));
    let metadata: std::collections::HashMap<String, serde_json::Value> =
        sorted_meta.into_iter().collect();
    ExtractionOutput {
        text: text.to_string(),
        pages: if pages.is_empty() { None } else { Some(pages) },
        language: None,
        outline: None,
        metadata,
        extractor: Extractor {
            kind: "legacy-txt-synthesized".into(),
            version: "0.1.0".into(),
            agent_run: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Markdown report renderer (FR-037)
// ---------------------------------------------------------------------------

/// Render `report` as the markdown body for
/// `requirements/audit/retroactive-provenance-report.md`.
pub fn render_audit_report(report: &AuditReport) -> String {
    use std::fmt::Write;
    let v = &report.validation;
    let total = v.summary.total.max(1);
    let health =
        100.0 * (v.summary.derived_count + v.summary.derived_weak_count) as f32 / total as f32;
    let mut out = String::new();

    let _ = writeln!(out, "# Retroactive Provenance Audit Report");
    let _ = writeln!(out);
    let _ = writeln!(out, "- **schemaVersion:** {}", v.schema_version);
    let _ = writeln!(
        out,
        "- **provenanceSchemaVersion:** {}",
        v.provenance_schema_version
    );
    let _ = writeln!(out, "- **validatorVersion:** {}", v.validator_version);
    let _ = writeln!(
        out,
        "- **synthesizedCorpus:** {}",
        report.synthesized_corpus
    );
    let _ = writeln!(out, "- **brdNotFound:** {}", report.brd_not_found);
    let _ = writeln!(out, "- **corpusEmpty:** {}", report.corpus_empty);
    let _ = writeln!(out, "- **corpusSource:** {:?}", report.corpus_source);
    let _ = writeln!(
        out,
        "- **unparsedInlineCount:** {}",
        report.unparsed_inline_count
    );
    let _ = writeln!(
        out,
        "- **extractedCorpusHash:** `{}`",
        v.extracted_corpus_hash
    );
    let _ = writeln!(
        out,
        "- **allowlistVersionHash:** `{}`",
        v.allowlist_version_hash
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Summary");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Mode | Count |");
    let _ = writeln!(out, "|------|------:|");
    let _ = writeln!(out, "| derived | {} |", v.summary.derived_count);
    let _ = writeln!(out, "| derivedWeak | {} |", v.summary.derived_weak_count);
    let _ = writeln!(out, "| assumption | {} |", v.summary.assumption_count);
    let _ = writeln!(
        out,
        "| assumptionOrphaned | {} |",
        v.summary.assumption_orphaned_count
    );
    let _ = writeln!(out, "| rejected | {} |", v.summary.rejected_count);
    let _ = writeln!(out, "| **total** | **{}** | ", v.summary.total);
    let _ = writeln!(out);
    let _ = writeln!(out, "**provenanceHealth:** {:.1}%", health);
    if let Some(panic_msg) = &v.panic_reason {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "> **⚠ Validator panic:** `{panic_msg}` -- gate failed closed (FR-005)."
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Findings");
    let _ = writeln!(out);
    for r in &v.claims {
        let _ = writeln!(out, "### {}", r.id);
        let _ = writeln!(out, "- mode: `{}`", mode_label(&r.provenance_mode));
        let _ = writeln!(out, "- kind: `{}`", r.kind.prefix());
        let _ = writeln!(out, "- anchorHash: `{}`", r.anchor_hash);
        let _ = writeln!(out, "- namesExternalEntity: {}", r.names_external_entity);
        if !r.extracted_entity_candidates.is_empty() {
            let _ = writeln!(
                out,
                "- entityCandidates: {}",
                r.extracted_entity_candidates.join(", ")
            );
        }
        if !r.entity_search.is_empty() {
            let _ = writeln!(out, "- corpusSearchSummary:");
            for s in &r.entity_search {
                let _ = writeln!(
                    out,
                    "  - `{}`: pagesSearched={}, hitCount={}",
                    s.source.display(),
                    s.pages_searched,
                    s.hit_count
                );
            }
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "## Suggested Next Actions");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- For each `rejected` claim: supply a verbatim citation against the corpus, downgrade to `assumption` with a named owner, OR remove the claim."
    );
    let _ = writeln!(
        out,
        "- For each `assumptionOrphaned` claim: re-cite against the new corpus span, OR confirm the underlying concept no longer holds."
    );
    if report.synthesized_corpus {
        let _ = writeln!(
            out,
            "- Re-run the audit against a typed (spec-120) corpus once available; this run synthesised pages from legacy `.txt` files (FR-039)."
        );
    }
    out
}

fn mode_label(m: &ProvenanceMode) -> String {
    match m {
        ProvenanceMode::Derived => "derived".into(),
        ProvenanceMode::DerivedWeak => "derivedWeak".into(),
        ProvenanceMode::Assumption => "assumption".into(),
        ProvenanceMode::AssumptionOrphaned => "assumptionOrphaned".into(),
        ProvenanceMode::Rejected { reason } => format!("rejected: {reason}"),
    }
}

// ---------------------------------------------------------------------------
// FR-005 panic-guard tests (unit, with #[cfg(test)] visibility into the
// inject_panic seam -- never exposed on the public surface).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod panic_guard_tests {
    use super::*;
    use chrono::TimeZone;
    use tenant_tail_types::provenance::{ClaimId, anchor_hash};

    fn allow() -> Allowlist {
        derive_allowlist(&ProjectContext::default())
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap()
    }

    fn one_claim() -> Claim {
        let text = "applicants must be registered";
        Claim {
            id: ClaimId("BR-001".into()),
            kind: ClaimKind::Br,
            stage: 1,
            minted_at: now(),
            text: text.into(),
            anchor_hash: anchor_hash(text),
            provenance_mode: ProvenanceMode::Derived,
            citations: vec![],
            assumption: None,
            names_external_entity: false,
            extracted_entity_candidates: vec![],
            candidate_promotion: None,
        }
    }

    /// Direct exercise of `validate_inner(..., inject_panic = true)`
    /// wrapped in `catch_unwind` -- same shape as `validate()` but with
    /// the test-only panic switch flipped. Confirms FR-005 gate fails
    /// closed: panic_reason is set, every input claim becomes Rejected
    /// with a `qg13_validator_panic:` reason.
    #[test]
    fn panic_in_validator_fails_gate_closed() {
        let claims = vec![one_claim()];
        let report = match catch_unwind(AssertUnwindSafe(|| {
            validate_inner(
                &claims,
                &Corpus::default(),
                &allow(),
                &AssumptionBudget::default(),
                now(),
                true,
            )
        })) {
            Ok(r) => r,
            Err(payload) => panic_report(&claims, &Corpus::default(), &allow(), &payload),
        };
        assert!(report.panic_reason.is_some());
        assert!(
            report
                .panic_reason
                .as_deref()
                .unwrap()
                .contains("test injection")
        );
        for r in &report.claims {
            match &r.provenance_mode {
                ProvenanceMode::Rejected { reason } => {
                    assert!(
                        reason.starts_with("qg13_validator_panic:"),
                        "panic guard rejection should carry qg13_validator_panic prefix; got {reason}",
                    );
                }
                other => panic!("expected every claim Rejected, got {other:?}"),
            }
        }
        assert_eq!(report.summary.rejected_count, 1);
        assert_eq!(report.summary.derived_count, 0);
    }

    /// When the input claim list is empty AND a panic occurs, the report
    /// still emits a synthetic VALIDATOR-PANIC row so consumers
    /// iterating `claims` see a non-empty failure surface.
    #[test]
    fn panic_with_empty_claim_list_emits_synthetic_row() {
        let claims: Vec<Claim> = vec![];
        let report = match catch_unwind(AssertUnwindSafe(|| {
            validate_inner(
                &claims,
                &Corpus::default(),
                &allow(),
                &AssumptionBudget::default(),
                now(),
                true,
            )
        })) {
            Ok(r) => r,
            Err(payload) => panic_report(&claims, &Corpus::default(), &allow(), &payload),
        };
        assert!(report.panic_reason.is_some());
        assert_eq!(report.claims.len(), 1);
        assert_eq!(report.claims[0].id.0, "VALIDATOR-PANIC");
    }
}
