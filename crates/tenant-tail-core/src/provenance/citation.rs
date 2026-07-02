//! Citation verification and entity search.
//!
//! `verify_citation` (FR-019, FR-020) checks that a `Citation`'s declared
//! `quote_hash` matches the actual content at its declared `line_range`
//! in the cited source. Matching is verbatim with NFC + whitespace
//! normalisation (FR-019). Stricter normalisation forms (NFKC, curly-vs-
//! straight quotes) are explicitly deferred to a future iteration per
//! spec §7 Open Decisions: V1 fails closed and requires re-citation.
//!
//! `search_entity` (FR-021) walks every `ExtractionOutput.text` and
//! `pages[].text` in the corpus for case-insensitive whole-word matches
//! of an entity surface form. Returns per-source hit summaries sorted
//! deterministically, with document-global line numbers.

use crate::provenance::corpus::Corpus;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tenant_tail_types::provenance::{Citation, QuoteHash, quote_hash};

/// Result of verifying one `Citation` against the corpus.
#[derive(Debug, Clone, PartialEq)]
pub enum CitationResult {
    /// The verbatim quote at `line_range` in `source` matches the declared
    /// `quote_hash`.
    Matched,
    /// The source was found but the declared `quote_hash` does not match
    /// the actual quote at the declared `line_range`. Catches stale and
    /// forged citations (FR-020).
    HashMismatch {
        expected: QuoteHash,
        actual: QuoteHash,
    },
    /// The declared `line_range` is outside the source's line count. The
    /// numbers are 1-based inclusive; `actual_line_count` is the number
    /// of lines in the source text after splitting on '\n'.
    LineRangeOutOfBounds {
        source: PathBuf,
        declared_range: (u32, u32),
        actual_line_count: u32,
    },
    /// The declared `Citation.source` does not match any `source_key` in
    /// the corpus.
    SourceNotFound,
}

/// Verify a single `Citation` against the corpus.
///
/// Steps (FR-019/FR-020):
///   1. Look up the corpus entry by `citation.source`.
///   2. Slice lines `[start..=end]` (1-based inclusive) from the entry.
///   3. Recompute `quote_hash` over the actual sliced text and compare to
///      the declared `citation.quote_hash`.
pub fn verify_citation(corpus: &Corpus, citation: &Citation) -> CitationResult {
    let entry = match corpus.get(&citation.source) {
        Some(e) => e,
        None => return CitationResult::SourceNotFound,
    };

    let (start, end) = citation.line_range;
    let source_text = entry.output.text.as_str();
    let lines: Vec<&str> = source_text.split('\n').collect();
    let line_count = lines.len() as u32;

    if start == 0 || end == 0 || start > end || end > line_count {
        return CitationResult::LineRangeOutOfBounds {
            source: citation.source.clone(),
            declared_range: (start, end),
            actual_line_count: line_count,
        };
    }

    let start_idx = (start - 1) as usize;
    let end_idx = end as usize;
    let actual_quote = lines[start_idx..end_idx].join("\n");
    let actual_hash = quote_hash(&actual_quote);

    if actual_hash == citation.quote_hash {
        CitationResult::Matched
    } else {
        CitationResult::HashMismatch {
            expected: citation.quote_hash.clone(),
            actual: actual_hash,
        }
    }
}

/// Return the verbatim source span (`[start..=end]`) a citation points at, or
/// `None` if the source or line range is invalid. This reads the ACTUAL corpus
/// content, independent of hash verification and independent of the
/// caller-declared `citation.quote` (which the producer controls). Callers use
/// it to confirm a citation substantiates what it claims to.
pub fn cited_span_text(corpus: &Corpus, citation: &Citation) -> Option<String> {
    let entry = corpus.get(&citation.source)?;
    let (start, end) = citation.line_range;
    let lines: Vec<&str> = entry.output.text.split('\n').collect();
    let line_count = lines.len() as u32;
    if start == 0 || end == 0 || start > end || end > line_count {
        return None;
    }
    Some(lines[(start - 1) as usize..end as usize].join("\n"))
}

/// True if `span` contains `entity` as a whole word (case-insensitive). Word
/// boundaries are Unicode-alphanumeric, so `ERP` does NOT match inside
/// `enterprise`. Used to confirm a cited span actually names the external
/// entity it is offered as evidence for (spec 121 FR-019/FR-020).
pub fn span_covers_entity(span: &str, entity: &str) -> bool {
    contains_word(&span.to_lowercase(), &entity.to_lowercase())
}

/// Case-insensitive whole-word containment. `haystack` and `needle` must both
/// already be lowercased by the caller. A match must be bounded on each side by
/// a non-alphanumeric char or a string edge, so substring-of-a-larger-word hits
/// (`erp` in `enterprise`, `it` in `commit`) do not count.
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    for (idx, matched) in haystack.match_indices(needle) {
        let before_ok = haystack[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_ok = haystack[idx + matched.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Upper bound on the number of `CitationHit`s (each cloning a line of source
/// text) retained per source. `hit_count` remains the true total; only the
/// stored `hits` sample is capped, bounding memory/JSON size against a crafted
/// corpus + claim set that would otherwise force superlinear allocation
/// (spec 121 FR-021, resource-exhaustion guard).
const MAX_HITS_PER_SOURCE: usize = 100;

/// Per-source hit summary returned by `search_entity` (FR-021).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitySearchSummary {
    pub source: PathBuf,
    pub pages_searched: u32,
    pub hit_count: u32,
    pub hits: Vec<CitationHit>,
}

/// One verbatim hit of an entity surface form in a source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationHit {
    /// 1-based inclusive line range where the hit was found.
    pub line_range: (u32, u32),
    /// The line contents containing the hit (without surrounding context).
    pub quote: String,
}

/// Search every corpus entry for case-insensitive whole-word matches of
/// `entity_text`. Walks both `ExtractionOutput.text` and `pages[].text`
/// (FR-021).
///
/// Reported `line_range`s are document-global (1-based into the source's
/// top-level `text`, which spec 120 defines as the page concatenation), so a
/// hit reported here round-trips as a `Citation` that [`verify_citation`] and
/// [`cited_span_text`] can re-resolve. Matching is whole-word (see
/// [`contains_word`]), not raw substring, so `ERP` no longer matches inside
/// `enterprise`.
///
/// Returns one `EntitySearchSummary` per source where at least one hit
/// was found, sorted by `source` for deterministic output (FR-002). The stored
/// `hits` sample is capped at [`MAX_HITS_PER_SOURCE`]; `hit_count` is the true
/// total.
pub fn search_entity(corpus: &Corpus, entity_text: &str) -> Vec<EntitySearchSummary> {
    let needle = entity_text.to_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }

    let mut results: Vec<EntitySearchSummary> = Vec::new();

    for entry in corpus.entries() {
        let mut hits: Vec<CitationHit> = Vec::new();
        let mut hit_count: u32 = 0;
        // Document-global line cursor (1-based). Incremented across pages so
        // the numbering matches `output.text` (the page concatenation), which
        // is exactly what citations index into.
        let mut global_line: u32 = 0;

        // FR-021 says "every ExtractionOutput.text AND every pages[].text".
        // Spec 120 documents that for paginated outputs, top-level `text`
        // is the page-concatenation, so naively walking both sources
        // double-counts every hit. We walk pages[].text when present and
        // fall back to output.text otherwise -- covers both shapes
        // exactly once.
        let pages_searched: u32;
        // Collect the source's lines once, in the same order `output.text`
        // concatenates them, then scan with a single document-global cursor.
        let lines: Vec<&str> = match &entry.output.pages {
            Some(pages) => {
                pages_searched = pages.len() as u32;
                pages.iter().flat_map(|p| p.text.split('\n')).collect()
            }
            None => {
                pages_searched = 1;
                entry.output.text.split('\n').collect()
            }
        };
        for line in lines {
            global_line += 1;
            if contains_word(&line.to_lowercase(), &needle) {
                hit_count += 1;
                if hits.len() < MAX_HITS_PER_SOURCE {
                    hits.push(CitationHit {
                        line_range: (global_line, global_line),
                        quote: line.to_string(),
                    });
                }
            }
        }

        if hit_count > 0 {
            results.push(EntitySearchSummary {
                source: entry.source_key.clone(),
                pages_searched,
                hit_count,
                hits,
            });
        }
    }

    // Determinism: sort by source key. Inner hits are already in
    // discovery order, which is line-ascending under split('\n').
    results.sort_by(|a, b| a.source.cmp(&b.source));
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::corpus::CorpusEntry;
    use std::collections::HashMap;
    use std::path::Path;
    use tenant_tail_types::knowledge::{ExtractionOutput, ExtractionPage, Extractor};
    use tenant_tail_types::provenance::quote_hash as compute_quote_hash;

    fn extraction_with_text(text: &str) -> ExtractionOutput {
        ExtractionOutput {
            text: text.to_string(),
            pages: None,
            language: Some("en".into()),
            outline: None,
            metadata: HashMap::new(),
            extractor: Extractor {
                kind: "deterministic-text".into(),
                version: "1.0.0".into(),
                agent_run: None,
            },
        }
    }

    fn extraction_with_pages(pages: &[&str]) -> ExtractionOutput {
        let combined = pages.join("\n");
        let page_objs: Vec<ExtractionPage> = pages
            .iter()
            .enumerate()
            .map(|(i, p)| ExtractionPage {
                index: i as u64,
                text: p.to_string(),
                bbox: None,
            })
            .collect();
        ExtractionOutput {
            text: combined,
            pages: Some(page_objs),
            language: Some("en".into()),
            outline: None,
            metadata: HashMap::new(),
            extractor: Extractor {
                kind: "deterministic-text".into(),
                version: "1.0.0".into(),
                agent_run: None,
            },
        }
    }

    fn corpus_with(entries: &[(&str, ExtractionOutput)]) -> Corpus {
        Corpus::from_entries(
            entries
                .iter()
                .map(|(k, o)| CorpusEntry {
                    source_key: PathBuf::from(*k),
                    output: o.clone(),
                })
                .collect(),
        )
    }

    fn citation(source: &str, line_range: (u32, u32), quote: &str, hash: QuoteHash) -> Citation {
        Citation {
            source: PathBuf::from(source),
            line_range,
            quote: quote.to_string(),
            quote_hash: hash,
        }
    }

    // ---------- verify_citation ----------

    #[test]
    fn verify_citation_matched() {
        let text = "line one\nline two\nline three";
        let c = corpus_with(&[("a.txt", extraction_with_text(text))]);
        let cit = citation("a.txt", (2, 2), "line two", compute_quote_hash("line two"));
        assert_eq!(verify_citation(&c, &cit), CitationResult::Matched);
    }

    #[test]
    fn verify_citation_matched_multi_line() {
        let text = "line one\nline two\nline three";
        let c = corpus_with(&[("a.txt", extraction_with_text(text))]);
        let span = "line one\nline two";
        let cit = citation("a.txt", (1, 2), span, compute_quote_hash(span));
        assert_eq!(verify_citation(&c, &cit), CitationResult::Matched);
    }

    #[test]
    fn verify_citation_hash_mismatch() {
        let text = "line one\nline two\nline three";
        let c = corpus_with(&[("a.txt", extraction_with_text(text))]);
        // Declares quote_hash for a different string.
        let cit = citation(
            "a.txt",
            (2, 2),
            "line two",
            compute_quote_hash("totally different"),
        );
        match verify_citation(&c, &cit) {
            CitationResult::HashMismatch { expected, actual } => {
                assert_ne!(expected, actual);
                assert_eq!(actual, compute_quote_hash("line two"));
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_citation_line_range_out_of_bounds() {
        let text = "only one line";
        let c = corpus_with(&[("a.txt", extraction_with_text(text))]);
        let cit = citation("a.txt", (5, 6), "anything", compute_quote_hash("anything"));
        match verify_citation(&c, &cit) {
            CitationResult::LineRangeOutOfBounds {
                declared_range,
                actual_line_count,
                source,
            } => {
                assert_eq!(declared_range, (5, 6));
                assert_eq!(actual_line_count, 1);
                assert_eq!(source, PathBuf::from("a.txt"));
            }
            other => panic!("expected LineRangeOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn verify_citation_zero_line_range_is_out_of_bounds() {
        // 1-based indexing: (0, 0) is invalid.
        let text = "line";
        let c = corpus_with(&[("a.txt", extraction_with_text(text))]);
        let cit = citation("a.txt", (0, 0), "line", compute_quote_hash("line"));
        assert!(matches!(
            verify_citation(&c, &cit),
            CitationResult::LineRangeOutOfBounds { .. }
        ));
    }

    #[test]
    fn verify_citation_inverted_range_is_out_of_bounds() {
        let text = "line one\nline two\nline three";
        let c = corpus_with(&[("a.txt", extraction_with_text(text))]);
        let cit = citation("a.txt", (3, 1), "anything", compute_quote_hash("anything"));
        assert!(matches!(
            verify_citation(&c, &cit),
            CitationResult::LineRangeOutOfBounds { .. }
        ));
    }

    #[test]
    fn verify_citation_source_not_found() {
        let c = corpus_with(&[("a.txt", extraction_with_text("hi"))]);
        let cit = citation("missing.txt", (1, 1), "hi", compute_quote_hash("hi"));
        assert_eq!(verify_citation(&c, &cit), CitationResult::SourceNotFound);
    }

    #[test]
    fn verify_citation_paginated_corpus() {
        // FR-021 mandates the verifier walks pages[].text. Citations point
        // at the top-level text path (which spec 120 always populates as
        // the page-concatenation), so this test ensures multi-page
        // corpora still match correctly.
        let pages = &["page zero text", "page one text"];
        let c = corpus_with(&[("p.txt", extraction_with_pages(pages))]);
        // Top-level text becomes "page zero text\npage one text".
        let cit = citation(
            "p.txt",
            (2, 2),
            "page one text",
            compute_quote_hash("page one text"),
        );
        assert_eq!(verify_citation(&c, &cit), CitationResult::Matched);
    }

    #[test]
    fn verify_citation_normalises_whitespace() {
        // FR-019: whitespace normalisation is part of quote_hash. A quote
        // declared with collapsed whitespace must verify against source
        // text that has runs of whitespace.
        let c = corpus_with(&[("a.txt", extraction_with_text("   spaced   \tquote   "))]);
        let cit = citation(
            "a.txt",
            (1, 1),
            "spaced quote",
            compute_quote_hash("spaced quote"),
        );
        assert_eq!(verify_citation(&c, &cit), CitationResult::Matched);
    }

    #[test]
    fn verify_citation_fails_closed_on_curly_quotes() {
        // Spec §7 Open Decisions: curly-vs-straight quote tolerance is
        // explicitly deferred. V1 fails closed. This test pins that
        // behaviour so a future implementer who adds NFKC widens the
        // quote_hash equivalence class deliberately, not by accident.
        let curly = "\u{201C}value\u{201D}"; // “value”
        let straight = "\"value\"";
        let c = corpus_with(&[("a.txt", extraction_with_text(curly))]);
        let cit = citation("a.txt", (1, 1), straight, compute_quote_hash(straight));
        assert!(matches!(
            verify_citation(&c, &cit),
            CitationResult::HashMismatch { .. }
        ));
    }

    // ---------- search_entity ----------

    #[test]
    fn search_entity_finds_case_insensitive_hits() {
        let c = corpus_with(&[(
            "a.txt",
            extraction_with_text("STK-13 references 1GX Oracle ERP."),
        )]);
        let r = search_entity(&c, "1gx");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].hit_count, 1);
    }

    #[test]
    fn search_entity_returns_no_results_when_absent() {
        let c = corpus_with(&[("a.txt", extraction_with_text("nothing here"))]);
        let r = search_entity(&c, "missing-vendor");
        assert!(r.is_empty());
    }

    #[test]
    fn search_entity_returns_sources_sorted() {
        let c = corpus_with(&[
            ("zebra.txt", extraction_with_text("vendor here")),
            ("alpha.txt", extraction_with_text("vendor here")),
            ("middle.txt", extraction_with_text("vendor here")),
        ]);
        let r = search_entity(&c, "vendor");
        let sources: Vec<&Path> = r.iter().map(|s| s.source.as_path()).collect();
        assert_eq!(
            sources,
            vec![
                Path::new("alpha.txt"),
                Path::new("middle.txt"),
                Path::new("zebra.txt"),
            ],
        );
    }

    #[test]
    fn search_entity_walks_pages() {
        let pages = &["nothing in page 0", "vendor lives on page 1"];
        let c = corpus_with(&[("p.txt", extraction_with_pages(pages))]);
        let r = search_entity(&c, "vendor");
        assert!(!r.is_empty());
        assert!(r[0].hit_count >= 1);
    }

    #[test]
    fn search_entity_does_not_double_count_paginated_hits() {
        // Spec 120 makes ExtractionOutput.text the page concatenation.
        // A naive walker would find the same hit once via output.text
        // and again via pages[].text. The implementation walks one OR
        // the other, never both, so paginated entries with one hit per
        // page report exactly that -- not 2x.
        let pages = &["vendor on zero", "vendor on one"];
        let c = corpus_with(&[("p.txt", extraction_with_pages(pages))]);
        let r = search_entity(&c, "vendor");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].hit_count, 2);
        assert_eq!(r[0].pages_searched, 2);
    }

    #[test]
    fn search_entity_empty_needle_returns_empty() {
        let c = corpus_with(&[("a.txt", extraction_with_text("anything"))]);
        assert!(search_entity(&c, "").is_empty());
    }

    #[test]
    fn search_entity_matches_whole_words_only() {
        // "erp" must not match inside "enterprise".
        let c = corpus_with(&[("a.txt", extraction_with_text("the enterprise plan"))]);
        assert!(search_entity(&c, "erp").is_empty());
        // but a standalone occurrence does match.
        let c2 = corpus_with(&[("a.txt", extraction_with_text("uses ERP heavily"))]);
        assert_eq!(search_entity(&c2, "erp").len(), 1);
    }

    #[test]
    fn search_entity_reports_document_global_line_numbers() {
        // pages -> top-level text is "alpha\nbeta vendor gamma"; the hit is on
        // document-global line 2, and that line round-trips as a citation.
        let pages = &["alpha", "beta vendor gamma"];
        let c = corpus_with(&[("p.txt", extraction_with_pages(pages))]);
        let r = search_entity(&c, "vendor");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].hits[0].line_range, (2, 2));
        let cit = citation(
            "p.txt",
            (2, 2),
            "beta vendor gamma",
            compute_quote_hash("beta vendor gamma"),
        );
        assert_eq!(verify_citation(&c, &cit), CitationResult::Matched);
    }

    #[test]
    fn cited_span_text_reads_actual_source_not_declared_quote() {
        let c = corpus_with(&[("a.txt", extraction_with_text("line one\nline two"))]);
        let cit = citation(
            "a.txt",
            (2, 2),
            "A DIFFERENT DECLARED QUOTE",
            compute_quote_hash("line two"),
        );
        assert_eq!(cited_span_text(&c, &cit).as_deref(), Some("line two"));
    }

    #[test]
    fn span_covers_entity_is_whole_word() {
        assert!(span_covers_entity(
            "integrates with Zorptech today",
            "Zorptech"
        ));
        assert!(!span_covers_entity("a Zorptechnology thing", "Zorptech"));
    }
}
