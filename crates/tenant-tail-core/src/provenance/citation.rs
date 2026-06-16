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
//! `pages[].text` in the corpus for case-insensitive substring matches
//! of an entity surface form. Returns per-source hit summaries sorted
//! deterministically.

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

/// Search every corpus entry for case-insensitive substring matches of
/// `entity_text`. Walks both `ExtractionOutput.text` and `pages[].text`
/// (FR-021).
///
/// Returns one `EntitySearchSummary` per source where at least one hit
/// was found, sorted by `source` for deterministic output (FR-002).
pub fn search_entity(corpus: &Corpus, entity_text: &str) -> Vec<EntitySearchSummary> {
    let needle = entity_text.to_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }

    let mut results: Vec<EntitySearchSummary> = Vec::new();

    for entry in corpus.entries() {
        let mut hits: Vec<CitationHit> = Vec::new();

        // FR-021 says "every ExtractionOutput.text AND every pages[].text".
        // Spec 120 documents that for paginated outputs, top-level `text`
        // is the page-concatenation, so naively walking both sources
        // double-counts every hit. We walk pages[].text when present and
        // fall back to output.text otherwise -- covers both shapes
        // exactly once.
        let pages_searched: u32;
        if let Some(pages) = &entry.output.pages {
            pages_searched = pages.len() as u32;
            for page in pages {
                for (i, line) in page.text.split('\n').enumerate() {
                    if line.to_lowercase().contains(&needle) {
                        hits.push(CitationHit {
                            line_range: ((i + 1) as u32, (i + 1) as u32),
                            quote: line.to_string(),
                        });
                    }
                }
            }
        } else {
            pages_searched = 1;
            for (i, line) in entry.output.text.split('\n').enumerate() {
                if line.to_lowercase().contains(&needle) {
                    hits.push(CitationHit {
                        line_range: ((i + 1) as u32, (i + 1) as u32),
                        quote: line.to_string(),
                    });
                }
            }
        }

        if !hits.is_empty() {
            results.push(EntitySearchSummary {
                source: entry.source_key.clone(),
                pages_searched,
                hit_count: hits.len() as u32,
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
}
