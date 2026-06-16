//! In-memory view over the typed extraction corpus produced by spec 120.
//!
//! A `Corpus` holds the deserialised `ExtractionOutput` for every
//! knowledge object in a project bundle, keyed by a stable `source_key`
//! (the relative path used as `Citation.source`). The collection is
//! sorted by `source_key` at construction so iteration is deterministic.
//!
//! `extracted_corpus_hash` (FR-022) is sha256 over the newline-joined,
//! sorted source-key list. Per spec, the hash gates *whether* citation
//! verification re-runs -- it is over the file inventory, NOT individual
//! file contents. Content drift is caught by `verify_citation` on the
//! re-run.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tenant_tail_types::knowledge::ExtractionOutput;

/// A single knowledge object in the corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct CorpusEntry {
    /// Stable relative path used as the `Citation.source` key. Must be
    /// identical across runs so citations remain bound to their source.
    pub source_key: PathBuf,
    /// The deserialised typed extraction.
    pub output: ExtractionOutput,
}

/// In-memory view over all `ExtractionOutput` artifacts for one project
/// run. Built once; immutable.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Corpus {
    entries: Vec<CorpusEntry>,
}

impl Corpus {
    /// Build a `Corpus` from a list of entries. Entries are sorted by
    /// `source_key` lexicographically before being stored, regardless of
    /// the input order. This enforces FR-002 determinism at construction
    /// rather than relying on caller discipline.
    pub fn from_entries(mut entries: Vec<CorpusEntry>) -> Self {
        entries.sort_by(|a, b| a.source_key.cmp(&b.source_key));
        // Dedupe on source_key: if the caller accidentally passes two
        // entries with the same key, keep the first (stable sort already
        // preserved the relative order of duplicates).
        entries.dedup_by(|a, b| a.source_key == b.source_key);
        Corpus { entries }
    }

    /// Iterate entries in `source_key` lexicographic order.
    pub fn entries(&self) -> &[CorpusEntry] {
        &self.entries
    }

    /// Number of entries in the corpus.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the corpus is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an entry by its `source_key`.
    pub fn get(&self, source_key: &Path) -> Option<&CorpusEntry> {
        self.entries
            .iter()
            .find(|e| e.source_key.as_path() == source_key)
    }

    /// FR-022 inventory hash: sha256 of newline-joined sorted source keys.
    /// NOT a content hash -- drift in individual file contents must be
    /// caught by `verify_citation`, not by this hash.
    pub fn inventory_hash(&self) -> String {
        let mut hasher = Sha256::new();
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                hasher.update(b"\n");
            }
            hasher.update(e.source_key.to_string_lossy().as_bytes());
        }
        let digest = hasher.finalize();
        let mut out = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in digest {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
        out
    }
}

/// FR-022 free-function alias of `Corpus::inventory_hash` so callers can
/// import the spec-named symbol without needing `Corpus` in scope.
pub fn extracted_corpus_hash(corpus: &Corpus) -> String {
    corpus.inventory_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tenant_tail_types::knowledge::Extractor;

    fn extraction(text: &str) -> ExtractionOutput {
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

    fn entry(key: &str, text: &str) -> CorpusEntry {
        CorpusEntry {
            source_key: PathBuf::from(key),
            output: extraction(text),
        }
    }

    #[test]
    fn corpus_sorts_entries_on_construction() {
        let c = Corpus::from_entries(vec![
            entry("z.txt", "z body"),
            entry("a.txt", "a body"),
            entry("m.txt", "m body"),
        ]);
        let keys: Vec<&Path> = c.entries().iter().map(|e| e.source_key.as_path()).collect();
        assert_eq!(
            keys,
            vec![Path::new("a.txt"), Path::new("m.txt"), Path::new("z.txt")],
        );
    }

    #[test]
    fn corpus_dedupes_by_source_key() {
        let c = Corpus::from_entries(vec![entry("a.txt", "first"), entry("a.txt", "second")]);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn corpus_inventory_hash_is_deterministic() {
        let c1 = Corpus::from_entries(vec![entry("a.txt", "x")]);
        let c2 = Corpus::from_entries(vec![entry("a.txt", "x")]);
        assert_eq!(c1.inventory_hash(), c2.inventory_hash());
        assert_eq!(c1.inventory_hash().len(), 64);
    }

    #[test]
    fn corpus_inventory_hash_changes_when_entry_added() {
        let c1 = Corpus::from_entries(vec![entry("a.txt", "x")]);
        let c2 = Corpus::from_entries(vec![entry("a.txt", "x"), entry("b.txt", "y")]);
        assert_ne!(c1.inventory_hash(), c2.inventory_hash());
    }

    #[test]
    fn corpus_inventory_hash_is_independent_of_entry_text() {
        // FR-022: the inventory hash is over source-key set, not content.
        // Re-OCR'd files with the same key produce the same inventory hash;
        // the verifier catches the content drift via quote_hash mismatch.
        let c1 = Corpus::from_entries(vec![entry("a.txt", "old")]);
        let c2 = Corpus::from_entries(vec![entry("a.txt", "new")]);
        assert_eq!(c1.inventory_hash(), c2.inventory_hash());
    }

    #[test]
    fn corpus_inventory_hash_independent_of_construction_order() {
        let c1 = Corpus::from_entries(vec![entry("a.txt", "x"), entry("b.txt", "y")]);
        let c2 = Corpus::from_entries(vec![entry("b.txt", "y"), entry("a.txt", "x")]);
        assert_eq!(c1.inventory_hash(), c2.inventory_hash());
    }

    #[test]
    fn extracted_corpus_hash_alias_matches_method() {
        let c = Corpus::from_entries(vec![entry("a.txt", "x")]);
        assert_eq!(extracted_corpus_hash(&c), c.inventory_hash());
    }

    #[test]
    fn corpus_get_finds_entry() {
        let c = Corpus::from_entries(vec![entry("a.txt", "x")]);
        assert!(c.get(Path::new("a.txt")).is_some());
        assert!(c.get(Path::new("missing.txt")).is_none());
    }
}
