//! Project allowlist derivation and external-entity detection.
//!
//! The allowlist is auto-derived per project from five inputs (FR-015):
//!
//!   (a) built-in core (jurisdictions, stopwords, common verbs, vendors
//!       widely used by Government of Alberta projects) -- embedded at
//!       compile time from `data/core-allowlist.txt`,
//!   (b) project name + slug + workspace name,
//!   (c) capitalized-token frequency scan over the typed extraction
//!       corpus (threshold-tunable; default 1 = generous),
//!   (d) `entity-model.yaml` from a prior Stage 2 run, if present
//!       (parsed minimally -- only `name:` lines under an `entities:` key
//!       are extracted; full YAML support deferred to keep the dep list
//!       at the FR-001 minimum),
//!   (e) charter vocabulary from spec 122, if present (null-safe -- 122
//!       is not yet shipped).
//!
//! External-entity detection (FR-016) flags tokens that look plausibly
//! like organization/system/product names AND are NOT in the allowlist.
//! Plausibility is a simple capitalization + length heuristic exposed as
//! the `EntityPlausibility` trait. NER is explicitly out of scope.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use tenant_tail_types::knowledge::ExtractionOutput;
use unicode_normalization::UnicodeNormalization;

const BUILTIN_CORE: &str = include_str!("../data/core-allowlist.txt");

/// Compiled project allowlist. Tokens are stored lowercased + NFC-
/// normalised for the `contains` check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    tokens: BTreeSet<String>,
    /// Stable version hash for cache invalidation (FR-017). sha256 of the
    /// sorted token list, joined by `\n`.
    pub version_hash: String,
}

impl Allowlist {
    /// True if `token` (after lowercase + NFC) is in the allowlist.
    pub fn contains(&self, token: &str) -> bool {
        let key = normalise(token);
        self.tokens.contains(&key)
    }

    /// Sorted iterator over the allowlist's tokens.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.tokens.iter().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// Inputs to allowlist derivation (FR-015).
#[derive(Debug, Clone)]
pub struct ProjectContext<'a> {
    pub corpus: &'a [ExtractionOutput],
    pub project_name: &'a str,
    pub project_slug: &'a str,
    pub workspace_name: &'a str,
    /// Optional `entity-model.yaml` contents from a prior Stage 2 run.
    /// `None` until Stage 2 has run at least once.
    pub entity_model_yaml: Option<&'a str>,
    /// Optional charter vocabulary from spec 122. `None` until 122 ships.
    pub charter_vocabulary: Option<&'a [String]>,
    /// Frequency threshold for the capitalized-token corpus scan
    /// (FR-015 input c). Default 1 = every distinct capitalized token
    /// qualifies (generous). Operators tune up to suppress noise.
    pub capitalized_token_frequency_threshold: u32,
}

impl<'a> Default for ProjectContext<'a> {
    fn default() -> Self {
        ProjectContext {
            corpus: &[],
            project_name: "",
            project_slug: "",
            workspace_name: "",
            entity_model_yaml: None,
            charter_vocabulary: None,
            capitalized_token_frequency_threshold: 1,
        }
    }
}

/// Derive the project allowlist from all input sources.
///
/// Pure: the only filesystem read is `include_str!` at compile time, so
/// the function has no I/O at runtime. Returns a deterministic
/// `Allowlist` whose `version_hash` is sha256 of the sorted token list.
pub fn derive(project: &ProjectContext<'_>) -> Allowlist {
    let mut tokens: BTreeSet<String> = BTreeSet::new();

    // (a) built-in core
    for line in BUILTIN_CORE.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        tokens.insert(normalise(trimmed));
    }

    // (b) project / workspace identifiers
    extend_tokens(&mut tokens, project.project_name);
    extend_tokens(&mut tokens, project.project_slug);
    extend_tokens(&mut tokens, project.workspace_name);

    // (c) capitalized-token frequency scan over the corpus
    let corpus_tokens = capitalized_tokens_above_threshold(
        project.corpus,
        project.capitalized_token_frequency_threshold,
    );
    for t in corpus_tokens {
        tokens.insert(t);
    }

    // (d) entity-model.yaml (minimal parser -- entities[].name only)
    if let Some(yaml) = project.entity_model_yaml {
        for name in extract_entity_names(yaml) {
            extend_tokens(&mut tokens, &name);
        }
    }

    // (e) charter vocabulary (null-safe)
    if let Some(vocab) = project.charter_vocabulary {
        for term in vocab {
            extend_tokens(&mut tokens, term);
        }
    }

    // Compute version hash from the sorted token list.
    let mut hasher = Sha256::new();
    for (i, t) in tokens.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\n");
        }
        hasher.update(t.as_bytes());
    }
    let digest = hasher.finalize();
    let mut version_hash = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        version_hash.push(HEX[(b >> 4) as usize] as char);
        version_hash.push(HEX[(b & 0x0F) as usize] as char);
    }

    Allowlist {
        tokens,
        version_hash,
    }
}

/// Plausibility predicate for external-entity detection (FR-016).
/// Implementations decide whether a token shape suggests an organization
/// or product name. The default `CapitalizationHeuristic` covers the
/// common cases; alternative implementations let workspace policy or
/// future spec iterations swap in stricter or laxer heuristics without
/// touching the validator core.
pub trait EntityPlausibility: Send + Sync {
    fn is_plausible_entity(&self, token: &str) -> bool;
}

/// Default heuristic: a token is plausibly an external entity if its
/// first character is uppercase ASCII or it is an all-uppercase acronym
/// of length >= 2. Lowercase tokens, single characters, and tokens
/// containing no alphabetic characters do not qualify.
///
/// KNOWN LIMITATION (spec 121 FR-016, casing evasion): because plausibility
/// keys on capitalization, an all-lowercase surface form of a real entity
/// (`oracle erp` instead of `Oracle ERP`) is NOT flagged, so a producer that
/// controls the claim text can dodge the "names an external entity, needs a
/// citation" requirement by lowercasing. Closing this properly needs named-
/// entity recognition, which FR-016 puts explicitly out of scope (a
/// lowercase-everything rule would flag ordinary prose and drown operators in
/// false positives). The residual risk is bounded downstream: any external
/// entity that IS flagged must be substantiated by a citation whose cited span
/// actually contains it (validator coverage check), and the corpus search is
/// case-insensitive. Treat the capitalization signal as a heuristic aid, not a
/// security boundary.
pub struct CapitalizationHeuristic;

impl EntityPlausibility for CapitalizationHeuristic {
    fn is_plausible_entity(&self, token: &str) -> bool {
        let trimmed = trim_punctuation(token);
        if trimmed.len() < 2 {
            return false;
        }
        let mut chars = trimmed.chars();
        let first = match chars.next() {
            Some(c) => c,
            None => return false,
        };
        if !first.is_ascii_alphabetic() {
            // Allow leading-digit acronyms like "1GX" if the token has at
            // least one ASCII alphabetic character.
            if !trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
                return false;
            }
        }
        let has_uppercase = trimmed.chars().any(|c| c.is_ascii_uppercase());
        let all_uppercase_alpha = trimmed
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .all(|c| c.is_ascii_uppercase());
        // Plausible if it begins with an uppercase letter, OR contains a
        // mix that includes uppercase, OR is an all-uppercase acronym.
        first.is_ascii_uppercase() || has_uppercase || all_uppercase_alpha
    }
}

/// Scan claim text for plausibly-external-entity tokens that are NOT in
/// the allowlist. Returns sorted, deduplicated surface forms (preserving
/// original casing in the surface form so the operator sees `"1GX"`,
/// not `"1gx"`).
pub fn detect_external_entities(
    claim_text: &str,
    allowlist: &Allowlist,
    plausibility: &dyn EntityPlausibility,
) -> Vec<String> {
    let mut hits: BTreeSet<String> = BTreeSet::new();

    for raw in claim_text.split(|c: char| c.is_whitespace()) {
        let token = trim_punctuation(raw);
        if token.is_empty() {
            continue;
        }
        if !plausibility.is_plausible_entity(token) {
            continue;
        }
        if allowlist.contains(token) {
            continue;
        }
        // Also check the hyphen-split components so `Treasury-Board` is
        // matched against the allowlist as `treasury` AND `board`. Only
        // if BOTH components are allowlisted is the compound suppressed --
        // otherwise the operator wants to see the surface form.
        let components: Vec<&str> = token.split('-').collect();
        if components.len() > 1 && components.iter().all(|c| allowlist.contains(c)) {
            continue;
        }
        hits.insert(token.to_string());
    }

    hits.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn normalise(token: &str) -> String {
    let trimmed = trim_punctuation(token).to_lowercase();
    trimmed.nfc().collect()
}

fn trim_punctuation(s: &str) -> &str {
    s.trim_matches(|c: char| !c.is_alphanumeric())
}

fn extend_tokens(target: &mut BTreeSet<String>, source: &str) {
    for raw in source.split(|c: char| c.is_whitespace() || c == '-' || c == '_') {
        let normalised = normalise(raw);
        if !normalised.is_empty() {
            target.insert(normalised);
        }
    }
}

fn capitalized_tokens_above_threshold(corpus: &[ExtractionOutput], threshold: u32) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for output in corpus {
        for_each_capitalized_token(&output.text, &mut |t| {
            *counts.entry(t).or_insert(0) += 1;
        });
        if let Some(pages) = &output.pages {
            for page in pages {
                for_each_capitalized_token(&page.text, &mut |t| {
                    *counts.entry(t).or_insert(0) += 1;
                });
            }
        }
    }
    counts
        .into_iter()
        .filter(|(_, c)| *c >= threshold)
        .map(|(k, _)| k)
        .collect()
}

fn for_each_capitalized_token(text: &str, sink: &mut dyn FnMut(String)) {
    for raw in text.split(|c: char| c.is_whitespace()) {
        let token = trim_punctuation(raw);
        if token.is_empty() {
            continue;
        }
        let first = token.chars().next();
        let starts_uppercase = first.map(|c| c.is_ascii_uppercase()).unwrap_or(false);
        let any_uppercase = token.chars().any(|c| c.is_ascii_uppercase());
        if !(starts_uppercase || any_uppercase) {
            continue;
        }
        // Add the full token AND the hyphen-split components so the
        // allowlist covers both `Treasury-Board` style and `Treasury` /
        // `Board` lookups.
        sink(normalise(token));
        if token.contains('-') {
            for component in token.split('-') {
                let n = normalise(component);
                if !n.is_empty() {
                    sink(n);
                }
            }
        }
    }
}

/// Minimal `entity-model.yaml` parser: extracts `name:` values that
/// appear under an `entities:` key. Robust enough for the common Stage 2
/// output shape; intentionally NOT a full YAML parser (FR-001 caps deps
/// at the listed five). False negatives are acceptable -- entity-model
/// is one of five allowlist sources, and any miss is caught by the
/// corpus capitalized-token scan.
fn extract_entity_names(yaml: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut in_entities = false;
    for raw_line in yaml.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            // Top-level key change -- `entities:` opens, anything else closes.
            in_entities = trimmed.starts_with("entities:");
            continue;
        }
        if !in_entities {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- name:") {
            names.push(strip_yaml_string(rest.trim()));
        } else if let Some(rest) = trimmed.strip_prefix("name:") {
            names.push(strip_yaml_string(rest.trim()));
        }
    }
    names
}

fn strip_yaml_string(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
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

    fn ctx_with<'a>(
        name: &'a str,
        slug: &'a str,
        workspace: &'a str,
        corpus: &'a [ExtractionOutput],
    ) -> ProjectContext<'a> {
        ProjectContext {
            project_name: name,
            project_slug: slug,
            workspace_name: workspace,
            corpus,
            entity_model_yaml: None,
            charter_vocabulary: None,
            capitalized_token_frequency_threshold: 1,
        }
    }

    // ---------- input source coverage ----------

    #[test]
    fn allowlist_contains_builtin_core_tokens() {
        let allow = derive(&ProjectContext::default());
        // Sample tokens from data/core-allowlist.txt
        assert!(allow.contains("alberta"));
        assert!(allow.contains("government"));
        assert!(allow.contains("the"));
        assert!(allow.contains("microsoft"));
    }

    #[test]
    fn allowlist_excludes_unrelated_token() {
        let allow = derive(&ProjectContext::default());
        // A made-up token that should NEVER appear in the core list.
        assert!(!allow.contains("xyzzyfrobnicate1gxoraclething"));
    }

    #[test]
    fn allowlist_contains_project_name_tokens() {
        let allow = derive(&ctx_with(
            "CFS Emergency Family Violence Services",
            "cfs-emergency-family-violence-services",
            "GoA",
            &[],
        ));
        assert!(allow.contains("cfs"));
        assert!(allow.contains("emergency"));
        assert!(allow.contains("family"));
        assert!(allow.contains("violence"));
        assert!(allow.contains("services"));
    }

    #[test]
    fn allowlist_contains_workspace_tokens() {
        let allow = derive(&ctx_with("p", "p", "PrivacyOps", &[]));
        assert!(allow.contains("privacyops"));
    }

    #[test]
    fn allowlist_contains_capitalized_corpus_tokens() {
        let corpus = vec![extraction(
            "The Entra ID system handles authentication for the Frobozz Engine.",
        )];
        let allow = derive(&ctx_with("p", "p", "w", &corpus));
        assert!(allow.contains("entra"));
        assert!(allow.contains("id"));
        // "Frobozz" is a made-up token; the corpus scan should pick it up.
        assert!(allow.contains("frobozz"));
    }

    #[test]
    fn allowlist_capitalized_token_frequency_threshold() {
        let corpus = vec![extraction("Oracle Vendor Vendor Vendor")];
        let mut ctx = ctx_with("p", "p", "w", &corpus);
        ctx.capitalized_token_frequency_threshold = 2;
        let allow = derive(&ctx);
        assert!(allow.contains("vendor"));
        assert!(!allow.contains("oracle"));
    }

    #[test]
    fn allowlist_entity_model_yaml_tokens() {
        let yaml =
            "entities:\n  - name: Shelter Society Registry\n  - name: \"Funding Approval\"\n";
        let ctx = ProjectContext {
            entity_model_yaml: Some(yaml),
            ..Default::default()
        };
        let allow = derive(&ctx);
        assert!(allow.contains("shelter"));
        assert!(allow.contains("society"));
        assert!(allow.contains("registry"));
        assert!(allow.contains("funding"));
        assert!(allow.contains("approval"));
    }

    #[test]
    fn allowlist_entity_model_yaml_ignores_other_keys() {
        // `name:` outside an `entities:` top-level block should NOT be
        // pulled into the allowlist (the parser only looks under
        // entities:).
        let yaml = "metadata:\n  name: Should Not Leak\nentities:\n  - name: Real Entity\n";
        let ctx = ProjectContext {
            entity_model_yaml: Some(yaml),
            ..Default::default()
        };
        let allow = derive(&ctx);
        assert!(allow.contains("real"));
        assert!(allow.contains("entity"));
        assert!(!allow.contains("leak"));
    }

    #[test]
    fn allowlist_charter_vocabulary_null_safe() {
        let ctx = ProjectContext {
            charter_vocabulary: None,
            ..Default::default()
        };
        // Must not panic.
        let _ = derive(&ctx);
    }

    #[test]
    fn allowlist_charter_vocabulary_tokens() {
        let vocab = vec!["Foundation Trust".to_string(), "Sponsor".to_string()];
        let ctx = ProjectContext {
            charter_vocabulary: Some(&vocab),
            ..Default::default()
        };
        let allow = derive(&ctx);
        assert!(allow.contains("foundation"));
        assert!(allow.contains("trust"));
        assert!(allow.contains("sponsor"));
    }

    // ---------- version hash ----------

    #[test]
    fn allowlist_version_hash_is_64_chars_hex() {
        let allow = derive(&ProjectContext::default());
        assert_eq!(allow.version_hash.len(), 64);
        assert!(allow.version_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn allowlist_version_hash_changes_with_inputs() {
        let a = derive(&ctx_with("Alpha", "alpha", "w", &[]));
        let b = derive(&ctx_with("Beta", "beta", "w", &[]));
        assert_ne!(a.version_hash, b.version_hash);
    }

    #[test]
    fn allowlist_version_hash_is_deterministic() {
        // Same inputs in two runs must produce identical version hashes --
        // the FR-002 determinism property.
        let a = derive(&ctx_with("p", "p", "w", &[]));
        let b = derive(&ctx_with("p", "p", "w", &[]));
        assert_eq!(a.version_hash, b.version_hash);
    }

    // ---------- entity detection ----------

    #[test]
    fn detect_external_entities_flags_unlisted() {
        let allow = derive(&ProjectContext::default());
        let claim = "STK-13 references Treasury Board Integrations and 1GX Oracle ERP.";
        let entities = detect_external_entities(claim, &allow, &CapitalizationHeuristic);
        // STK-13 is alphanumeric uppercase but contains "stk" which is
        // not in the allowlist. Acceptable as a flagged candidate.
        assert!(entities.iter().any(|e| e.contains("1GX")));
        assert!(entities.iter().any(|e| e == "ERP"));
    }

    #[test]
    fn detect_external_entities_suppresses_allowlisted() {
        // "Microsoft" and "Azure" are in the built-in core. They should
        // NOT show up as external entities even though their token shape
        // is plausible.
        let allow = derive(&ProjectContext::default());
        let entities = detect_external_entities(
            "Microsoft Azure handles auth.",
            &allow,
            &CapitalizationHeuristic,
        );
        assert!(!entities.iter().any(|e| e == "Microsoft"));
        assert!(!entities.iter().any(|e| e == "Azure"));
    }

    #[test]
    fn detect_external_entities_returns_sorted_unique() {
        let allow = derive(&ProjectContext::default());
        let entities = detect_external_entities(
            "Frobozz, Frobozz, and Frobozz again. Acme.",
            &allow,
            &CapitalizationHeuristic,
        );
        assert_eq!(entities, vec!["Acme".to_string(), "Frobozz".to_string()],);
    }

    // ---------- capitalization heuristic ----------

    #[test]
    fn capitalization_heuristic_uppercase_words_qualify() {
        let h = CapitalizationHeuristic;
        assert!(h.is_plausible_entity("Oracle"));
        assert!(h.is_plausible_entity("ERP")); // all-caps acronym
        assert!(h.is_plausible_entity("1GX")); // alphanumeric with letters
        assert!(h.is_plausible_entity("AzureAD"));
    }

    #[test]
    fn capitalization_heuristic_lowercase_or_short_does_not_qualify() {
        let h = CapitalizationHeuristic;
        assert!(!h.is_plausible_entity("oracle"));
        assert!(!h.is_plausible_entity("a")); // single char
        assert!(!h.is_plausible_entity("")); // empty
        assert!(!h.is_plausible_entity("123")); // no alphabetic
    }
}
