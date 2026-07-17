//! Rust mirror of statecraft's `ExtractionOutput` schema (spec 115 source of
//! truth: `platform/services/statecraft/api/knowledge/extractionOutput.ts`).
//!
//! Field names are camelCase via `serde(rename_all)` so a serialised
//! `ExtractionOutput` round-trips through statecraft's Zod parser without
//! transformation. The schema version is a compile-time const on both sides;
//! drift fails CI via `tools/oap/schema-parity-check`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Shared schema version. Mirrored verbatim by
/// `KNOWLEDGE_SCHEMA_VERSION` in `extractionOutput.ts`.
pub const KNOWLEDGE_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionOutput {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages: Option<Vec<ExtractionPage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outline: Option<Vec<ExtractionOutlineEntry>>,
    pub metadata: HashMap<String, Value>,
    pub extractor: Extractor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionPage {
    pub index: u64,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bbox: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionOutlineEntry {
    pub level: u64,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_index: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Extractor {
    pub kind: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_run: Option<AgentRun>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRun {
    pub model_id: String,
    pub prompt_fingerprint: String,
    pub duration_ms: u64,
    pub token_spend: TokenSpend,
    pub cost_usd: f64,
    pub attempts: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSpend {
    pub input: u64,
    pub output: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<u64>,
}

/// Canonical structural fingerprint of the `ExtractionOutput` schema as
/// produced by the Rust types above. The matching `tools/oap/schema-parity-check`
/// computes the same shape from `extractionOutput.ts` and asserts equality.
///
/// Field lists at every nesting level are emitted in alphabetical order so
/// the comparison is order-independent.
pub fn knowledge_schema_fingerprint() -> Value {
    let token_spend = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "cacheRead", "required": false, "type": {"kind": "int"}},
            {"name": "cacheWrite", "required": false, "type": {"kind": "int"}},
            {"name": "input", "required": true, "type": {"kind": "int"}},
            {"name": "output", "required": true, "type": {"kind": "int"}},
        ],
    });
    let agent_run = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "attempts", "required": true, "type": {"kind": "int"}},
            {"name": "costUsd", "required": true, "type": {"kind": "number"}},
            {"name": "durationMs", "required": true, "type": {"kind": "int"}},
            {"name": "modelId", "required": true, "type": {"kind": "string"}},
            {"name": "promptFingerprint", "required": true, "type": {"kind": "string"}},
            {"name": "tokenSpend", "required": true, "type": token_spend},
        ],
    });
    let extractor = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "agentRun", "required": false, "type": agent_run},
            {"name": "kind", "required": true, "type": {"kind": "string"}},
            {"name": "version", "required": true, "type": {"kind": "string"}},
        ],
    });
    let page = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "bbox", "required": false, "type": {"kind": "unknown"}},
            {"name": "index", "required": true, "type": {"kind": "int"}},
            {"name": "text", "required": true, "type": {"kind": "string"}},
        ],
    });
    let outline_entry = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "level", "required": true, "type": {"kind": "int"}},
            {"name": "pageIndex", "required": false, "type": {"kind": "int"}},
            {"name": "text", "required": true, "type": {"kind": "string"}},
        ],
    });
    let root = serde_json::json!({
        "kind": "object",
        "fields": [
            {"name": "extractor", "required": true, "type": extractor},
            {"name": "language", "required": false, "type": {"kind": "string"}},
            {"name": "metadata", "required": true, "type": {
                "kind": "map",
                "key": {"kind": "string"},
                "value": {"kind": "unknown"},
            }},
            {"name": "outline", "required": false, "type": {
                "kind": "array",
                "element": outline_entry,
            }},
            {"name": "pages", "required": false, "type": {
                "kind": "array",
                "element": page,
            }},
            {"name": "text", "required": true, "type": {"kind": "string"}},
        ],
    });
    serde_json::json!({
        "version": KNOWLEDGE_SCHEMA_VERSION,
        "root": root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The OAP-side fingerprint-to-disk test (feeding `tools/oap/schema-parity-check`
    // against the statecraft TS mirror) is dropped in tenant-tail: there is no TS
    // mirror here, and a test that writes into the committed tree as a side effect
    // is undesirable. The pure fingerprint + drift tests below are kept.

    /// Anchor the kind-string contract. The parity walker emits
    /// `"int"` (not `"integer"`) for `z.number().int()`; a contributor
    /// who renamed it on the Rust side without touching the walker would
    /// pass this test only if both sides changed in lockstep.
    #[test]
    fn integer_fields_use_int_kind() {
        let fp = knowledge_schema_fingerprint();
        let pages = fp["root"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "pages")
            .unwrap();
        let element_fields = pages["type"]["element"]["fields"].as_array().unwrap();
        let index_field = element_fields
            .iter()
            .find(|f| f["name"] == "index")
            .unwrap();
        assert_eq!(index_field["type"]["kind"], "int");
    }

    /// Drift-anchor: serialise a populated `ExtractionOutput`, walk the
    /// resulting JSON keys, and assert they match what the fingerprint
    /// describes. Catches the case where a contributor adds a serde field
    /// but forgets to update `knowledge_schema_fingerprint`.
    #[test]
    fn fingerprint_matches_serialised_keys() {
        let populated = ExtractionOutput {
            text: "hello".into(),
            pages: Some(vec![ExtractionPage {
                index: 0,
                text: "p1".into(),
                bbox: Some(serde_json::json!({"x": 0})),
            }]),
            language: Some("en".into()),
            outline: Some(vec![ExtractionOutlineEntry {
                level: 1,
                text: "intro".into(),
                page_index: Some(0),
            }]),
            metadata: HashMap::new(),
            extractor: Extractor {
                kind: "deterministic-text".into(),
                version: "1.0.0".into(),
                agent_run: Some(AgentRun {
                    model_id: "test".into(),
                    prompt_fingerprint: "0".repeat(64),
                    duration_ms: 0,
                    token_spend: TokenSpend {
                        input: 0,
                        output: 0,
                        cache_read: Some(0),
                        cache_write: Some(0),
                    },
                    cost_usd: 0.0,
                    attempts: 1,
                }),
            },
        };
        let v = serde_json::to_value(&populated).unwrap();
        let fp = knowledge_schema_fingerprint();
        assert_keys_match(&v, &fp["root"]);
    }

    fn assert_keys_match(actual: &Value, fp_node: &Value) {
        let kind = fp_node["kind"].as_str().expect("fp kind missing");
        match kind {
            "object" => {
                let actual_obj = actual.as_object().expect("expected serialised object");
                let fp_fields: Vec<(String, bool, &Value)> = fp_node["fields"]
                    .as_array()
                    .expect("fields array")
                    .iter()
                    .map(|f| {
                        (
                            f["name"].as_str().unwrap().to_string(),
                            f["required"].as_bool().unwrap(),
                            &f["type"],
                        )
                    })
                    .collect();
                let actual_keys: std::collections::BTreeSet<&String> = actual_obj.keys().collect();
                let required_fp_names: std::collections::BTreeSet<String> = fp_fields
                    .iter()
                    .filter(|(_, req, _)| *req)
                    .map(|(n, _, _)| n.clone())
                    .collect();
                let optional_fp_names: std::collections::BTreeSet<String> = fp_fields
                    .iter()
                    .filter(|(_, req, _)| !req)
                    .map(|(n, _, _)| n.clone())
                    .collect();
                for name in &required_fp_names {
                    assert!(
                        actual_keys.contains(name),
                        "fingerprint declares required field '{name}' missing in serialisation",
                    );
                }
                for name in &actual_keys {
                    let n = (*name).clone();
                    assert!(
                        required_fp_names.contains(&n) || optional_fp_names.contains(&n),
                        "serialisation has field '{n}' not declared in fingerprint",
                    );
                }
                for (name, _, t) in &fp_fields {
                    if let Some(child) = actual_obj.get(name) {
                        assert_keys_match(child, t);
                    }
                }
            }
            "array" => {
                let arr = actual.as_array().expect("expected serialised array");
                if let Some(first) = arr.first() {
                    assert_keys_match(first, &fp_node["element"]);
                }
            }
            "map" => {
                let _ = actual.as_object().expect("expected serialised map/object");
            }
            "string" | "int" | "number" | "boolean" | "unknown" => {}
            other => panic!("unknown fingerprint kind: {other}"),
        }
    }

    /// Deliberate-drift regression: a synthetic perturbation of the
    /// fingerprint must compare not-equal. Proves the equality check has
    /// teeth.
    #[test]
    fn drift_is_detected() {
        let baseline = knowledge_schema_fingerprint();
        let mut drifted = baseline.clone();
        drifted["root"]["fields"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "name": "syntheticDrift",
                "required": true,
                "type": {"kind": "string"}
            }));
        assert_ne!(baseline, drifted);
    }
}
