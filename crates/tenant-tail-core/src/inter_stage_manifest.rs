//! Signed inter-stage manifests for the factory-engine two-phase pipeline.
//!
//! Every hand-off between stages (s0–s5 sequential, s6a–s6g fan-out) carries
//! a signed manifest identifying the producer, the artifacts handed over, and
//! a per-stage ephemeral-key signature anchored to a run-level root key
//! (spec 170 §2).
//!
//! This is the verify-only half, extracted from OAP's
//! `factory-engine/src/inter_stage_manifest.rs` and relicensed Apache-2.0 from
//! AGPL-3.0 by the sole copyright holder (see NOTICE). The signing/minting side
//! (key chains, `sign_manifest`, the handoff session) is excluded; only the
//! types and `verify_manifest` (replayed by the certificate verifier against a
//! chain embedded in the certificate) are kept.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

/// JSON shape of an inter-stage manifest (spec 170 §2).
///
/// `signature` is the base64-encoded Ed25519 signature over the canonical
/// JSON of the manifest with `signature` set to empty string. The signing
/// key is the dispatching stage's ephemeral key, derived from the run's
/// root key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterStageManifest {
    pub run_id: String,
    pub from_stage: String,
    pub to_stage: String,
    pub produced_at: DateTime<Utc>,
    pub artifact_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub signer: ManifestSigner,
    pub signature: String,
}

/// Identity of the agent that signed the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSigner {
    /// Agent identifier (URI). Today this is `factory-engine/stage/<id>`;
    /// future distributed factory may carry a richer identity.
    pub agent_id: String,
    /// Fingerprint of the ephemeral key (SHA-256 of the public-key bytes,
    /// base64-encoded). The receiving stage resolves this against the run's
    /// key chain (§2.1).
    pub ephemeral_key_id: String,
}

/// Errors that can occur while building, signing, or verifying a manifest.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest signature verification failed: {0}")]
    SignatureInvalid(String),
    #[error(
        "signer's ephemeral_key_id {fingerprint} is not registered in run {run_id}'s key chain"
    )]
    UnknownSigner { run_id: String, fingerprint: String },
    #[error(
        "manifest's run_id {manifest_run_id} does not match expected run {expected_run_id} (cross-run swap)"
    )]
    RunIdMismatch {
        expected_run_id: String,
        manifest_run_id: String,
    },
    #[error(
        "manifest's to_stage {actual_to_stage} does not match expected receiver {expected_to_stage}"
    )]
    StageMismatch {
        expected_to_stage: String,
        actual_to_stage: String,
    },
    #[error(
        "key {fingerprint} is registered under a fingerprint that is not the SHA-256 of its own public key (forged key-chain entry)"
    )]
    FingerprintMismatch { fingerprint: String },
    #[error("invalid key material: {0}")]
    KeyMaterial(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(String),
}

// ── Run key chain ────────────────────────────────────────────────────

/// Per-run key chain: the root verifying key plus the registry of stage
/// ephemeral keys established as the run progresses.
///
/// Persisted under the run directory so receiving stages can resolve a
/// manifest's `ephemeral_key_id` offline (FR-006). The signing keys
/// themselves never appear in the chain -- only verifying material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunKeyChain {
    pub run_id: String,
    /// Base64-encoded Ed25519 verifying key (32 bytes). Anchored in the
    /// run's governance certificate at run completion (spec 170 §2.1,
    /// spec 102 FR-007 composition).
    pub root_public_key_b64: String,
    pub stage_keys: BTreeMap<String, StageKeyRecord>,
}

/// One stage's registered ephemeral public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StageKeyRecord {
    pub stage_id: String,
    /// Base64-encoded Ed25519 verifying key.
    pub ephemeral_public_key_b64: String,
    /// SHA-256 of the verifying-key bytes, base64-encoded. Stable identifier
    /// referenced by `ManifestSigner.ephemeral_key_id`.
    pub key_fingerprint: String,
}

impl RunKeyChain {
    /// Resolve a fingerprint to a verifying key by linear scan of the
    /// registered stage keys. Returns the verifying key and the stage_id
    /// it belongs to.
    pub fn resolve_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<(VerifyingKey, &str), ManifestError> {
        for record in self.stage_keys.values() {
            if record.key_fingerprint == fingerprint {
                let bytes: [u8; 32] = B64
                    .decode(&record.ephemeral_public_key_b64)
                    .map_err(|e| ManifestError::KeyMaterial(format!("base64: {e}")))?
                    .try_into()
                    .map_err(|v: Vec<u8>| {
                        ManifestError::KeyMaterial(format!(
                            "ephemeral_public_key length {} != 32",
                            v.len()
                        ))
                    })?;
                // Bind the fingerprint label to the actual key bytes: the
                // registered `key_fingerprint` MUST be the SHA-256 of the key
                // it labels. Without this, an attacker could register their
                // own key under any fingerprint string and have a manifest
                // reference that label (the fingerprint would otherwise be an
                // unverified alias, not a commitment to the key).
                if fingerprint_of_pubkey(&bytes) != record.key_fingerprint {
                    return Err(ManifestError::FingerprintMismatch {
                        fingerprint: fingerprint.to_string(),
                    });
                }
                let key = VerifyingKey::from_bytes(&bytes)
                    .map_err(|e| ManifestError::KeyMaterial(format!("not Ed25519: {e}")))?;
                return Ok((key, record.stage_id.as_str()));
            }
        }
        Err(ManifestError::UnknownSigner {
            run_id: self.run_id.clone(),
            fingerprint: fingerprint.to_string(),
        })
    }
}

/// SHA-256 of an Ed25519 public-key payload, base64-encoded.
pub fn fingerprint_of_pubkey(pubkey_bytes: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    B64.encode(hasher.finalize())
}

// ── Manifest signing / verifying ─────────────────────────────────────

/// Verify a manifest against the run's key chain.
///
/// Checks, in order:
///   1. `manifest.run_id == expected_run_id` (cross-run-swap guard, SC-003).
///   2. `manifest.to_stage == expected_to_stage` when supplied (the consumer
///      provides its own stage id so a manifest produced for a different
///      receiver doesn't pass).
///   3. The `ephemeral_key_id` resolves in the chain AND its fingerprint is
///      the SHA-256 of the key it labels (no aliasing a foreign key).
///   4. The Ed25519 signature verifies (strictly) against the canonical bytes.
pub fn verify_manifest(
    manifest: &InterStageManifest,
    key_chain: &RunKeyChain,
    expected_to_stage: Option<&str>,
) -> Result<(), ManifestError> {
    if manifest.run_id != key_chain.run_id {
        return Err(ManifestError::RunIdMismatch {
            expected_run_id: key_chain.run_id.clone(),
            manifest_run_id: manifest.run_id.clone(),
        });
    }
    if let Some(expected) = expected_to_stage
        && manifest.to_stage != expected
    {
        return Err(ManifestError::StageMismatch {
            expected_to_stage: expected.to_string(),
            actual_to_stage: manifest.to_stage.clone(),
        });
    }
    // The resolved stage id is available for a producer/key binding
    // (`from_stage == key_stage`), but that is deliberately NOT enforced here:
    // tenant-tail ships no inter-stage chain fixture, so the exact string
    // relationship between a manifest's `from_stage` and the stage-key
    // registration id is unverified against a real OAP chain, and an
    // over-strict equality check would risk false-rejecting a legitimate
    // certificate. The check is defence-in-depth anyway (the whole chain is
    // inside the certificate's Ed25519 signature). Revisit once a golden
    // chain fixture exists.
    let (verifying_key, _key_stage) =
        key_chain.resolve_fingerprint(&manifest.signer.ephemeral_key_id)?;

    let sig_bytes: [u8; 64] = B64
        .decode(&manifest.signature)
        .map_err(|e| ManifestError::SignatureInvalid(format!("base64: {e}")))?
        .try_into()
        .map_err(|v: Vec<u8>| {
            ManifestError::SignatureInvalid(format!("signature length {} != 64", v.len()))
        })?;
    let signature = Signature::from_bytes(&sig_bytes);

    let canonical = canonical_bytes_for_signing(manifest)?;
    // `verify_strict`: reject malleable signatures and small-order keys.
    verifying_key
        .verify_strict(&canonical, &signature)
        .map_err(|e| ManifestError::SignatureInvalid(format!("Ed25519: {e}")))
}

fn canonical_bytes_for_signing(manifest: &InterStageManifest) -> Result<Vec<u8>, ManifestError> {
    let mut clone = manifest.clone();
    clone.signature = String::new();
    serde_json::to_vec(&clone).map_err(|e| ManifestError::Serialization(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a run key chain plus a manifest whose s1 ephemeral key signs it,
    /// with a fingerprint that is the true SHA-256 of that key.
    fn signed_chain() -> (RunKeyChain, InterStageManifest, SigningKey) {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let vk = key.verifying_key();
        let fp = fingerprint_of_pubkey(&vk.to_bytes());
        let mut stage_keys = BTreeMap::new();
        stage_keys.insert(
            "s1".to_string(),
            StageKeyRecord {
                stage_id: "s1".into(),
                ephemeral_public_key_b64: B64.encode(vk.to_bytes()),
                key_fingerprint: fp.clone(),
            },
        );
        let chain = RunKeyChain {
            run_id: "run-1".into(),
            root_public_key_b64: B64.encode(vk.to_bytes()),
            stage_keys,
        };
        let mut m = InterStageManifest {
            run_id: "run-1".into(),
            from_stage: "s1".into(),
            to_stage: "s2".into(),
            produced_at: Utc::now(),
            artifact_hashes: BTreeMap::new(),
            metadata: BTreeMap::new(),
            signer: ManifestSigner {
                agent_id: "factory-engine/stage/s1".into(),
                ephemeral_key_id: fp,
            },
            signature: String::new(),
        };
        let canonical = canonical_bytes_for_signing(&m).unwrap();
        m.signature = B64.encode(key.sign(&canonical).to_bytes());
        (chain, m, key)
    }

    #[test]
    fn valid_manifest_verifies() {
        let (chain, m, _k) = signed_chain();
        assert!(verify_manifest(&m, &chain, Some("s2")).is_ok());
    }

    #[test]
    fn forged_fingerprint_label_is_rejected() {
        // Attacker relabels the registered key under a bogus fingerprint the
        // manifest also references. The label is no longer the SHA-256 of the
        // key, so resolution fails before the signature is even checked.
        let (mut chain, mut m, _k) = signed_chain();
        let bogus = "not-the-real-fingerprint".to_string();
        chain.stage_keys.get_mut("s1").unwrap().key_fingerprint = bogus.clone();
        m.signer.ephemeral_key_id = bogus;
        assert!(matches!(
            verify_manifest(&m, &chain, None),
            Err(ManifestError::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn cross_run_manifest_is_rejected() {
        let (chain, mut m, _k) = signed_chain();
        m.run_id = "other-run".into();
        assert!(matches!(
            verify_manifest(&m, &chain, None),
            Err(ManifestError::RunIdMismatch { .. })
        ));
    }
}
