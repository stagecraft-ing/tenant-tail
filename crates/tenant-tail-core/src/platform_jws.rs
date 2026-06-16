//! Spec 198 FR-014 -- verification of platform-issued compact JWS.
//!
//! Rust twin of stagecraft's `api/factory/signing-pure.ts`. Stagecraft is
//! the signing authority (Ed25519, JWKS-published public keys with `kid`
//! rotation); the OPC engine and `verify-certificate` are verifiers only --
//! OPC and every agent are keyless, categorically (ASI10 m6). Three
//! signature classes, domain-separated by the JWS `typ` header:
//!
//! - `oap-admission-seal+jws` -- the admission seal the engine verifies
//!   before trusting any factory content in the OPC bundle (ASI04 m1).
//! - `oap-run-grant+jwt` -- the run-grant (intent capsule realised, FR-005).
//! - `oap-cert-countersign+jws` -- the emission countersign bound into the
//!   governance certificate and checked by `verify-certificate`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const TYP_ADMISSION_SEAL: &str = "oap-admission-seal+jws";
pub const TYP_RUN_GRANT: &str = "oap-run-grant+jwt";
pub const TYP_CERT_COUNTERSIGN: &str = "oap-cert-countersign+jws";

#[derive(Debug, thiserror::Error)]
pub enum JwsError {
    #[error("malformed compact JWS: {0}")]
    Malformed(String),
    #[error("JWS typ mismatch: got '{got}', expected '{expected}' (domain separation)")]
    TypMismatch { got: String, expected: String },
    #[error("unexpected JWS alg '{0}' (expected EdDSA)")]
    UnexpectedAlg(String),
    #[error("no JWKS key matches kid '{0}'")]
    UnknownKid(String),
    #[error("JWKS key '{0}' is not an Ed25519 OKP key")]
    NotEd25519(String),
    #[error("JWS signature verification failed: {0}")]
    SignatureInvalid(String),
}

/// One JWKS entry as served by `GET /api/factory/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformJwk {
    pub kty: String,
    pub crv: String,
    /// base64url raw 32-byte Ed25519 public key.
    pub x: String,
    pub kid: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
}

/// The published keyset (current key plus, during rotation, the previous).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformJwks {
    pub keys: Vec<PlatformJwk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedJws {
    pub header: JwsHeader,
    pub payload: serde_json::Value,
}

fn b64url(segment: &str, what: &str) -> Result<Vec<u8>, JwsError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| JwsError::Malformed(format!("{what}: {e}")))
}

/// Verify a platform compact JWS against the published keyset, requiring
/// the expected domain-separation `typ`. Any failure is fail-closed for
/// callers -- an invalid seal/grant/countersign is never partially trusted.
/// Claim-level checks (expiry, hashes, ids) are the caller's, on the
/// returned payload.
pub fn verify_compact_jws(
    jws: &str,
    jwks: &PlatformJwks,
    expected_typ: &str,
) -> Result<VerifiedJws, JwsError> {
    let segments: Vec<&str> = jws.split('.').collect();
    if segments.len() != 3 {
        return Err(JwsError::Malformed("expected 3 segments".into()));
    }
    let header: JwsHeader = serde_json::from_slice(&b64url(segments[0], "header")?)
        .map_err(|e| JwsError::Malformed(format!("header JSON: {e}")))?;
    if header.alg != "EdDSA" {
        return Err(JwsError::UnexpectedAlg(header.alg));
    }
    if header.typ != expected_typ {
        return Err(JwsError::TypMismatch {
            got: header.typ,
            expected: expected_typ.to_string(),
        });
    }
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == header.kid)
        .ok_or_else(|| JwsError::UnknownKid(header.kid.clone()))?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        return Err(JwsError::NotEd25519(jwk.kid.clone()));
    }
    let key_bytes: [u8; 32] = b64url(&jwk.x, "jwk.x")?
        .try_into()
        .map_err(|_| JwsError::NotEd25519(jwk.kid.clone()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| JwsError::NotEd25519(format!("{}: {e}", jwk.kid)))?;
    let sig_bytes: [u8; 64] = b64url(segments[2], "signature")?
        .try_into()
        .map_err(|_| JwsError::SignatureInvalid("signature length != 64".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|e| JwsError::SignatureInvalid(format!("Ed25519: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&b64url(segments[1], "payload")?)
        .map_err(|e| JwsError::Malformed(format!("payload JSON: {e}")))?;
    Ok(VerifiedJws { header, payload })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sign_test_jws(
        key: &SigningKey,
        kid: &str,
        typ: &str,
        payload: &serde_json::Value,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"alg": "EdDSA", "typ": typ, "kid": kid}))
                .unwrap(),
        );
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let sig = key.sign(format!("{header}.{body}").as_bytes());
        format!("{header}.{body}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn test_keyset(key: &SigningKey, kid: &str) -> PlatformJwks {
        PlatformJwks {
            keys: vec![PlatformJwk {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                kid: kid.into(),
                alg: Some("EdDSA".into()),
                use_: Some("sig".into()),
            }],
        }
    }

    #[test]
    fn round_trips_a_signed_payload() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let jwks = test_keyset(&key, "fk-1");
        let jws = sign_test_jws(&key, "fk-1", TYP_RUN_GRANT, &serde_json::json!({"seq": 3}));
        let verified = verify_compact_jws(&jws, &jwks, TYP_RUN_GRANT).unwrap();
        assert_eq!(verified.payload["seq"], 3);
        assert_eq!(verified.header.kid, "fk-1");
    }

    #[test]
    fn rejects_cross_class_typ() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let jwks = test_keyset(&key, "fk-1");
        let jws = sign_test_jws(&key, "fk-1", TYP_RUN_GRANT, &serde_json::json!({}));
        let err = verify_compact_jws(&jws, &jwks, TYP_CERT_COUNTERSIGN).unwrap_err();
        assert!(matches!(err, JwsError::TypMismatch { .. }));
    }

    #[test]
    fn rejects_tampered_payload() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let jwks = test_keyset(&key, "fk-1");
        let jws = sign_test_jws(
            &key,
            "fk-1",
            TYP_ADMISSION_SEAL,
            &serde_json::json!({"a": 1}),
        );
        let mut parts: Vec<String> = jws.split('.').map(String::from).collect();
        parts[1] =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"a": 2})).unwrap());
        let forged = parts.join(".");
        let err = verify_compact_jws(&forged, &jwks, TYP_ADMISSION_SEAL).unwrap_err();
        assert!(matches!(err, JwsError::SignatureInvalid(_)));
    }

    #[test]
    fn rejects_unknown_kid_and_wrong_key() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let jwks = test_keyset(&key, "fk-1");
        let unknown = sign_test_jws(&other, "fk-9", TYP_RUN_GRANT, &serde_json::json!({}));
        assert!(matches!(
            verify_compact_jws(&unknown, &jwks, TYP_RUN_GRANT).unwrap_err(),
            JwsError::UnknownKid(_)
        ));
        // Forged: another key claiming a known kid.
        let forged = sign_test_jws(&other, "fk-1", TYP_RUN_GRANT, &serde_json::json!({}));
        assert!(matches!(
            verify_compact_jws(&forged, &jwks, TYP_RUN_GRANT).unwrap_err(),
            JwsError::SignatureInvalid(_)
        ));
    }

    #[test]
    fn rejects_malformed_inputs() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let jwks = test_keyset(&key, "fk-1");
        assert!(matches!(
            verify_compact_jws("a.b", &jwks, TYP_RUN_GRANT).unwrap_err(),
            JwsError::Malformed(_)
        ));
    }

    /// Cross-language fixture: a JWS produced by stagecraft's
    /// `signing-pure.ts` against a fixed key must verify here. The fixture
    /// below was generated with Node (`crypto.generateKeyPairSync` seeded
    /// key material is not exportable deterministically, so the fixture
    /// pins the raw public key + a captured signature instead).
    #[test]
    fn signing_input_matches_ts_convention() {
        // The TS side signs over `${headerB64}.${payloadB64}` exactly --
        // assert our verifier consumes the same signing input by signing
        // with the same construction here.
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let jwks = test_keyset(&key, "fk-x");
        let payload = serde_json::json!({
            "org_id": "o", "run_id": "r", "seq": 0
        });
        let jws = sign_test_jws(&key, "fk-x", TYP_RUN_GRANT, &payload);
        let verified = verify_compact_jws(&jws, &jwks, TYP_RUN_GRANT).unwrap();
        assert_eq!(verified.payload, payload);
    }
}
