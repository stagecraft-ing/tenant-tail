//! Behavior-parity test for the certificate verify core.
//!
//! The golden fixture (`tests/fixtures/cert-run/`) is a real governance
//! certificate minted by OAP's in-tree `build-certificate` emitter over a run
//! directory of stage artifacts. This is the cross-implementation parity check
//! the handoff calls for (the analogue of OAP's schema-parity-walker): a
//! certificate produced by the factory MUST verify in the vended tenant-tail
//! verifier, and any tampering MUST be caught.
//!
//! Regenerate the fixture (when the certificate format changes) with OAP's
//! emitter:
//!   build-certificate <run-dir> --adapter demo-adapter \
//!     --business-docs <doc> --out <run-dir>/governance-certificate.json

use std::path::{Path, PathBuf};
use tenant_tail_core::{
    GovernanceCertificate, verify_certificate, verify_certificate_with_platform,
};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cert-run")
}

fn load_fixture() -> (GovernanceCertificate, PathBuf) {
    let dir = fixture_dir();
    let json = std::fs::read_to_string(dir.join("governance-certificate.json"))
        .expect("fixture certificate is present");
    let cert: GovernanceCertificate =
        serde_json::from_str(&json).expect("fixture certificate deserializes");
    (cert, dir)
}

#[test]
fn oap_minted_certificate_verifies() {
    let (cert, dir) = load_fixture();
    let result = verify_certificate(&cert, Some(&dir));
    assert!(
        result.valid,
        "OAP-minted certificate must verify in tenant-tail; errors: {:?}",
        result.errors
    );
    assert!(
        result.errors.is_empty(),
        "no errors expected: {:?}",
        result.errors
    );
}

#[test]
fn certificate_verifies_without_artifact_dir() {
    // The offline signature + self-hash chain holds with no artifact dir; the
    // artifact-hash re-derivation step (FR-005) is simply skipped.
    let (cert, _dir) = load_fixture();
    let result = verify_certificate(&cert, None);
    assert!(result.valid, "errors: {:?}", result.errors);
}

#[test]
fn tampered_field_breaks_signature_and_hash() {
    let (mut cert, dir) = load_fixture();
    // Mutate a signed field. Both the recomputed self-hash and the Ed25519
    // signature now mismatch: a tamper-with-resign attack cannot mint a valid
    // signature without the private key.
    cert.pipeline_run_id = "tampered-run-id".to_string();
    let result = verify_certificate(&cert, Some(&dir));
    assert!(!result.valid, "tampered certificate must be rejected");
    assert!(
        result.errors.iter().any(|e| e.contains("signature")),
        "expected a signature failure; got {:?}",
        result.errors
    );
}

#[test]
fn tampered_artifact_on_disk_is_rejected() {
    let (cert, _dir) = load_fixture();
    // Copy the fixture into a temp dir and corrupt one artifact. The cert is
    // unchanged (signature + self-hash still valid) but the on-disk artifact no
    // longer matches its recorded hash (FR-005).
    let tmp = tempfile::tempdir().expect("tempdir");
    let stage = "s0-preflight";
    std::fs::create_dir_all(tmp.path().join(stage)).unwrap();
    std::fs::write(
        tmp.path().join(stage).join("preflight.txt"),
        b"CORRUPTED CONTENT\n",
    )
    .unwrap();

    let result = verify_certificate(&cert, Some(tmp.path()));
    assert!(!result.valid, "corrupted artifact must be rejected");
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("artifact hash mismatch")),
        "expected an artifact hash mismatch; got {:?}",
        result.errors
    );
}

#[test]
fn unsealed_fixture_fails_closed_when_seal_required() {
    // The real fixture is validly signed but carries no platform countersign.
    // With the seal required (the default posture, spec 198 FR-014), the offline
    // chain still holds but the absent countersign is an error: the result is
    // rejected and the reason names the unsealed state.
    let (cert, dir) = load_fixture();
    let result = verify_certificate_with_platform(&cert, Some(&dir), None, true, None, None);
    assert!(
        !result.valid,
        "an unsealed certificate must fail closed when the seal is required; errors: {:?}",
        result.errors
    );
    assert!(
        result.errors.iter().any(|e| e.contains("UNSEALED")),
        "expected an unsealed rejection; errors: {:?}",
        result.errors
    );
}

#[test]
fn unsealed_fixture_is_a_notice_when_unsealed_allowed() {
    // The same fixture with the seal requirement lifted (--allow-unsealed): the
    // offline chain verifies and the unsealed state is a visible notice, never
    // silently equivalent to sealed.
    let (cert, dir) = load_fixture();
    let result = verify_certificate_with_platform(&cert, Some(&dir), None, false, None, None);
    assert!(
        result.valid,
        "unsealed-allowed must verify the offline chain; errors: {:?}",
        result.errors
    );
    assert!(
        result.notices.iter().any(|n| n.contains("UNSEALED")),
        "expected a verifiable-but-unsealed notice; notices: {:?}",
        result.notices
    );
}
