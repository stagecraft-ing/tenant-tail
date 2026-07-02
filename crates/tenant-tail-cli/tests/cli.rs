//! CLI exit-code contract tests (spec 000 wiring over the verify cores).
//!
//! Pins the convention the verbs promise: 0 verified/ok, 1 verification failed
//! or a fail-closed flag fired, 2 usage or I/O error. These exercise the guards
//! added in the audit remediation, so a future refactor cannot silently route a
//! path typo back through the verdict path or drop the missing-BRD fail-closed
//! branch.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tenant-tail")
}

fn cert_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tenant-tail-core/tests/fixtures/cert-run/governance-certificate.json")
}

fn provenance_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tenant-tail-core/tests/fixtures/provenance-project")
}

fn code(out: &Output) -> i32 {
    out.status
        .code()
        .expect("process exited via a code, not a signal")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn missing_corpus_dir_is_usage_error_exit_2() {
    let out = Command::new(bin())
        .args(["verify-provenance", "--project"])
        .arg(provenance_fixture())
        .args(["--corpus", "/no/such/corpus/dir"])
        .output()
        .expect("spawn");
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
}

#[test]
fn missing_artifact_dir_is_usage_error_exit_2() {
    // A path typo must surface as exit 2 (usage/I-O), never exit 1 (which would
    // masquerade as certificate tamper).
    let out = Command::new(bin())
        .arg("verify-certificate")
        .arg(cert_fixture())
        .args(["--artifact-dir", "/no/such/artifact/dir"])
        .output()
        .expect("spawn");
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
}

#[test]
fn missing_brd_under_fail_on_rejected_is_exit_1() {
    // A directory that exists but carries no requirements/BRD: fail-closed mode
    // must not report a green pass for an audit that verified nothing.
    let dir = std::env::temp_dir().join(format!("tt-cli-nobrd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(bin())
        .args(["verify-provenance", "--project"])
        .arg(&dir)
        .arg("--fail-on-rejected")
        .output()
        .expect("spawn");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("no BRD"), "stderr: {}", stderr(&out));
}

#[test]
fn unsealed_certificate_with_allow_unsealed_verifies_exit_0() {
    // The parity fixture carries no platform countersign. --allow-unsealed opts
    // out of the default sealed requirement, so the offline chain verifies and
    // the unsealed state is a visible notice, not a failure.
    let out = Command::new(bin())
        .arg("verify-certificate")
        .arg(cert_fixture())
        .arg("--allow-unsealed")
        .output()
        .expect("spawn");
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("VERIFIED"),
        "verdict headline should be on stdout; stdout: {}",
        stdout(&out)
    );
}

#[test]
fn unsealed_certificate_is_rejected_by_default_exit_1() {
    // Trust-nobody posture (spec 198 FR-014): an unsealed certificate fails
    // closed by default. The offline chain still holds, but the missing platform
    // countersign is now an error, not a notice, so the verb exits 1 and the
    // INVALID headline is on stdout with the reason on stderr.
    let out = Command::new(bin())
        .arg("verify-certificate")
        .arg(cert_fixture())
        .output()
        .expect("spawn");
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("INVALID"),
        "verdict headline should be on stdout; stdout: {}",
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("UNSEALED"),
        "the rejection reason should name the unsealed state; stderr: {}",
        stderr(&out)
    );
}

#[test]
fn provenance_report_is_on_stdout_exit_0() {
    let out = Command::new(bin())
        .args(["verify-provenance", "--project"])
        .arg(provenance_fixture())
        .output()
        .expect("spawn");
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("Retroactive Provenance Audit Report"),
        "report should be on stdout; stdout: {}",
        stdout(&out)
    );
}
