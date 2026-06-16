//! End-to-end test for the provenance verify core.
//!
//! The per-rule logic parity with OAP lives in the ported in-crate unit tests
//! (those are OAP's own `provenance-validator` tests, running unchanged against
//! the extracted code). This test exercises the full `audit()` path -- BRD
//! discovery, claim parsing, corpus loading, validation -- on a golden fixture
//! project, confirming the read-only retroactive audit works in the vended
//! form and renders a report.

use std::path::{Path, PathBuf};
use tenant_tail_core::provenance::{audit_with_options, render_audit_report};

fn project_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provenance-project")
}

#[test]
fn audit_finds_brd_and_parses_claims() {
    let report = audit_with_options(&project_dir(), None);

    assert!(!report.brd_not_found, "fixture BRD must be discovered");
    assert!(
        report.validation.panic_reason.is_none(),
        "audit must not panic; reason: {:?}",
        report.validation.panic_reason
    );
    assert!(
        report.validation.summary.total >= 2,
        "expected the two BR claims to be parsed, got {}",
        report.validation.summary.total
    );
    // Every parsed claim is recorded with a stable id + kind.
    assert_eq!(
        report.validation.claims.len(),
        report.validation.summary.total as usize
    );
}

#[test]
fn audit_renders_a_report() {
    let report = audit_with_options(&project_dir(), None);
    let md = render_audit_report(&report);
    assert!(!md.is_empty(), "report markdown must be non-empty");
    assert!(
        md.contains("brdNotFound"),
        "report should surface the brdNotFound flag"
    );
}

#[test]
fn audit_on_missing_project_reports_brd_not_found() {
    // A directory with no requirements/ BRD yields a well-formed report with
    // brd_not_found = true (the verb's exit-2 "not a directory" guard lives in
    // the CLI; the library is read-only and never panics on a missing BRD).
    let tmp = tempfile::tempdir().expect("tempdir");
    let report = audit_with_options(tmp.path(), None);
    assert!(report.brd_not_found);
    assert!(report.validation.panic_reason.is_none());
}
