//! tenant-tail: the verify-only CLI.
//!
//! Two verbs re-check a factory's run-side paperwork with no trust in the
//! producer, offline and identity-free:
//!
//!   * `verify-certificate` -- the governance certificate (Ed25519 signature,
//!     self-hash, stage artifact hashes, inter-stage manifest chain, optional
//!     platform countersign).
//!   * `verify-provenance` -- the claim-provenance audit over a produced app.
//!
//! A third verb, `verify-sbom`, is forward-declared (OAP spec 203) and joins
//! when its core exists; it is deliberately absent here, not stubbed.
//!
//! Both verbs are read-only and need no network. The cert verb's offline
//! platform-seal check reads a saved JWKS file (`--platform-jwks`); the
//! `--jwks-url` network fetch from OAP's in-tree verifier is intentionally
//! omitted (tenant-tail links no HTTP client). The provenance verb prints its
//! report to stdout rather than writing into the audited project, so the tool
//! stays read-only down to the package boundary.

use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use tenant_tail_core::certificate::{GovernanceCertificate, verify_certificate_with_platform};
use tenant_tail_core::platform_jws::PlatformJwks;
use tenant_tail_core::provenance::{audit_with_options, render_audit_report};

#[derive(Parser)]
#[command(
    name = "tenant-tail",
    version,
    about = "Verify a factory's run-side paperwork (governance certificate, provenance) with no trust in the producer. Offline, identity-free, read-only."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a governance certificate by re-deriving hashes, checking proof
    /// chain integrity (spec 102 FR-007), adjudicating the platform seal
    /// (spec 198 FR-014), checking the corpus binding by reference
    /// (spec 218 FR-003), and checking the SBOM artifact binding by re-hashing
    /// the on-disk BOM + audit artifacts (spec 203 FR-003).
    VerifyCertificate(VerifyCertificateArgs),
    /// Re-check claim provenance for a produced app (spec 121). Read-only: the
    /// markdown report is written to stdout, never into the audited project.
    VerifyProvenance(VerifyProvenanceArgs),
}

#[derive(Parser)]
struct VerifyCertificateArgs {
    /// Path to the governance-certificate.json file.
    certificate: PathBuf,

    /// Optional directory containing stage artifacts for hash re-derivation.
    #[arg(long)]
    artifact_dir: Option<PathBuf>,

    /// Path to a saved platform JWKS JSON file (offline seal verification).
    #[arg(long)]
    platform_jwks: Option<PathBuf>,

    /// Fail (exit 1) when the certificate carries no verifiable platform
    /// countersign. Default posture reports unsealed certificates as a
    /// visible notice with exit 0.
    #[arg(long)]
    require_sealed: bool,

    /// Path to a corpus attestation artifact to check the certificate's
    /// corpus binding against (spec 218). The verifier confirms the link only
    /// (claimed hash == hash of this file); the attestation's own truth is
    /// delegated to spec-spine's verify-attestation. Absent: a present binding
    /// is reported "present-but-unverified" and an absent one "unbound".
    #[arg(long)]
    corpus_attestation: Option<PathBuf>,

    /// Directory of the produced application, used to re-hash its CycloneDX
    /// BOM (`.factory/sbom.cdx.json`) and dependency-audit artifact
    /// (`.factory/audit.json`) against the certificate's SBOM artifact
    /// binding (spec 203 FR-003). The verifier never regenerates the BOM.
    /// Absent: a present binding is reported "present-but-unverified" and an
    /// absent one "unbound".
    #[arg(long)]
    sbom_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct VerifyProvenanceArgs {
    /// Project directory to re-check (its BRD + extraction corpus).
    #[arg(long)]
    project: PathBuf,

    /// Override the corpus path (typed JSON or legacy `.txt` directory).
    #[arg(long)]
    corpus: Option<PathBuf>,

    /// Exit 1 when any claim is rejected (a tenant-ward fail-closed mode; OAP's
    /// in-tree audit is a diagnostic that always exits 0). The audit verdict is
    /// identical either way; only the exit code differs.
    #[arg(long)]
    fail_on_rejected: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::VerifyCertificate(args) => verify_certificate_cmd(args),
        Command::VerifyProvenance(args) => verify_provenance_cmd(args),
    }
}

/// Write `text` to stdout, tolerating a reader that closed the pipe (e.g.
/// `tenant-tail ... | head`). Rust ignores SIGPIPE, so the default `print!`
/// PANICS (exit 101) on a broken pipe; here a broken pipe is swallowed so the
/// verb still returns its real verdict exit code, and any other write error
/// maps to the exit-2 I/O convention.
fn emit_stdout(text: &str) -> Result<(), ExitCode> {
    match std::io::stdout().write_all(text.as_bytes()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => {
            eprintln!("error: cannot write to stdout: {e}");
            Err(ExitCode::from(2))
        }
    }
}

/// Require that an optional `--flag <dir>` argument, when supplied, points at
/// an existing directory. A mistyped path is a usage/I-O error (exit 2), NOT a
/// verification failure (exit 1): the distinction keeps a path typo from
/// masquerading as certificate tamper or a silently-empty audit.
fn require_dir_if_present(flag: &str, path: Option<&std::path::Path>) -> Result<(), ExitCode> {
    if let Some(p) = path
        && !p.is_dir()
    {
        eprintln!("error: {flag} {} is not an existing directory", p.display());
        return Err(ExitCode::from(2));
    }
    Ok(())
}

fn verify_certificate_cmd(args: VerifyCertificateArgs) -> ExitCode {
    let json = match std::fs::read_to_string(&args.certificate) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", args.certificate.display());
            return ExitCode::from(2);
        }
    };
    let cert: GovernanceCertificate = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: invalid certificate JSON: {e}");
            return ExitCode::from(2);
        }
    };

    // A mistyped directory is an input error (exit 2), distinct from a
    // verification failure (exit 1): validate before the core reads under it.
    if let Err(code) = require_dir_if_present("--artifact-dir", args.artifact_dir.as_deref()) {
        return code;
    }
    if let Err(code) = require_dir_if_present("--sbom-dir", args.sbom_dir.as_deref()) {
        return code;
    }

    let jwks = match load_jwks(args.platform_jwks.as_deref()) {
        Ok(j) => j,
        Err(code) => return code,
    };

    // Spec 218 -- read the corpus attestation bytes (if supplied) so the
    // verifier can check the binding link by reference. A read failure exits 2
    // (consistent with the other input-read failures above).
    let corpus_attestation = match &args.corpus_attestation {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                eprintln!(
                    "error: cannot read --corpus-attestation {}: {e}",
                    path.display()
                );
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let result = verify_certificate_with_platform(
        &cert,
        args.artifact_dir.as_deref(),
        jwks.as_ref(),
        args.require_sealed,
        corpus_attestation.as_deref(),
        args.sbom_dir.as_deref(),
    );

    for notice in &result.notices {
        eprintln!("notice: {notice}");
    }

    // The one-line verdict is the machine-readable result and goes to stdout
    // (so a consumer capturing stdout gets it); human detail goes to stderr.
    if result.valid {
        let headline = format!(
            "governance certificate VERIFIED (pipeline: {}, status: {:?})\n",
            cert.pipeline_run_id, cert.status
        );
        if let Err(code) = emit_stdout(&headline) {
            return code;
        }
        eprintln!("  stages: {}", cert.stages.len());
        eprintln!("  proof chain records: {}", cert.proof_chain.record_count);
        if cert.certificate_hash.len() >= 16 {
            eprintln!("  certificate hash: {}", &cert.certificate_hash[..16]);
        }
        eprintln!(
            "  platform seal: {}",
            if cert.platform_countersign.is_some() {
                "present"
            } else {
                "ABSENT (unsealed)"
            }
        );
        ExitCode::SUCCESS
    } else {
        let headline = format!(
            "governance certificate INVALID ({} error(s))\n",
            result.errors.len()
        );
        if let Err(code) = emit_stdout(&headline) {
            return code;
        }
        for err in &result.errors {
            eprintln!("  - {err}");
        }
        ExitCode::from(1)
    }
}

/// Read and parse a saved JWKS file. `None` path -> `Ok(None)` (offline,
/// unsealed-or-unadjudicated posture). A read/parse failure exits 2.
fn load_jwks(path: Option<&std::path::Path>) -> Result<Option<PlatformJwks>, ExitCode> {
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("error: cannot read --platform-jwks {}: {e}", path.display());
        ExitCode::from(2)
    })?;
    let jwks: PlatformJwks = serde_json::from_str(&raw).map_err(|e| {
        eprintln!(
            "error: --platform-jwks {} is not a JWKS JSON: {e}",
            path.display()
        );
        ExitCode::from(2)
    })?;
    Ok(Some(jwks))
}

fn verify_provenance_cmd(args: VerifyProvenanceArgs) -> ExitCode {
    if !args.project.is_dir() {
        eprintln!(
            "error: project directory not found or not a directory: {}",
            args.project.display()
        );
        return ExitCode::from(2);
    }
    // A mistyped `--corpus` must not silently degrade to an empty corpus and a
    // green exit: treat a missing override directory as an input error.
    if let Err(code) = require_dir_if_present("--corpus", args.corpus.as_deref()) {
        return code;
    }

    let report = audit_with_options(&args.project, args.corpus.as_deref());

    // The markdown report goes to stdout (read-only: we never write into the
    // audited project); the summary goes to stderr. The stdout write tolerates
    // a closed pipe rather than panicking.
    if let Err(code) = emit_stdout(&render_audit_report(&report)) {
        return code;
    }

    let s = &report.validation.summary;
    eprintln!(
        "provenance audit: total={} derived={} assumption={} rejected={} \
         synthesizedCorpus={} brdNotFound={} corpusEmpty={} corpusSource={:?}",
        s.total,
        s.derived_count,
        s.assumption_count,
        s.rejected_count,
        report.synthesized_corpus,
        report.brd_not_found,
        report.corpus_empty,
        report.corpus_source,
    );

    if let Some(reason) = &report.validation.panic_reason {
        eprintln!("error: validator panic (fail-closed) -- {reason}");
        return ExitCode::from(1);
    }
    // Fail-closed mode must not report a green pass for an audit that verified
    // nothing: a missing BRD means there were no claims to check at all.
    if args.fail_on_rejected && report.brd_not_found {
        eprintln!(
            "provenance verification FAILED: no BRD found under the project; nothing was \
             verified (--fail-on-rejected)"
        );
        return ExitCode::from(1);
    }
    if args.fail_on_rejected && s.rejected_count > 0 {
        eprintln!(
            "provenance verification FAILED: {} rejected claim(s) (--fail-on-rejected)",
            s.rejected_count
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
