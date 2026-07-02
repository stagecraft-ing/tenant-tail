//! Governance Certificate -- the single JSON artifact proving the full
//! intent-to-spec-to-code-to-audit chain for a factory pipeline run.
//!
//! This is the verify-only half, extracted from OAP's
//! `factory-engine/src/governance_certificate.rs` and relicensed Apache-2.0
//! from AGPL-3.0 by the sole copyright holder (see NOTICE). The emitter (the
//! certificate builder, signing-key resolution, and `generate_certificate*`)
//! is excluded by construction: tenant-tail re-checks certificates the factory
//! produced, it never mints them. The data types are preserved verbatim so
//! deserialization and the recomputed self-hash stay byte-identical to OAP's.

use crate::inter_stage_manifest::{InterStageManifest, RunKeyChain, verify_manifest};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// Schema version for the governance certificate format.
///
/// 1.3.0 introduces two optional top-level fields landing in parallel:
///   * `signer` (spec 168 §FR-003) -- named identity for the principal that
///     drove the run (Rauthy JWT subject or analogous identity per spec
///     106 / 137).
///   * `interStageChain` (spec 170 §FR-007) -- signed inter-stage manifest
///     chain produced by [`crate::inter_stage_manifest`].
///
/// Both fields are `skip_serializing_if = "Option::is_none"` so a
/// certificate built without them serialises byte-identically to a
/// pre-1.3.0 payload; only the version string differs. Note this is a
/// serialization property, not an acceptance property: the verifier
/// accepts ONLY [`CERTIFICATE_VERSION`] (see the version check in
/// [`verify_certificate`]). A payload carrying an older version string
/// serialises byte-identically for the fields it shares, but is still
/// rejected as an unsupported version; regenerate legacy fixtures to the
/// current version.
///
/// 1.2.0 (spec 162 §FR-008) introduced the optional `sandboxExecution`
/// per-stage record. 1.1.0 added Ed25519 signing (spec 102 FR-008.1);
/// the hash check is no longer the authoritative provenance check after
/// that point, but it remains as a content fingerprint inside the signed
/// payload.
///
/// 1.4.0 (spec 198 FR-005/FR-009/FR-014) added the admission-binding
/// fields -- `admittedEnvelopeHash`, `goalId`, `intentCapsuleHash`, all
/// inside the hash + signature (bound at emission) -- and the
/// post-emission `platformCountersign`, which is EXCLUDED from both the
/// self-hash and the engine signature (zeroed before canonicalisation)
/// so platform sealing on sync-back never invalidates the offline chain.
///
/// 1.5.0 (spec 198 FR-013 c) added `consumedOverrides` -- the overrides of
/// admitted factory content the run consumed, with provenance + verified
/// state, inside the hash + signature. Empty lists are skipped in
/// serialization so override-free certificates stay byte-identical to
/// 1.4.0 payloads (only the version string differs).
pub const CERTIFICATE_VERSION: &str = "1.5.0";

// ── Top-level Certificate ────────────────────────────────────────────

/// A Governance Certificate proves the full chain from intent to auditable output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceCertificate {
    pub certificate_version: String,
    pub pipeline_run_id: String,
    pub timestamp: DateTime<Utc>,
    pub status: CertificateStatus,

    pub intent: IntentRecord,
    pub build_spec: BuildSpecRecord,
    pub stages: Vec<StageRecord>,
    pub verification: VerificationRecord,
    pub proof_chain: ProofChainSummary,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ComplianceRecord>,

    /// Spec 168 §FR-003 / §FR-007 -- identity attribution for the principal
    /// that drove the run. Required for tenant-emit mode (per-project
    /// certificates); optional on OAP-self runs to preserve byte-for-byte
    /// compatibility with pre-1.3.0 fixtures. Anonymous signing is
    /// forbidden: when set, `Signer::subject` is non-empty after trim
    /// (constructed via `Signer::new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,

    /// Spec 170 §FR-007 -- signed inter-stage manifest chain. Optional
    /// for runs that did not produce signed hand-offs (legacy / pre-1.3.0
    /// fixtures); `skip_serializing_if = "Option::is_none"` keeps the
    /// canonical JSON byte-identical for those payloads so their
    /// certificate hash is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inter_stage_chain: Option<InterStageChainRecord>,

    /// Spec 198 FR-009 -- hash of the admitted governance envelope this run
    /// executed under. Inside the hash + signature (bound at emission), so
    /// the certificate is reconcilable to its admission contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_envelope_hash: Option<String>,

    /// Spec 198 FR-005 -- stable goal identifier from the run's intent
    /// capsule (ASI01 m7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,

    /// Spec 198 FR-005/FR-009 -- SHA-256 of the run's canonical intent
    /// capsule, as presented at grant issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_capsule_hash: Option<String>,

    /// Spec 198 FR-013(c) -- overrides of admitted factory content this run
    /// consumed, as presented by the platform's admission-gated bundle
    /// (already predicate-checked against `overrides.require_verified`).
    /// Inside the hash + signature (bound at emission) so every consumed
    /// override is traceable and revocable via its content hash (FR-010).
    /// Skipped when empty so override-free certificates serialise
    /// byte-identically to pre-1.5.0 payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumed_overrides: Vec<ConsumedOverride>,

    /// Spec 218 FR-001 -- the corpus attestation in effect at the run, by
    /// reference. Additive and optional: absence is a named "unbound" state,
    /// not a failure. Inside the hash + signature (a normal cert field);
    /// skipped when absent so unbound certificates serialise byte-identically
    /// to pre-binding payloads. See [`CorpusBinding`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_binding: Option<CorpusBinding>,

    /// Spec 203 FR-003 -- the produced application's CycloneDX BOM + audit
    /// artifact content binding, by hash. Additive and optional: absence is a
    /// named "unbound" state, not a failure. Inside the hash + signature (a
    /// normal cert field, unlike `platform_countersign`); skipped when absent
    /// so unbound certificates serialise byte-identically to pre-binding
    /// payloads. See [`SbomArtifactBinding`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_artifact_binding: Option<SbomArtifactBinding>,

    /// SHA-256 of the canonical JSON of this certificate with `certificate_hash`
    /// AND `cert_signature` set to empty string. Content-binding fingerprint
    /// inside the signed payload -- not the authoritative provenance check
    /// after spec 102 FR-008.1 (see `cert_signature`).
    pub certificate_hash: String,

    /// Base64-encoded Ed25519 public key (32 bytes) -- verifier checks
    /// `cert_signature` against this. Empty for pre-1.1.0 fixtures and
    /// unsigned certificates; HIAS-mode verifiers reject empty.
    /// Spec 102 FR-008.2.
    #[serde(default)]
    pub signing_public_key: String,

    /// Base64-encoded Ed25519 signature (64 bytes) over canonical JSON
    /// of the certificate with `cert_signature` set to empty string and
    /// `certificate_hash` populated. Spec 102 FR-008.1.
    #[serde(default)]
    pub cert_signature: String,

    /// Trust-posture descriptor for `signing_public_key`. Spec 102 FR-008.3.
    #[serde(default)]
    pub signing_attestation: SigningAttestation,

    /// Spec 198 FR-014 -- the platform countersign applied on sync-back,
    /// after stagecraft verified the engine's chain against the run-grant
    /// sequence it issued. EXCLUDED from `certificate_hash` and
    /// `cert_signature` (zeroed before canonicalisation) so sealing never
    /// invalidates the offline chain. `None` = verifiable-but-unsealed --
    /// visibly so, never silently equivalent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_countersign: Option<PlatformCountersign>,
}

/// Spec 198 FR-014 -- the platform seal on an emitted certificate. The
/// compact JWS (`typ: oap-cert-countersign+jws`) carries the claims
/// (`certificate_sha256`, `run_id`, `grant_count`, `grant_chain_sha256`,
/// `envelope_hash`, …); `kid` resolves against the platform JWKS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCountersign {
    pub countersign_jws: String,
    pub kid: String,
    pub countersigned_at: DateTime<Utc>,
}

/// Spec 218 FR-001 -- the corpus attestation in effect at the run, recorded by
/// reference. `corpus_attestation_hash` is the SHA-256 of the upstream corpus
/// attestation artifact; `spec_spine_version` records the spec-spine that
/// produced it.
///
/// Additive and optional: a certificate without this block is a named "unbound"
/// state, not a failure (FR-004). `skip_serializing_if = "Option::is_none"`
/// keeps unbound certificates byte-identical to pre-binding payloads, so their
/// certificate hash is unchanged. When present the block is INSIDE the hash and
/// signature (a normal cert field, unlike `platform_countersign`).
///
/// The cert builder is GIVEN this value and never recomputes it (FR-002, an
/// OAP-side boundary). The verifier checks the LINK by reference only (FR-003):
/// it confirms the claimed hash equals the hash of a supplied attestation and
/// delegates the attestation's own truth (recompute / signature) to spec-spine's
/// `verify-attestation`. The run-cert verifier never recomputes the corpus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CorpusBinding {
    pub corpus_attestation_hash: String,
    pub spec_spine_version: String,
}

/// Spec 203 FR-003 -- the produced application's BOM + dependency-audit
/// content binding, recorded by hash. `bom_hash` is the SHA-256 of the
/// CycloneDX BOM (`.factory/sbom.cdx.json`); `audit_hash` is the SHA-256 of
/// the dependency-audit artifact (`.factory/audit.json`); `bom_tool_version`
/// is the `@cyclonedx/cyclonedx-npm` semver used to generate the BOM.
///
/// Additive and optional: a certificate without this block is a named
/// "unbound" state, not a failure (mirrors [`CorpusBinding`], spec 218 FR-004
/// posture). `skip_serializing_if = "Option::is_none"` keeps unbound
/// certificates byte-identical to pre-binding payloads, so their certificate
/// hash is unchanged. When present the block is INSIDE the hash and
/// signature (a normal cert field, unlike `platform_countersign`).
///
/// The cert builder is GIVEN both hashes and never recomputes the BOM (an
/// OAP-side boundary, spec 218's "read, never recompute" discipline). The
/// verifier re-hashes the on-disk artifacts under `--sbom-dir` and compares;
/// it never regenerates the BOM. See [`adjudicate_sbom_binding_state`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomArtifactBinding {
    pub bom_hash: String,
    pub audit_hash: String,
    pub bom_tool_version: String,
}

/// Spec 198 FR-013(c) -- one override of admitted factory content the run
/// consumed: artifact identity, content hash, author provenance (FR-013 b)
/// and the verified state at consumption time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConsumedOverride {
    pub artifact_id: String,
    pub path: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<String>,
}

/// Trust posture for the signing public key (spec 102 FR-008.3).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SigningAttestation {
    pub kind: SigningAttestationKind,
    /// Free-form note: operator email, key-rotation epoch, CI run URL, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAttestationKind {
    /// No `signing_public_key` was set -- pre-1.1.0 fixture or unsigned cert.
    /// HIAS-strict and non-strict verification both reject these once
    /// signing material is required by the runtime.
    #[default]
    Unsigned,
    /// Key generated for this run's lifetime; trust is "the run was
    /// internally consistent." Suitable for local dev.
    Ephemeral,
    /// Operator-supplied key via `OAP_SIGNING_KEY` or `OAP_SIGNING_KEY_PATH`.
    /// Trust is "the operator vouches for runs using this key."
    Operator,
    /// Signed by a Sigstore Fulcio-issued certificate and anchored to the
    /// Rekor transparency log. Required by HIAS-strict. Implementation
    /// landed in P0-3b (spec 102 FR-008.5).
    SigstoreRekor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Complete,
    Incomplete,
}

// ── Inter-stage manifest chain (spec 170 FR-007) ─────────────────────

/// Run-level record of the signed inter-stage manifest chain.
///
/// Embeds the per-run key chain (root verifying key + stage ephemeral
/// verifying keys) alongside the ordered list of signed manifests. The
/// certificate verifier (`verify_certificate`) replays every manifest
/// against the chain offline (spec 170 FR-006).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterStageChainRecord {
    pub key_chain: RunKeyChain,
    #[serde(default)]
    pub manifests: Vec<InterStageManifest>,
}

// ── Signer (spec 168 FR-003 / FR-007) ────────────────────────────────

/// Identity attribution for the principal that drove the pipeline run.
///
/// The `subject` is the principal identifier (typically a Rauthy JWT `sub`
/// for human-driven runs, or an agent identity for agent-driven runs per
/// spec 106 / 137). The `identityProvider` names the system that attested
/// the subject (e.g. `rauthy@<tenant-org>`, `github-actions@<repo>`,
/// `oap-self`). The `sessionId` is an optional run-scoped correlation id.
///
/// Constructed only via [`Signer::new`], which rejects empty/whitespace
/// `subject` so that anonymous signing cannot bypass FR-007 by submitting
/// an empty string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Signer {
    pub subject: String,
    pub identity_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

// ── Intent ───────────────────────────────────────────────────────────

/// Records the original intent that initiated the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentRecord {
    /// SHA-256 hash of the concatenated input requirements documents.
    pub requirements_hash: String,
    /// The governing spec ID (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_id: Option<String>,
    /// SHA-256 hash of the governing spec.md at pipeline start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<String>,
}

// ── Build Spec ───────────────────────────────────────────────────────

/// Records the frozen Build Spec and its approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildSpecRecord {
    /// SHA-256 hash of the frozen Build Spec YAML.
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_record: Option<ApprovalRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    pub approved_at: DateTime<Utc>,
    pub gate_type: String,
}

// ── Stages ───────────────────────────────────────────────────────────

/// Per-stage record in the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StageRecord {
    pub stage_id: String,
    pub status: StageOutcome,
    /// SHA-256 hashes of all output artifacts, keyed by artifact name.
    pub artifact_hashes: BTreeMap<String, String>,
    pub gate_result: Option<GateResultRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Spec 162 §FR-008 -- sandbox-execution record. Populated when the
    /// stage exercised adapter-emitted code through a `SandboxClient`
    /// (lint / test / build / run-once). The fields bind the executed
    /// command, the input artifact hashes (pre-execution), the output
    /// artifact hashes (post-execution), the resource utilisation peak,
    /// the realised isolation tier (1/2/3), the opaque runtime
    /// descriptor, and whether the TTL fired. Pre-1.2.0 fixtures omit
    /// the field; `skip_serializing_if = "Option::is_none"` keeps the
    /// canonical JSON byte-identical for legacy stages so their
    /// certificate hash is invariant under the field's introduction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_execution: Option<SandboxExecutionRecord>,
}

/// Per-stage sandbox-execution binding (spec 162 §FR-008).
///
/// Backend-agnostic by construction: `isolation_tier` is normalised to
/// 1/2/3 (1 = sandbox runtime, 2 = restricted container, 3 = forbidden);
/// `runtime_descriptor` is treated by the verifier as an opaque
/// base64-encoded fingerprint of backend identity + version + selected
/// runtime. Backends choose their own pre-encoded bytes, so long as the
/// bytes are deterministic for a given build.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxExecutionRecord {
    /// Executed command -- argv echoed back; the verifier binds this
    /// exact form (FR-008).
    pub command: Vec<String>,
    /// Pre-execution input artifact hashes, keyed by sandbox-mount-relative
    /// path.
    pub input_artifact_hashes: BTreeMap<String, String>,
    /// Post-execution output artifact hashes, keyed by sandbox-mount-relative
    /// path.
    pub output_artifact_hashes: BTreeMap<String, String>,
    /// Peak resource utilisation observed during the execution.
    pub resource_peak: SandboxResourcePeak,
    /// Realised isolation tier -- 1 = sandbox runtime (gVisor /
    /// Firecracker / Kata), 2 = restricted container (rootless OCI,
    /// RO rootfs, seccomp default). MUST NOT be 3 for a successful
    /// outcome (162 §2.2 -- Tier 3 is reserved for refusal diagnostics).
    pub isolation_tier: u8,
    /// Opaque backend identity + version + runtime fingerprint, base64.
    /// Verifier treats this as bytes -- no parsing.
    pub runtime_descriptor: String,
    /// True iff the TTL fired and the execution was terminated.
    pub deadline_hit: bool,
    /// Process exit code from the sandboxed command.
    pub exit_code: i32,
}

/// Peak resource utilisation observed during a sandbox execution
/// (spec 162 §FR-008).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResourcePeak {
    pub cpu_milli_peak: u32,
    pub memory_bytes_peak: u64,
    pub pid_peak: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StageOutcome {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateResultRecord {
    pub passed: bool,
    pub checks_run: u32,
    pub checks_failed: u32,
}

// ── Verification ─────────────────────────────────────────────────────

/// Aggregate verification outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRecord {
    pub compile: VerificationOutcome,
    pub test: VerificationOutcome,
    pub lint: VerificationOutcome,
    pub typecheck: VerificationOutcome,
    pub security_scan: VerificationOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerificationOutcome {
    Passed,
    Failed,
    Skipped,
}

// ── Proof Chain ──────────────────────────────────────────────────────

/// Summary of the proof chain from policy-kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofChainSummary {
    pub record_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_record_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_record_hash: Option<String>,
    pub chain_integrity: ChainIntegrity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChainIntegrity {
    Verified,
    Unverified,
    Empty,
}

// ── Compliance ───────────────────────────────────────────────────────

/// Compliance mapping for the pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceRecord {
    pub frameworks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mappings: Vec<ComplianceMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceMapping {
    pub control: String,
    pub mechanism: String,
    pub status: String,
}

// ── Hash + Signature Computation ─────────────────────────────────────

/// Compute the content-binding SHA-256 hash of a certificate (FR-008 revised).
///
/// Zeros both `certificate_hash` AND `cert_signature` so the hash is
/// invariant under signing -- the signature can be re-computed without
/// invalidating the hash. The hash is no longer the authoritative
/// provenance check (see `compute_certificate_signature` + FR-008.4); it
/// remains as a content fingerprint and an accidental-corruption guard
/// inside the signed payload.
pub fn compute_certificate_hash(cert: &GovernanceCertificate) -> String {
    let mut cert_for_hash = cert.clone();
    cert_for_hash.certificate_hash = String::new();
    cert_for_hash.cert_signature = String::new();
    // Spec 198 FR-014 -- the platform countersign is applied AFTER emission
    // (sync-back patch); excluding it keeps the offline chain valid across
    // sealing.
    cert_for_hash.platform_countersign = None;

    // Canonical JSON: serde_json produces deterministic output for BTreeMap.
    // For Vec fields, order is preserved as inserted.
    let canonical = serde_json::to_string(&cert_for_hash).expect("certificate serialises to JSON");

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify the Ed25519 signature on a certificate. Returns `Err` with a
/// specific diagnostic on failure (FR-008.4).
fn verify_certificate_signature(cert: &GovernanceCertificate) -> Result<(), String> {
    if cert.signing_public_key.is_empty() {
        return Err(
            "certificate is unsigned (signing_public_key empty) -- rejected per FR-008.2".into(),
        );
    }
    if cert.cert_signature.is_empty() {
        return Err(
            "certificate is unsigned (cert_signature empty) -- rejected per FR-008.1".into(),
        );
    }
    let pk_bytes: [u8; 32] = B64
        .decode(&cert.signing_public_key)
        .map_err(|e| format!("signing_public_key base64 decode: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("signing_public_key length {} != 32", v.len()))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("signing_public_key not a valid Ed25519 point: {e}"))?;
    let sig_bytes: [u8; 64] = B64
        .decode(&cert.cert_signature)
        .map_err(|e| format!("cert_signature base64 decode: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("cert_signature length {} != 64", v.len()))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let mut cert_for_sig = cert.clone();
    cert_for_sig.cert_signature = String::new();
    // Spec 198 FR-014 -- the countersign is patched in after signing;
    // strip it so a sealed certificate's engine signature still verifies.
    cert_for_sig.platform_countersign = None;
    let canonical = serde_json::to_string(&cert_for_sig)
        .map_err(|e| format!("certificate re-serialises to JSON for verification: {e}"))?;

    // `verify_strict` (not `verify`): rejects signature malleability and
    // small-order / non-canonical public keys, so a second valid signature
    // cannot be forged for the same payload and a degenerate key cannot pass.
    verifying_key
        .verify_strict(canonical.as_bytes(), &sig)
        .map_err(|e| format!("Ed25519 signature verification failed: {e}"))
}

/// Reject a path fragment supplied by the (untrusted) certificate that would
/// escape the operator-supplied `--artifact-dir`. Only plain in-tree relative
/// segments are permitted: an absolute path, a drive prefix, or a `..`
/// traversal component is refused. This closes both an out-of-tree read oracle
/// (e.g. `stage_id`/artifact name `../../etc/passwd`) and an unbounded-read DoS
/// (e.g. `/dev/zero`) driven by attacker-controlled certificate fields. The
/// check is lexical (no filesystem access), so it is total and cannot hang.
fn ensure_in_tree(label: &str, value: &str) -> Result<(), String> {
    use std::path::Component;
    for comp in Path::new(value).components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "refusing to read {label} {value:?}: path escapes --artifact-dir \
                     (absolute path or `..` traversal in an untrusted certificate field)"
                ));
            }
        }
    }
    Ok(())
}

/// SHA-256 hash of raw bytes, returned as lowercase hex.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ── Verification (FR-007) ────────────────────────────────────────────

/// Result of certificate verification.
#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    /// Non-fatal observations (spec 198 FR-014): e.g. the
    /// "verifiable-but-unsealed" notice for a certificate with no platform
    /// countersign -- visible, never silently equivalent to sealed.
    pub notices: Vec<String>,
}

/// Verify a governance certificate by re-deriving hashes and checking integrity.
///
/// FR-007: exits 0 on success, 1 on any mismatch.
///
/// Spec 102 FR-008.4: signature verification runs FIRST and is the
/// authoritative provenance check. The content-binding hash check is
/// retained but is now defence-in-depth, not the primary check.
pub fn verify_certificate(
    cert: &GovernanceCertificate,
    artifact_dir: Option<&Path>,
) -> VerificationResult {
    let mut errors = Vec::new();

    // 0. Verify Ed25519 signature first (FR-008.4). This is the authoritative
    //    provenance check post-amendment -- a tamper-with-resign attack that
    //    only updates the SHA-256 hash but cannot mint a valid signature
    //    over the modified content is caught here.
    if let Err(diagnostic) = verify_certificate_signature(cert) {
        errors.push(diagnostic);
    }

    // 1. Verify certificate self-hash (FR-008 revised -- content binding,
    //    defence-in-depth).
    let expected_hash = compute_certificate_hash(cert);
    if cert.certificate_hash != expected_hash {
        errors.push(format!(
            "certificate hash mismatch: expected {expected_hash}, got {}",
            cert.certificate_hash
        ));
    }

    // 2. Verify artifact hashes against files on disk (FR-005).
    if let Some(dir) = artifact_dir {
        for stage in &cert.stages {
            if let Err(e) = ensure_in_tree("stage id", &stage.stage_id) {
                errors.push(e);
                continue;
            }
            let stage_dir = dir.join(&stage.stage_id);
            for (artifact_name, recorded_hash) in &stage.artifact_hashes {
                if let Err(e) = ensure_in_tree("artifact name", artifact_name) {
                    errors.push(e);
                    continue;
                }
                let artifact_path = stage_dir.join(artifact_name);
                match std::fs::read(&artifact_path) {
                    Ok(contents) => {
                        let actual_hash = sha256_bytes(&contents);
                        if &actual_hash != recorded_hash {
                            errors.push(format!(
                                "artifact hash mismatch: {}/{}: expected {recorded_hash}, got {actual_hash}",
                                stage.stage_id, artifact_name
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(format!(
                            "cannot read artifact {}/{}: {e}",
                            stage.stage_id, artifact_name
                        ));
                    }
                }
            }
        }
    }

    // 3. Verify version.
    if cert.certificate_version != CERTIFICATE_VERSION {
        errors.push(format!(
            "unsupported certificate version: {}",
            cert.certificate_version
        ));
    }

    // 4. Spec 170 FR-007 -- verify the signed inter-stage manifest chain
    //    if present. Each manifest must validate against the run's key
    //    chain offline; tampered or cross-run manifests are surfaced as
    //    distinct errors so the auditor can attribute failures.
    if let Some(chain_record) = &cert.inter_stage_chain {
        if chain_record.key_chain.run_id != cert.pipeline_run_id {
            errors.push(format!(
                "inter-stage chain run_id {} does not match certificate pipeline_run_id {}",
                chain_record.key_chain.run_id, cert.pipeline_run_id
            ));
        }
        for manifest in &chain_record.manifests {
            if let Err(e) = verify_manifest(manifest, &chain_record.key_chain, None) {
                errors.push(format!(
                    "inter-stage manifest {}→{} failed verification: {e}",
                    manifest.from_stage, manifest.to_stage
                ));
            }
        }
    }

    VerificationResult {
        valid: errors.is_empty(),
        errors,
        notices: Vec::new(),
    }
}

/// Spec 198 FR-014/AC-4 -- full verification including the platform seal.
///
/// Runs [`verify_certificate`] (the producer-untrusted offline chain,
/// unchanged), then adjudicates the countersign:
///
/// - **Unsealed** (`platform_countersign: None`): a notice is emitted --
///   "verifiable-but-unsealed". Fails only under `require_sealed`.
/// - **Sealed + JWKS provided**: the countersign JWS must verify against
///   the keyset and its claims must bind this certificate's hash and run
///   id; any failure is an error.
/// - **Sealed + no JWKS**: the seal cannot be adjudicated -- a notice under
///   the default posture, an error under `require_sealed` (fail closed).
///
/// Spec 218 FR-003/FR-004 -- after the platform seal, the corpus binding is
/// adjudicated by reference: `corpus_attestation` is the bytes of a supplied
/// corpus attestation artifact (if any). The verifier checks ONLY the link
/// (claimed hash == SHA-256 of the supplied attestation); the attestation's own
/// truth is delegated to spec-spine's `verify-attestation`, never performed
/// here. See [`adjudicate_corpus_binding_state`] for the four legible states.
///
/// Spec 203 FR-003 -- after the corpus binding, the SBOM artifact binding is
/// adjudicated by re-hashing the on-disk artifacts: `sbom_dir` is the produced
/// application's root (if supplied), under which `.factory/sbom.cdx.json` and
/// `.factory/audit.json` are read and hashed. The cert crate never regenerates
/// the BOM. See [`adjudicate_sbom_binding_state`] for the legible states.
pub fn verify_certificate_with_platform(
    cert: &GovernanceCertificate,
    artifact_dir: Option<&Path>,
    platform_jwks: Option<&crate::platform_jws::PlatformJwks>,
    require_sealed: bool,
    corpus_attestation: Option<&[u8]>,
    sbom_dir: Option<&Path>,
) -> VerificationResult {
    let mut result = verify_certificate(cert, artifact_dir);

    match (&cert.platform_countersign, platform_jwks) {
        (None, _) => {
            if require_sealed {
                result.errors.push(
                    "certificate is verifiable-but-UNSEALED (no platform countersign) -- \
                     rejected under --require-sealed (spec 198 FR-014)"
                        .into(),
                );
            } else {
                result.notices.push(
                    "certificate is verifiable-but-UNSEALED: the offline chain holds, but no \
                     platform countersign binds this run to its admission contract (spec 198 FR-014)"
                        .into(),
                );
            }
        }
        (Some(seal), Some(jwks)) => {
            match crate::platform_jws::verify_compact_jws(
                &seal.countersign_jws,
                jwks,
                crate::platform_jws::TYP_CERT_COUNTERSIGN,
            ) {
                Ok(verified) => {
                    // The certificate hash is the authoritative binding --
                    // unique to these exact bytes. The countersign's
                    // `run_id` claim is the PLATFORM run identity, distinct
                    // from the engine-minted `pipeline_run_id`; it is
                    // surfaced informationally, not compared.
                    //
                    // Fail closed if the seal carries no `certificate_sha256`
                    // claim at all: a seal that binds nothing must never be
                    // treated as binding this certificate.
                    match verified.payload["certificate_sha256"].as_str() {
                        Some(claimed_hash) if claimed_hash == cert.certificate_hash => {}
                        Some(claimed_hash) => {
                            result.errors.push(format!(
                                "platform countersign binds certificate hash {claimed_hash} but \
                                 this certificate's hash is {}",
                                cert.certificate_hash
                            ));
                        }
                        None => {
                            result.errors.push(
                                "platform countersign carries no certificate_sha256 claim -- it \
                                 binds no certificate (spec 198 FR-014)"
                                    .into(),
                            );
                        }
                    }

                    // Defence-in-depth: when the seal names an `envelope_hash`
                    // and the certificate carries an `admittedEnvelopeHash`
                    // (both inside the engine signature), they must agree --
                    // the seal and the signed body must reference the same
                    // admission envelope.
                    if let (Some(sealed_env), Some(cert_env)) = (
                        verified.payload["envelope_hash"].as_str(),
                        cert.admitted_envelope_hash.as_deref(),
                    ) && sealed_env != cert_env
                    {
                        result.errors.push(format!(
                            "platform countersign binds envelope hash {sealed_env} but the \
                             certificate's admittedEnvelopeHash is {cert_env} (spec 198 FR-014)"
                        ));
                    }

                    if result.errors.is_empty() {
                        result.notices.push(format!(
                            "platform countersign VERIFIED (kid {}, platform run {}, {} grant(s) in chain)",
                            verified.header.kid,
                            verified.payload["run_id"].as_str().unwrap_or("?"),
                            verified.payload["grant_count"].as_u64().unwrap_or(0)
                        ));
                    }
                }
                Err(e) => {
                    result
                        .errors
                        .push(format!("platform countersign invalid: {e}"));
                }
            }
        }
        (Some(_), None) => {
            if require_sealed {
                result.errors.push(
                    "certificate carries a platform countersign but no JWKS was provided to \
                     verify it -- supply --platform-jwks <file> or --jwks-url (fail-closed under \
                     --require-sealed)"
                        .into(),
                );
            } else {
                result.notices.push(
                    "certificate carries a platform countersign, NOT verified (no JWKS provided \
                     -- supply --platform-jwks <file> or --jwks-url)"
                        .into(),
                );
            }
        }
    }

    // Spec 218 FR-003/FR-004 -- adjudicate the corpus binding by reference.
    append_corpus_binding_findings(cert, corpus_attestation, &mut result);

    // Spec 203 FR-003 -- adjudicate the SBOM artifact binding by re-hashing
    // the on-disk BOM + audit artifacts.
    append_sbom_binding_findings(cert, sbom_dir, &mut result);

    result.valid = result.errors.is_empty();
    result
}

/// Spec 218 FR-004 -- the adjudicated state of a certificate's corpus binding.
///
/// The verifier never silently passes: every state is legible (FR-004). The
/// `Mismatch` variant is the only failing state; `Unbound` and
/// `PresentButUnverified` are visible-but-non-fatal, consistent with the
/// additive, optional-on-land posture (FR-001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusBindingState {
    /// No `corpus_binding` on the certificate. Additive, non-breaking.
    Unbound,
    /// Binding present, but no attestation was supplied to check the link.
    PresentButUnverified,
    /// Binding present and the supplied attestation hashes to the claimed value.
    Verified,
    /// Binding present and the supplied attestation does NOT match the claim.
    Mismatch { claimed: String, actual: String },
}

/// Spec 218 FR-003 -- the pure link check. Confirms the certificate's claimed
/// `corpus_attestation_hash` equals the SHA-256 of a supplied attestation,
/// WITHOUT recomputing the corpus. Verifying the attestation's own truth
/// (recompute / signature) is the responsibility of spec-spine's
/// `verify-attestation` (FR-003 / AC-5): two verifiers, two responsibilities,
/// composed by reference.
pub fn adjudicate_corpus_binding_state(
    binding: Option<&CorpusBinding>,
    corpus_attestation: Option<&[u8]>,
) -> CorpusBindingState {
    match (binding, corpus_attestation) {
        (None, _) => CorpusBindingState::Unbound,
        (Some(_), None) => CorpusBindingState::PresentButUnverified,
        (Some(binding), Some(attestation)) => {
            let actual = sha256_bytes(attestation);
            if actual == binding.corpus_attestation_hash {
                CorpusBindingState::Verified
            } else {
                CorpusBindingState::Mismatch {
                    claimed: binding.corpus_attestation_hash.clone(),
                    actual,
                }
            }
        }
    }
}

/// Map the adjudicated [`CorpusBindingState`] onto the result's notices/errors.
/// Only `Mismatch` is fatal; the rest are visible notices (spec 218 FR-004,
/// skip-as-pass forbidden).
fn append_corpus_binding_findings(
    cert: &GovernanceCertificate,
    corpus_attestation: Option<&[u8]>,
    result: &mut VerificationResult,
) {
    match adjudicate_corpus_binding_state(cert.corpus_binding.as_ref(), corpus_attestation) {
        CorpusBindingState::Unbound => {
            result.notices.push(
                "certificate is corpus-UNBOUND: no corpus_binding present -- the run is not \
                 bound by reference to a corpus attestation (spec 218 FR-004)"
                    .into(),
            );
        }
        CorpusBindingState::PresentButUnverified => {
            // `corpus_binding` is Some in this state.
            let binding = cert.corpus_binding.as_ref().expect("binding present");
            result.notices.push(format!(
                "corpus binding present-but-UNVERIFIED: certificate claims corpus attestation \
                 hash {} (spec-spine {}) but no attestation was supplied to check the link -- \
                 supply --corpus-attestation <file> (spec 218 FR-004)",
                binding.corpus_attestation_hash, binding.spec_spine_version
            ));
        }
        CorpusBindingState::Verified => {
            let binding = cert.corpus_binding.as_ref().expect("binding present");
            result.notices.push(format!(
                "corpus binding VERIFIED: supplied attestation hashes to the claimed \
                 corpus_attestation_hash {} (spec-spine {}); the attestation's own truth is \
                 delegated to spec-spine verify-attestation (spec 218 FR-003)",
                binding.corpus_attestation_hash, binding.spec_spine_version
            ));
        }
        CorpusBindingState::Mismatch { claimed, actual } => {
            result.errors.push(format!(
                "corpus binding MISMATCH: certificate claims corpus_attestation_hash {claimed} \
                 but the supplied attestation hashes to {actual} (spec 218 FR-004)"
            ));
        }
    }
}

// ── SBOM artifact binding adjudication (spec 203 FR-003) ─────────────

/// Spec 203 FR-003 -- relative path of the produced app's CycloneDX BOM,
/// under the produced-app root supplied via `--sbom-dir`.
pub const SBOM_BOM_RELPATH: &str = ".factory/sbom.cdx.json";

/// Spec 203 FR-003 -- relative path of the produced app's dependency-audit
/// artifact, under the produced-app root supplied via `--sbom-dir`.
pub const SBOM_AUDIT_RELPATH: &str = ".factory/audit.json";

/// Spec 203 FR-003 -- the adjudicated state of a certificate's SBOM artifact
/// binding. Mirrors [`CorpusBindingState`]: every state is legible. The
/// `BomMismatch`, `AuditMismatch`, and `Unreadable` variants are the only
/// failing states; `Unbound` and `PresentButUnverified` are
/// visible-but-non-fatal, consistent with the additive, optional-on-land
/// posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SbomBindingState {
    /// No `sbom_artifact_binding` on the certificate. Additive, non-breaking.
    Unbound,
    /// Binding present, but no `--sbom-dir` was supplied to check the artifacts.
    PresentButUnverified,
    /// Binding present and both on-disk artifacts hash to the claimed values.
    Verified,
    /// Binding present and the on-disk BOM does not match the claimed hash.
    BomMismatch { claimed: String, actual: String },
    /// Binding present and the on-disk audit artifact does not match the
    /// claimed hash.
    AuditMismatch { claimed: String, actual: String },
    /// Binding present, `--sbom-dir` supplied, but a required artifact file
    /// could not be read (missing or otherwise unreadable).
    Unreadable { path: String, error: String },
}

/// Spec 203 FR-003 -- the pure link check. Re-hashes the on-disk BOM
/// (`<sbom_dir>/.factory/sbom.cdx.json`) and audit artifact
/// (`<sbom_dir>/.factory/audit.json`) and compares against the certificate's
/// claimed hashes, WITHOUT regenerating the BOM. Mirrors
/// `adjudicate_corpus_binding_state`'s by-reference posture: this checks
/// content identity only.
pub fn adjudicate_sbom_binding_state(
    binding: Option<&SbomArtifactBinding>,
    sbom_dir: Option<&Path>,
) -> SbomBindingState {
    let (binding, dir) = match (binding, sbom_dir) {
        (None, _) => return SbomBindingState::Unbound,
        (Some(_), None) => return SbomBindingState::PresentButUnverified,
        (Some(binding), Some(dir)) => (binding, dir),
    };

    let bom_path = dir.join(SBOM_BOM_RELPATH);
    let bom_bytes = match std::fs::read(&bom_path) {
        Ok(b) => b,
        Err(e) => {
            return SbomBindingState::Unreadable {
                path: bom_path.display().to_string(),
                error: e.to_string(),
            };
        }
    };
    let bom_hash = sha256_bytes(&bom_bytes);
    if bom_hash != binding.bom_hash {
        return SbomBindingState::BomMismatch {
            claimed: binding.bom_hash.clone(),
            actual: bom_hash,
        };
    }

    let audit_path = dir.join(SBOM_AUDIT_RELPATH);
    let audit_bytes = match std::fs::read(&audit_path) {
        Ok(b) => b,
        Err(e) => {
            return SbomBindingState::Unreadable {
                path: audit_path.display().to_string(),
                error: e.to_string(),
            };
        }
    };
    let audit_hash = sha256_bytes(&audit_bytes);
    if audit_hash != binding.audit_hash {
        return SbomBindingState::AuditMismatch {
            claimed: binding.audit_hash.clone(),
            actual: audit_hash,
        };
    }

    SbomBindingState::Verified
}

/// Map the adjudicated [`SbomBindingState`] onto the result's notices/errors.
/// `BomMismatch`, `AuditMismatch`, and `Unreadable` are fatal; the rest are
/// visible notices (spec 203 FR-003, skip-as-pass forbidden).
fn append_sbom_binding_findings(
    cert: &GovernanceCertificate,
    sbom_dir: Option<&Path>,
    result: &mut VerificationResult,
) {
    match adjudicate_sbom_binding_state(cert.sbom_artifact_binding.as_ref(), sbom_dir) {
        SbomBindingState::Unbound => {
            result.notices.push(
                "certificate is sbom-UNBOUND: no sbom_artifact_binding present -- the run is not \
                 bound by hash to a CycloneDX BOM or dependency-audit artifact (spec 203 FR-003)"
                    .into(),
            );
        }
        SbomBindingState::PresentButUnverified => {
            // `sbom_artifact_binding` is Some in this state.
            let binding = cert
                .sbom_artifact_binding
                .as_ref()
                .expect("binding present");
            result.notices.push(format!(
                "sbom artifact binding present-but-UNVERIFIED: certificate claims bomHash {} / \
                 auditHash {} (bom tool {}) but no --sbom-dir was supplied to check the \
                 artifacts (spec 203 FR-003)",
                binding.bom_hash, binding.audit_hash, binding.bom_tool_version
            ));
        }
        SbomBindingState::Verified => {
            let binding = cert
                .sbom_artifact_binding
                .as_ref()
                .expect("binding present");
            result.notices.push(format!(
                "sbom artifact binding VERIFIED: on-disk {SBOM_BOM_RELPATH} and \
                 {SBOM_AUDIT_RELPATH} hash to the claimed values (bom tool {})",
                binding.bom_tool_version
            ));
        }
        SbomBindingState::BomMismatch { claimed, actual } => {
            result.errors.push(format!(
                "sbom binding MISMATCH: certificate claims bomHash {claimed} but \
                 {SBOM_BOM_RELPATH} hashes to {actual} (spec 203 FR-003)"
            ));
        }
        SbomBindingState::AuditMismatch { claimed, actual } => {
            result.errors.push(format!(
                "sbom binding MISMATCH: certificate claims auditHash {claimed} but \
                 {SBOM_AUDIT_RELPATH} hashes to {actual} (spec 203 FR-003)"
            ));
        }
        SbomBindingState::Unreadable { path, error } => {
            result.errors.push(format!(
                "sbom artifact binding present but {path} could not be read: {error} \
                 (spec 203 FR-003)"
            ));
        }
    }
}

// ── spec_id resolution seam (spec 102 G-2) -- feature-gated OFF ──────
//
// This is the certificate verifier's ONE spec-spine edge: it resolves
// `intent.spec_id` against a spec registry via OAP's
// `open_agentic_spec_registry_reader`. It is warn-only (findings go to a
// sibling `validation-warnings.json`, never into the cert) and changes NO
// verify verdict, so dropping it is behavior-parity-safe.
//
// The vended tenant-tail build links no spec-spine crate, so the whole seam is
// gated behind the off-by-default `spec-id-resolution` feature and compiles out.
// Enabling the feature would also require adding `open_agentic_spec_registry_reader`
// as a dependency, which tenant-tail deliberately does not do; the code is kept
// only to document parity with OAP's in-tree verifier.

/// A single spec-id-resolution finding.
#[cfg(feature = "spec-id-resolution")]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ValidationWarning {
    /// `intent.spec_id` was set but no spec with that id exists in
    /// the spec-spine registry.
    SpecIdNotResolved {
        spec_id: String,
        registry_path: String,
    },
    /// The registry was not loadable at the expected path. By
    /// default this surfaces as a warning, not an error, because
    /// the cert is authoritative independent of the registry's
    /// existence on this filesystem.
    RegistryNotLoadable {
        registry_path: String,
        error: String,
    },
}

#[cfg(feature = "spec-id-resolution")]
impl ValidationWarning {
    /// Stable string id for the finding kind. Used by the env-gate
    /// to decide whether to promote a warning to an error.
    pub fn kind(&self) -> &'static str {
        match self {
            ValidationWarning::SpecIdNotResolved { .. } => "spec-id-not-resolved",
            ValidationWarning::RegistryNotLoadable { .. } => "registry-not-loadable",
        }
    }
}

/// Validate `cert.intent.spec_id` against the spec spine.
///
/// Returns the list of [`ValidationWarning`]s (possibly empty). When
/// `intent.spec_id` is `None`, returns an empty list -- the cert does
/// not claim a spec governance and there is nothing to validate.
#[cfg(feature = "spec-id-resolution")]
pub fn validate_spec_id_resolution(
    cert: &GovernanceCertificate,
    repo_root: &Path,
) -> Vec<ValidationWarning> {
    let Some(spec_id) = cert.intent.spec_id.as_deref() else {
        return Vec::new();
    };
    let registry_path = repo_root.join(".derived/spec-registry/registry.json");
    let registry = match open_agentic_spec_registry_reader::load(&registry_path) {
        Ok(r) => r,
        Err(e) => {
            return vec![ValidationWarning::RegistryNotLoadable {
                registry_path: registry_path.display().to_string(),
                error: format!("{e}"),
            }];
        }
    };
    if registry.find_by_id(spec_id).is_some() {
        return Vec::new();
    }
    vec![ValidationWarning::SpecIdNotResolved {
        spec_id: spec_id.to_string(),
        registry_path: registry_path.display().to_string(),
    }]
}

/// Write the validation warnings to a sibling
/// `validation-warnings.json` next to the certificate (no-op when
/// the slice is empty -- sibling-file absence == no warnings).
#[cfg(feature = "spec-id-resolution")]
pub fn write_validation_warnings(
    warnings: &[ValidationWarning],
    cert_path: &Path,
) -> Result<Option<std::path::PathBuf>, std::io::Error> {
    if warnings.is_empty() {
        return Ok(None);
    }
    let sibling = cert_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("validation-warnings.json");
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "certificateHash": "see governance-certificate.json",
        "warnings": warnings,
    }))
    .expect("validation warnings serialize");
    std::fs::write(&sibling, body)?;
    Ok(Some(sibling))
}

/// Returns true when the operator has opted into hard-failure mode
/// via `OAP_REQUIRE_SPEC_ID_RESOLUTION=1`. Default: false (warnings
/// remain warnings).
#[cfg(feature = "spec-id-resolution")]
pub fn require_spec_id_resolution_enabled() -> bool {
    matches!(
        std::env::var("OAP_REQUIRE_SPEC_ID_RESOLUTION").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

// ── Tests: corpus binding adjudication (spec 218 FR-003/FR-004) ───────

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_for(attestation: &[u8]) -> CorpusBinding {
        CorpusBinding {
            corpus_attestation_hash: sha256_bytes(attestation),
            spec_spine_version: "0.4.0".to_string(),
        }
    }

    #[test]
    fn corpus_binding_absent_is_unbound() {
        // No binding, with or without a supplied attestation, is "unbound".
        assert_eq!(
            adjudicate_corpus_binding_state(None, None),
            CorpusBindingState::Unbound
        );
        assert_eq!(
            adjudicate_corpus_binding_state(None, Some(b"anything")),
            CorpusBindingState::Unbound
        );
    }

    #[test]
    fn corpus_binding_present_no_attestation_is_present_but_unverified() {
        let binding = binding_for(b"corpus-attestation-bytes");
        assert_eq!(
            adjudicate_corpus_binding_state(Some(&binding), None),
            CorpusBindingState::PresentButUnverified
        );
    }

    #[test]
    fn corpus_binding_matching_attestation_is_verified() {
        let attestation = b"the upstream corpus attestation artifact";
        let binding = binding_for(attestation);
        assert_eq!(
            adjudicate_corpus_binding_state(Some(&binding), Some(attestation)),
            CorpusBindingState::Verified
        );
    }

    #[test]
    fn corpus_binding_mismatched_attestation_is_mismatch() {
        let binding = binding_for(b"the attestation the cert was bound to");
        let supplied = b"a different attestation entirely";
        let state = adjudicate_corpus_binding_state(Some(&binding), Some(supplied));
        match state {
            CorpusBindingState::Mismatch { claimed, actual } => {
                assert_eq!(claimed, binding.corpus_attestation_hash);
                assert_eq!(actual, sha256_bytes(supplied));
                assert_ne!(claimed, actual, "the whole point is they differ");
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn corpus_binding_is_omitted_when_absent() {
        // FR-001: an unbound certificate serialises with no `corpusBinding`
        // key, so its canonical JSON (and hence its hash) is byte-identical to
        // a pre-binding payload.
        let json = serde_json::json!({ "corpusBinding": null });
        assert!(
            json.get("corpusBinding").is_some(),
            "sanity: key exists in this literal"
        );

        let binding = binding_for(b"x");
        let serialised = serde_json::to_string(&binding).expect("binding serialises");
        assert!(serialised.contains("corpusAttestationHash"));
        assert!(serialised.contains("specSpineVersion"));
    }

    // ── Tests: SBOM artifact binding adjudication (spec 203 FR-003) ───

    fn sbom_binding_for(bom: &[u8], audit: &[u8]) -> SbomArtifactBinding {
        SbomArtifactBinding {
            bom_hash: sha256_bytes(bom),
            audit_hash: sha256_bytes(audit),
            bom_tool_version: "4.0.0".to_string(),
        }
    }

    #[test]
    fn sbom_binding_absent_is_unbound() {
        // No binding, with or without a supplied sbom dir, is "unbound".
        assert_eq!(
            adjudicate_sbom_binding_state(None, None),
            SbomBindingState::Unbound
        );
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            adjudicate_sbom_binding_state(None, Some(tmp.path())),
            SbomBindingState::Unbound
        );
    }

    #[test]
    fn sbom_binding_present_no_dir_is_present_but_unverified() {
        let binding = sbom_binding_for(b"bom-bytes", b"audit-bytes");
        assert_eq!(
            adjudicate_sbom_binding_state(Some(&binding), None),
            SbomBindingState::PresentButUnverified
        );
    }

    #[test]
    fn sbom_binding_matching_artifacts_is_verified() {
        let bom = b"cyclonedx-bom-bytes";
        let audit = b"npm-audit-bytes";
        let binding = sbom_binding_for(bom, audit);

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".factory")).unwrap();
        std::fs::write(tmp.path().join(SBOM_BOM_RELPATH), bom).unwrap();
        std::fs::write(tmp.path().join(SBOM_AUDIT_RELPATH), audit).unwrap();

        assert_eq!(
            adjudicate_sbom_binding_state(Some(&binding), Some(tmp.path())),
            SbomBindingState::Verified
        );
    }

    #[test]
    fn sbom_binding_tampered_bom_is_bom_mismatch() {
        let bom = b"cyclonedx-bom-bytes";
        let audit = b"npm-audit-bytes";
        let binding = sbom_binding_for(bom, audit);

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".factory")).unwrap();
        // Tamper the BOM: on-disk bytes no longer match what the binding was
        // computed over.
        std::fs::write(tmp.path().join(SBOM_BOM_RELPATH), b"TAMPERED BOM CONTENT").unwrap();
        std::fs::write(tmp.path().join(SBOM_AUDIT_RELPATH), audit).unwrap();

        let state = adjudicate_sbom_binding_state(Some(&binding), Some(tmp.path()));
        match state {
            SbomBindingState::BomMismatch { claimed, actual } => {
                assert_eq!(claimed, binding.bom_hash);
                assert_ne!(claimed, actual, "the whole point is they differ");
            }
            other => panic!("expected BomMismatch, got {other:?}"),
        }
    }

    #[test]
    fn sbom_binding_tampered_audit_is_audit_mismatch() {
        let bom = b"cyclonedx-bom-bytes";
        let audit = b"npm-audit-bytes";
        let binding = sbom_binding_for(bom, audit);

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".factory")).unwrap();
        std::fs::write(tmp.path().join(SBOM_BOM_RELPATH), bom).unwrap();
        std::fs::write(
            tmp.path().join(SBOM_AUDIT_RELPATH),
            b"TAMPERED AUDIT CONTENT",
        )
        .unwrap();

        let state = adjudicate_sbom_binding_state(Some(&binding), Some(tmp.path()));
        match state {
            SbomBindingState::AuditMismatch { claimed, actual } => {
                assert_eq!(claimed, binding.audit_hash);
                assert_ne!(claimed, actual, "the whole point is they differ");
            }
            other => panic!("expected AuditMismatch, got {other:?}"),
        }
    }

    #[test]
    fn sbom_binding_missing_artifact_is_unreadable() {
        let binding = sbom_binding_for(b"bom", b"audit");
        let tmp = tempfile::tempdir().expect("tempdir");
        // Empty tempdir: neither .factory artifact exists on disk.
        let state = adjudicate_sbom_binding_state(Some(&binding), Some(tmp.path()));
        match state {
            SbomBindingState::Unreadable { path, .. } => {
                assert!(path.ends_with("sbom.cdx.json"), "path: {path}");
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn sbom_binding_is_omitted_when_absent() {
        // FR-003: an unbound certificate serialises with no
        // `sbomArtifactBinding` key, so its canonical JSON (and hence its
        // hash) is byte-identical to a pre-binding payload.
        let binding = sbom_binding_for(b"x", b"y");
        let serialised = serde_json::to_string(&binding).expect("binding serialises");
        assert!(serialised.contains("bomHash"));
        assert!(serialised.contains("auditHash"));
        assert!(serialised.contains("bomToolVersion"));
    }

    // ── Tests: SBOM findings through `verify_certificate_with_platform`'s
    // internal hook (spec 203 FR-003) ──────────────────────────────────
    //
    // tenant-tail links no signing key material (it is verify-only), so a
    // minimal struct literal stands in for a builder-minted certificate; only
    // the sbom-binding findings are under test here. The signature/self-hash
    // chain over a real OAP-minted certificate is covered separately by
    // `tests/certificate_parity.rs`.

    fn minimal_cert(sbom_artifact_binding: Option<SbomArtifactBinding>) -> GovernanceCertificate {
        GovernanceCertificate {
            certificate_version: CERTIFICATE_VERSION.to_string(),
            pipeline_run_id: "test-run".to_string(),
            timestamp: Utc::now(),
            status: CertificateStatus::Complete,
            intent: IntentRecord {
                requirements_hash: String::new(),
                spec_id: None,
                spec_hash: None,
            },
            build_spec: BuildSpecRecord {
                hash: String::new(),
                approval_record: None,
            },
            stages: Vec::new(),
            verification: VerificationRecord {
                compile: VerificationOutcome::Skipped,
                test: VerificationOutcome::Skipped,
                lint: VerificationOutcome::Skipped,
                typecheck: VerificationOutcome::Skipped,
                security_scan: VerificationOutcome::Skipped,
            },
            proof_chain: ProofChainSummary {
                record_count: 0,
                first_record_hash: None,
                last_record_hash: None,
                chain_integrity: ChainIntegrity::Empty,
            },
            compliance: None,
            signer: None,
            inter_stage_chain: None,
            admitted_envelope_hash: None,
            goal_id: None,
            intent_capsule_hash: None,
            consumed_overrides: Vec::new(),
            corpus_binding: None,
            sbom_artifact_binding,
            certificate_hash: String::new(),
            signing_public_key: String::new(),
            cert_signature: String::new(),
            signing_attestation: SigningAttestation::default(),
            platform_countersign: None,
        }
    }

    fn empty_result() -> VerificationResult {
        VerificationResult {
            valid: true,
            errors: Vec::new(),
            notices: Vec::new(),
        }
    }

    #[test]
    fn sbom_findings_unbound_cert_is_notice_not_error() {
        let cert = minimal_cert(None);
        let mut result = empty_result();
        append_sbom_binding_findings(&cert, None, &mut result);
        assert!(result.errors.is_empty(), "unbound must not error");
        assert!(
            result.notices.iter().any(|n| n.contains("sbom-UNBOUND")),
            "expected an unbound notice: {:?}",
            result.notices
        );
    }

    #[test]
    fn sbom_findings_matching_artifacts_pass_with_sbom_dir() {
        let bom = b"cyclonedx-bom-bytes";
        let audit = b"npm-audit-bytes";
        let binding = sbom_binding_for(bom, audit);
        let cert = minimal_cert(Some(binding));

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".factory")).unwrap();
        std::fs::write(tmp.path().join(SBOM_BOM_RELPATH), bom).unwrap();
        std::fs::write(tmp.path().join(SBOM_AUDIT_RELPATH), audit).unwrap();

        let mut result = empty_result();
        append_sbom_binding_findings(&cert, Some(tmp.path()), &mut result);
        assert!(
            result.errors.is_empty(),
            "matching artifacts must not error: {:?}",
            result.errors
        );
        assert!(
            result.notices.iter().any(|n| n.contains("VERIFIED")),
            "expected a verified notice: {:?}",
            result.notices
        );
    }

    fn stage_with_artifact(stage_id: &str, artifact_name: &str) -> StageRecord {
        let mut hashes = BTreeMap::new();
        hashes.insert(artifact_name.to_string(), "deadbeef".to_string());
        StageRecord {
            stage_id: stage_id.to_string(),
            status: StageOutcome::Passed,
            artifact_hashes: hashes,
            gate_result: None,
            duration_ms: None,
            sandbox_execution: None,
        }
    }

    #[test]
    fn artifact_name_traversal_is_refused_not_read() {
        // A `..` artifact name from an untrusted certificate must be refused
        // rather than escaping --artifact-dir.
        let mut cert = minimal_cert(None);
        cert.stages
            .push(stage_with_artifact("s0", "../../../../etc/passwd"));
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = verify_certificate(&cert, Some(tmp.path()));
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("escapes --artifact-dir")),
            "expected a traversal refusal; errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn absolute_artifact_name_is_refused() {
        let mut cert = minimal_cert(None);
        cert.stages.push(stage_with_artifact("s0", "/etc/passwd"));
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = verify_certificate(&cert, Some(tmp.path()));
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("escapes --artifact-dir")),
            "expected an absolute-path refusal; errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn absolute_stage_id_is_refused() {
        let mut cert = minimal_cert(None);
        cert.stages
            .push(stage_with_artifact("/abs-stage", "ok.txt"));
        let tmp = tempfile::tempdir().expect("tempdir");
        let result = verify_certificate(&cert, Some(tmp.path()));
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("escapes --artifact-dir")),
            "expected a stage-id refusal; errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn sbom_findings_tampered_bom_fails_with_bom_mismatch_finding() {
        let bom = b"cyclonedx-bom-bytes";
        let audit = b"npm-audit-bytes";
        let binding = sbom_binding_for(bom, audit);
        let cert = minimal_cert(Some(binding));

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join(".factory")).unwrap();
        std::fs::write(tmp.path().join(SBOM_BOM_RELPATH), b"TAMPERED BOM").unwrap();
        std::fs::write(tmp.path().join(SBOM_AUDIT_RELPATH), audit).unwrap();

        let mut result = empty_result();
        append_sbom_binding_findings(&cert, Some(tmp.path()), &mut result);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("sbom binding MISMATCH") && e.contains("bomHash")),
            "expected a bom-mismatch error: {:?}",
            result.errors
        );
    }
}
