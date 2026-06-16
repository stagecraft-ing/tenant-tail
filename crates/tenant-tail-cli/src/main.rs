//! tenant-tail: the verify-only CLI. SCAFFOLD ONLY.
//!
//! The two verbs (`verify-certificate`, `verify-provenance`) and the staged
//! third (`verify-sbom`) are wired by the tenant-tail worker agent over
//! `tenant-tail-core`. This placeholder compiles and exits non-zero so the
//! scaffold is obviously not yet functional. See OAP spec 219.

fn main() {
    eprintln!(
        "tenant-tail: scaffold only -- verify cores not yet implemented \
         (OAP spec 219-tenant-tail-verifier-toolkit)."
    );
    // EX_SOFTWARE: the program is present but the feature is not yet built.
    std::process::exit(70);
}
