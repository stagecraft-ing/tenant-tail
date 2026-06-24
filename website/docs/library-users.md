---
id: library-users
title: For Library Users (Rust)
sidebar_position: 7
---

# For Library Users (Rust)

`tenant-tail` is built as a set of Rust crates. If you are building a custom verifier or integrating verification into a Rust application, you can use the library API directly.

## Importing the Crates

Add the crates to your `Cargo.toml`:

```toml
[dependencies]
tenant-tail-types = "0.1.0"
tenant-tail-core = "0.1.0"
```

## Verifying a Certificate

To verify a governance certificate programmatically:

```rust
use tenant_tail_core::certificate::{GovernanceCertificate, verify_certificate};

// Parse the certificate JSON
let cert: GovernanceCertificate = serde_json::from_str(&json_string).unwrap();

// Verify without platform seal adjudication
let result = verify_certificate(&cert, Some(artifact_dir_path));

if result.valid {
    println!("Certificate verified!");
} else {
    for err in result.errors {
        eprintln!("Error: {}", err);
    }
}
```

## Verifying with Platform Seal

To include platform seal and corpus binding adjudication:

```rust
use tenant_tail_core::certificate::verify_certificate_with_platform;
use tenant_tail_core::platform_jws::PlatformJwks;

let jwks: PlatformJwks = serde_json::from_str(&jwks_json).unwrap();

let result = verify_certificate_with_platform(
    &cert,
    Some(artifact_dir_path),
    Some(&jwks),
    true, // require_sealed
    Some(corpus_attestation_bytes)
);
```

## Running a Provenance Audit

To run the claim-provenance audit and render the report:

```rust
use tenant_tail_core::provenance::{audit, render_audit_report};
use std::path::Path;

let project_dir = Path::new("./my-project");
let report = audit(project_dir);

// Render the Markdown report
let markdown = render_audit_report(&report);
println!("{}", markdown);
```

The library API is verify-only by construction. There is no emitter API and no signing keys are handled.
