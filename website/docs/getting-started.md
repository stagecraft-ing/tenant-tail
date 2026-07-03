---
id: getting-started
title: Getting Started
sidebar_position: 1
---

# Getting Started

`tenant-tail` is a verify-only CLI toolkit that re-checks a run's governance paperwork (governance certificates and claim provenance) with no trust in the producer. It is offline, identity-free, and read-only down to the package boundary.

## Installation

You can install `tenant-tail` via npm, PyPI, or Cargo.

### npm (TypeScript/JS apps)

For TypeScript or JavaScript applications, `tenant-tail` is shipped as a prebuilt-binary launcher pinned next to `spec-spine`.

```bash
npm i -D tenant-tail
```

### PyPI (Python)

For Python applications, `tenant-tail` is distributed as platform-specific wheels.

```bash
uvx tenant-tail verify-certificate cert.json --artifact-dir ./run
# or
pip install tenant-tail
```

### crates.io (Rust)

For Rust environments or unsupported platforms (like musl Linux), install via Cargo.

```bash
cargo install tenant-tail-cli
```

## Quickstart

To verify a governance certificate, you can use the real fixture shipped in the repository.

```bash
npx --no-install tenant-tail verify-certificate \
  ./crates/tenant-tail-core/tests/fixtures/cert-run/governance-certificate.json \
  --artifact-dir ./crates/tenant-tail-core/tests/fixtures/cert-run \
  --allow-unsealed
```

The fixture carries no platform countersign, so `--allow-unsealed` is required: by default `tenant-tail` fails closed (exit `1`) on an unsealed certificate. With the flag, a successful verification returns exit code `0` and outputs a verified result:

```text
governance certificate VERIFIED (pipeline: cert-run, status: complete)
  stages: 6
  proof chain records: 0
  certificate hash: 5d1e2f3a...
  platform seal: ABSENT (unsealed)
```

To run a claim-provenance audit on a produced application:

```bash
npx --no-install tenant-tail verify-provenance --project .
```

This reads the project directory, audits all claims, and prints a Markdown report to `stdout` without writing into the audited project.
