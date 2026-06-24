---
id: architecture
title: Architecture and Integration
sidebar_position: 5
---

# Architecture and Integration

`tenant-tail` is designed as a verify-only counterpart to `tenant-emit`, extracted from the Open Agentic Platform (OAP) factory engine.

## The Three-Crate Workspace

The Rust core (edition 2024, toolchain `1.92.0`, MSRV `1.85`) consists of three crates:

1. **`tenant-tail-types` (0.1.0):** Shared verify-surface DTOs and carrier types (serde only). Includes provenance claim types, corpus fingerprinting types, and the `AssumptionBudget`.
2. **`tenant-tail-core` (0.1.0):** The verify engines (crypto + serde). Contains the certificate verifier, Ed25519 signature checks, offline compact-JWS verification, and the provenance validator subtree. Ships an embedded `core-allowlist.txt`.
3. **`tenant-tail-cli` (0.1.0):** The `tenant-tail` binary wiring the verbs.

## The npm Binary Wrapper

For TypeScript/JS applications, `tenant-tail` ships as a prebuilt-binary wrapper mirroring `spec-spine`'s shape. The main `tenant-tail` package is a thin exec-forward launcher. It relies on five optional platform packages:
- `@tenant-tail/cli-darwin-arm64`
- `@tenant-tail/cli-darwin-x64`
- `@tenant-tail/cli-linux-x64`
- `@tenant-tail/cli-linux-arm64`
- `@tenant-tail/cli-win32-x64`

npm installs only the binary matching the host. `musl` Linux is intentionally unsupported (fallback to `cargo install`).

## Python Wheels and sdist Fallback

The PyPI distribution (`tenant-tail`) ships the same prebuilt binary as five per-platform wheels. The wheel platform tag is the selector. An `sdist` fallback is provided for unsupported hosts, containing an entry point that refuses installation and directs the user to `cargo install`.

## Dogfooding `spec-spine`

This repository's own `specs/` corpus is governed by a pinned `spec-spine` dev dependency. CI runs a `self_governance` job that compiles, lints, and couples the specs to ensure the repository adheres to its own rules.

## The Rust Library API

`tenant-tail-core` exports a verify-only library API for Rust consumers. See [For Library Users](./library-users.md) for details.
