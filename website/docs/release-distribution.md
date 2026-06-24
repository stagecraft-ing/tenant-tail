---
id: release-distribution
title: Release and Distribution
sidebar_position: 8
---

# Release and Distribution

The `tenant-tail` release pipeline is tag-gated (`v*`) and ensures reproducible, verifiable distribution across all supported platforms.

## Supported Targets

The five supported platform targets are kept in lockstep across the npm wrapper, PyPI wheels, and the release build matrix:
- `darwin-arm64` (macOS Apple Silicon)
- `darwin-x64` (macOS Intel)
- `linux-x64` (Linux glibc x86_64)
- `linux-arm64` (Linux glibc aarch64)
- `win32-x64` (Windows x86_64)

## GitHub Releases and Archives

When a tag is pushed, the release workflow builds a per-triple archive for all five targets. Each archive ships with:
- The prebuilt binary
- A `.sha256` sidecar
- A per-target CycloneDX SBOM
- A SLSA build-provenance attestation

## Idempotent Publish Legs

The release pipeline executes three idempotent publish legs:
1. **crates.io:** Publishes the three crates (`tenant-tail-types`, `tenant-tail-core`, `tenant-tail-cli`).
2. **npm:** Assembles and publishes the main package and the five `@tenant-tail/cli-<os>-<cpu>` platform packages directly from the release archives. No second Rust build occurs.
3. **PyPI:** Assembles and publishes the five per-platform wheels and the `sdist` fallback using OIDC Trusted Publishing.

## Supply-Chain Security

A `determinism` job in CI proves that the `.derived/` shards (registry and index) are byte-identical across four different triples (Linux x86_64/aarch64, macOS aarch64, Windows x86_64). This guarantees that the committed artifacts are platform-independent.
