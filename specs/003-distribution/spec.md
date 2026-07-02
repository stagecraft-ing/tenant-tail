---
id: "003-distribution"
title: "Distribution: the verb surface, npm + PyPI binary shims, and release pipeline"
status: draft
created: "2026-06-16"
authors: ["tenant-tail"]
kind: tooling
implementation: complete
risk: medium
summary: >
  How the tenant-tail verifier reaches a produced application: the CLI verb
  surface (`verify-certificate`, `verify-provenance`; `verify-sbom` forward-
  declared), the prebuilt-binary npm shim a TS/JS app pins next to spec-spine
  (one exact-version devDependency, one pin per verb), and the tag-gated release
  pipeline that builds the five per-triple archives (with SBOM + SLSA
  provenance) and assembles the `@tenant-tail/cli-<os>-<cpu>` platform packages.
  The shim is a launcher, not a native addon, and mirrors spec-spine's npm/ shape.
  A parallel PyPI channel (`uvx tenant-tail ...`) ships the same prebuilt binary
  as five per-platform wheels plus an sdist refusal fallback, assembled from the
  same release archives (no second Rust build), mirroring spec-spine 008.
depends_on:
  - "000-tenant-tail-bootstrap"
  - "001-certificate-verify-core"
  - "002-provenance-verify-core"
establishes:
  - { kind: file, path: "crates/tenant-tail-cli/src/main.rs" }
  - { kind: file, path: "npm/bin/tenant-tail.js" }
  - { kind: file, path: "npm/lib/platform.js" }
  - { kind: file, path: "npm/scripts/generate-platform-packages.js" }
  - { kind: file, path: "npm/scripts/smoke-test.sh" }
  - { kind: file, path: "npm/test/platform.test.js" }
  - { kind: file, path: "npm/package.json" }
  - { kind: file, path: ".github/workflows/release.yml" }
  - { kind: file, path: ".github/workflows/ci.yml" }
  - { kind: file, path: ".github/workflows/determinism.yml" }
  - { kind: file, path: ".github/workflows/ai-pr-review.yml" }
  - { kind: directory, path: "py" }
  - { kind: file, path: "py/scripts/generate_wheels.py" }
references:
  - { unit: { kind: file, path: "npm/README.md" }, role: context }
  - { unit: { kind: file, path: "py/README.md" }, role: context }
---

# 003: Distribution

## 1. Purpose

`cargo install tenant-tail-cli` puts the binary on a machine, but a produced
TypeScript/JS application's reflex is `npm i -D tenant-tail`, pinned next to
`spec-spine`, and it will not install a Rust toolchain to re-check its own
paperwork. This spec governs the verb surface that application invokes and the
machinery that delivers it: the npm binary shim and the release pipeline.

## 2. Territory

- `crates/tenant-tail-cli/src/main.rs`: the verb surface. `verify-certificate`
  (now carrying `--sbom-dir`, OAP spec 203 FR-003, which folds the SBOM binding
  check into the certificate verify rather than a separate verb) and
  `verify-provenance` are implemented; the standalone `verify-sbom` verb stays
  deliberately absent (its function is subsumed by `--sbom-dir`), not stubbed.
- `npm/`: the prebuilt-binary distribution shim (launcher + platform resolver +
  publish-time platform-package generator + its unit test and smoke test). A
  faithful mirror of spec-spine's `npm/`.
- `py/`: the PyPI channel (one project + five per-platform wheels + an sdist
  whose only entry point is the unsupported-host refusal). `platform_map.py` is
  the Python copy of the five-target fact; `generate_wheels.py` assembles
  byte-reproducible, version-locked wheels from the release archives. A faithful
  mirror of spec-spine's `py/` (spec-spine 008).
- `.github/workflows/release.yml`: the tag-gated per-triple build + SBOM + SLSA
  provenance + GitHub Release + crates.io + npm publish.
- `.github/workflows/ci.yml`: the CI gates, mirroring spec-spine's shape. A
  `test` job (build/test/clippy/fmt), a `self-governance` job (compile / index
  check / lint / couple, run via the pinned spec-spine), the reusable
  `determinism` job, and a `ci-gate` aggregate that is the single required check.
- `.github/workflows/determinism.yml`: the cross-platform golden proving the
  committed governance artifacts (registry + index) are byte-identical on every
  triple, so the committed `.derived/` is platform-independent.
- `.github/workflows/ai-pr-review.yml`: the AI PR review, a reusable workflow
  ci.yml dispatches into `ci-gate` so a failed or absent review blocks merge
  (green ci-gate => actually reviewed or visibly skipped). It classifies a
  Claude CLI failure: an unset `CLAUDE_CODE_OAUTH_TOKEN` or an auth/permission
  error hard-fails (a broken token must be fixed, not masked), while any other
  API failure (overloaded, rate-limit, 5xx, timeout, network) passes `ci-gate`
  with a loud, visible PR notice so a third-party Anthropic incident does not
  block merges. The pass is never silent.

## 3. Behavior

- The shim MUST work with no network at install and under `npm ci`: the launcher
  resolves the matching `@tenant-tail/cli-<os>-<cpu>` optional dependency and
  exec's the prebuilt binary, forwarding argv and exit code. No postinstall.
- The five-target platform fact MUST stay in lockstep across the four copies:
  the `SUPPORTED` map in `npm/lib/platform.js`, the `TARGETS` map in
  `npm/scripts/generate-platform-packages.js`, the `TARGETS` map in
  `py/src/tenant_tail/platform_map.py`, and the `release.yml` build matrix.
- The PyPI channel MUST deliver the same prebuilt binary as the npm shim with no
  second Rust build: `generate_wheels.py` assembles five per-platform wheels
  (the wheel platform tag is the selector) plus an sdist from the release
  archives, byte-reproducibly and version-locked to the tag. An unsupported host
  (musl/Alpine, win-arm64, 32-bit) matches no wheel and falls to the sdist, whose
  only entry point names the host and points at `cargo install tenant-tail-cli`
  (parity with the npm shim's unsupported-host refusal). Publish is OIDC
  Trusted-Publishing and idempotent (skip-existing); absent the one-time setup
  (`vars.PYPI_TRUSTED_PUBLISHING`) the release leg is a clean no-op.
- The Linux release binaries MUST honor the `manylinux_2_17` glibc floor that the
  wheel and npm `libc` tags promise: they are cross-linked against glibc 2.17
  (via `cargo zigbuild --target <triple>.2.17`) and `release.yml` asserts, from
  the ELF dynamic symbol table, that no referenced `GLIBC_x.y` symbol exceeds
  2.17 before publishing. A toolchain bump that raised the floor fails the
  release rather than shipping a wheel/npm tag that is a lie.
- The verbs MUST be verify-only and offline: no emitter verb, no `--jwks-url`
  network fetch (a saved JWKS file is read instead), no writes into an audited
  project.
- The tenant pin model: one exact-version `tenant-tail` devDependency next to
  `spec-spine`; `npm ci` sha512 lockfile integrity covers it. One pin, every verb.
- CI MUST expose a single aggregate required check (`ci-gate`) so branch
  protection and the merge queue gate on one stable name; a failed or cancelled
  upstream job MUST fail it, a skipped (event-gated) job MUST NOT.

## 4. Out of scope

- The verify engines themselves (001, 002) and the certificate/provenance verdict
  logic.
- `verify-sbom`: forward-declared; joins when OAP spec 203's core exists. No stub.
