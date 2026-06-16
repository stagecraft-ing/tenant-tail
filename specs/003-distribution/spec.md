---
id: "003-distribution"
title: "Distribution: the verb surface, npm binary shim, and release pipeline"
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
references:
  - { unit: { kind: file, path: "npm/README.md" }, role: context }
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
  and `verify-provenance` are implemented; `verify-sbom` is forward-declared
  (OAP spec 203) and deliberately absent, not stubbed.
- `npm/`: the prebuilt-binary distribution shim (launcher + platform resolver +
  publish-time platform-package generator + its unit test and smoke test). A
  faithful mirror of spec-spine's `npm/`.
- `.github/workflows/release.yml`: the tag-gated per-triple build + SBOM + SLSA
  provenance + GitHub Release + crates.io + npm publish.
- `.github/workflows/ci.yml`: the CI gates, mirroring spec-spine's shape. A
  `test` job (build/test/clippy/fmt), a `self-governance` job (compile / index
  check / lint / couple, run via the pinned spec-spine), the reusable
  `determinism` job, and a `ci-gate` aggregate that is the single required check.
- `.github/workflows/determinism.yml`: the cross-platform golden proving the
  committed governance artifacts (registry + index) are byte-identical on every
  triple, so the committed `.derived/` is platform-independent.

## 3. Behavior

- The shim MUST work with no network at install and under `npm ci`: the launcher
  resolves the matching `@tenant-tail/cli-<os>-<cpu>` optional dependency and
  exec's the prebuilt binary, forwarding argv and exit code. No postinstall.
- The five-target `SUPPORTED` table MUST stay in lockstep across
  `npm/lib/platform.js`, `npm/scripts/generate-platform-packages.js`, and the
  `release.yml` build matrix.
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
