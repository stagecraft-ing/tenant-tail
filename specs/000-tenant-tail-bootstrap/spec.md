---
id: "000-tenant-tail-bootstrap"
title: "tenant-tail bootstrap (verify-only toolkit skeleton)"
status: draft
created: "2026-06-16"
authors: ["tenant-tail"]
kind: tooling
implementation: pending
risk: low
summary: >
  Bootstrap spec for the tenant-tail repository: a verify-only toolkit that
  re-checks a factory's run-side paperwork (governance certificate, provenance)
  with no trust in the producer. This spec establishes the workspace skeleton
  (a three-crate Cargo workspace mirroring spec-spine, plus the npm
  binary-distribution wrapper) and seeds this repo's own spec corpus, which is
  governed by the pinned spec-spine library. The verify cores and the verbs that
  expose them are added by subsequent specs in this corpus as the extraction
  lands; see OAP spec 219-tenant-tail-verifier-toolkit for the decision to vend
  and the extraction map.
depends_on: []
establishes:
  - { kind: file, path: "Cargo.toml" }
  - { kind: directory, path: "crates/tenant-tail-types" }
  - { kind: directory, path: "crates/tenant-tail-core" }
  - { kind: directory, path: "crates/tenant-tail-cli" }
  - { kind: directory, path: "npm" }
references:
  - { unit: { kind: file, path: "README.md" }, role: context }
---

# 000: tenant-tail bootstrap

## 1. Purpose

tenant-tail is the vended tenant verification surface. Spine to tail: spec-spine
compiles the corpus, tenant-tail verifies the factory's run-side telltales. It is
a verify-only CLI a produced application pins (one exact-version npm
devDependency, next to spec-spine) to re-check the artifacts the factory asserted
about its build. It carries no emitter, no signing identity, and needs no
network: the spec 102 do-not-trust-the-producer posture, turned tenant-ward.

This bootstrap spec exists so the repository has a governed seed: the workspace
skeleton compiles, this corpus is non-empty, and spec-spine can dogfood it. The
substance has since landed (per OAP spec 219): the cert verify core
(`001-certificate-verify-core`), the provenance verify core
(`002-provenance-verify-core`), and the verb surface + npm wrapper + release
matrix (`003-distribution`) each claim their own files. This spec retains the
crate skeleton it seeded: the per-crate manifests and crate roots that wire the
substance together.

## 2. Territory

This spec establishes the skeleton, mapped to the establishes edges above. The
directory edges are a coupling floor: the substance files within them are claimed
by the feature specs (001-003), while the crate skeleton (each crate's
`Cargo.toml` manifest and `src/lib.rs` root) and the workspace root remain
bootstrap territory.

- `Cargo.toml`: the three-crate workspace root (types / core / cli), mirroring
  spec-spine's shape; the CLI binary is `tenant-tail`.
- `crates/tenant-tail-types`: shared verify-surface DTOs (carrier types).
- `crates/tenant-tail-core`: the verify engines.
- `crates/tenant-tail-cli`: the `tenant-tail` binary (verbs).
- `npm`: the prebuilt-binary distribution wrapper (main package +
  `@tenant-tail/cli-<os>-<cpu>` optional dependencies + exec-forward launcher +
  publish-time platform-package generator).

## 3. Behavior

- The repository MUST build as a single Cargo workspace
  (`cargo build --workspace`).
- The toolkit MUST remain verify-only: no emitter verb, no emitter dependency,
  no signing-key handling. The verify-only boundary is structural, not
  documentary.
- This repo's own `specs/` corpus MUST be governed by the pinned spec-spine
  library (compile / lint / index check / couple), the same dogfooding pattern
  spec-spine and OAP follow.
- Each crate's `src/lib.rs` root composes and re-exports the verify surface its
  modules implement (the certificate types and verify entrypoints, the
  provenance validator). When a feature spec adds a type to that surface (for
  example the corpus-binding types added under `001-certificate-verify-core`),
  the crate root re-exports it too; the root stays bootstrap territory while the
  substance stays with the owning feature spec.

## 4. Out of scope

- The verify cores themselves, the verbs, behavior parity with the OAP in-tree
  paths, the feature-gated spec-spine seam, the release matrix, and the npm
  publish flow. Each is owned by a subsequent spec in this corpus, authored as
  the extraction lands.
- The corpus attestation's own truth (spec-spine `023-ledger-seal`, verified by
  spec-spine's `verify-attestation`) and the emit side of the run-cert corpus
  binding (OAP spec 218, which mints the `corpusBinding` block): sibling work in
  other corpora. The tenant-ward VERIFY side of the binding (the by-reference
  link check) has landed under `001-certificate-verify-core`.
