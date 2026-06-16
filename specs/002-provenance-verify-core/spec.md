---
id: "002-provenance-verify-core"
title: "Provenance verify core (claim-provenance re-check)"
status: draft
created: "2026-06-16"
authors: ["tenant-tail"]
kind: verify-core
implementation: complete
risk: medium
summary: >
  The claim-provenance verify engine, extracted from OAP's standalone
  `provenance-validator` (spec 121) and relicensed Apache-2.0 (see NOTICE),
  plus the bounded carrier types it consumes (the `provenance` + `knowledge` +
  `budget` slice of OAP's `factory-contracts`). Exposes the pure, byte-
  deterministic `validate()` and the read-only retroactive `audit()`. LLM-
  independent by construction: the whole dependency graph is crypto + serde
  only, so the validator cannot be fooled by the model that minted the claims.
depends_on: ["000-tenant-tail-bootstrap"]
establishes:
  - { kind: directory, path: "crates/tenant-tail-core/src/provenance" }
  - { kind: file, path: "crates/tenant-tail-core/src/data/core-allowlist.txt" }
  - { kind: file, path: "crates/tenant-tail-types/src/provenance.rs" }
  - { kind: file, path: "crates/tenant-tail-types/src/knowledge.rs" }
  - { kind: file, path: "crates/tenant-tail-types/src/budget.rs" }
  - { kind: file, path: "crates/tenant-tail-types/src/lib.rs" }
  - { kind: file, path: "crates/tenant-tail-core/tests/provenance_parity.rs" }
references:
  - { unit: { kind: file, path: "NOTICE" }, role: context }
---

# 002: Provenance verify core

## 1. Purpose

A produced application must be able to re-check that every claim minted during
its build carries valid provenance (a citation against the extraction corpus, or
an `ASSUMPTION` tag within budget), with no trust in the producer. This spec
governs the verify-only provenance engine: OAP's `provenance-validator`,
extracted whole and relicensed Apache-2.0, plus the bounded carrier types it
consumes.

## 2. Territory

- `crates/tenant-tail-core/src/provenance/`: the validator subtree (allowlist
  derivation, corpus view, citation verification, assumption-manifest handling,
  and the `validate()` / `audit()` entry points).
- `crates/tenant-tail-core/src/data/core-allowlist.txt`: the built-in core
  allowlist, embedded at compile time.
- `crates/tenant-tail-types/src/{provenance,knowledge,budget}.rs` and
  `lib.rs`: the carrier types the validator imports (the bounded slice of OAP's
  `factory-contracts`, leaving the `agent-frontmatter` / `ts-rs` leaf behind).
- `crates/tenant-tail-core/tests/provenance_parity.rs`: the end-to-end audit
  test over a golden fixture project.

## 3. Behavior

- `validate()` MUST be pure and byte-deterministic: identical inputs produce an
  identical serialized report.
- A panic in validation MUST fail closed: the report records all claims as
  rejected and carries the panic reason.
- `audit()` MUST be read-only at the library layer; it never writes to disk.
- The dependency graph MUST remain crypto + serde only (LLM-independence): no
  LLM client crate, no network.
- Behavior parity: the per-rule logic is the OAP validator's own unit tests,
  ported unchanged and run against the extracted code.

## 4. Out of scope

- Emitting or promoting claims, writing assumption manifests into a project:
  the engine is verify/audit-only and read-only.
- The heavier `factory-contracts` modules (build-spec, adapter, governance
  envelope, etc.) and the `agent-frontmatter` / `ts-rs` transitive leaf: out of
  the carrier slice by design.
