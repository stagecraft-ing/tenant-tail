---
name: setup
description: One-time contributor setup. Build the tenant-tail binary, run the workspace tests and lints, smoke the CLI, and verify the dogfood governance loop so `/init` can report lifecycle and structural counts.
allowed-tools: Bash, Read
---

# Setup

Get a fresh clone operational. After this completes, `tenant-tail --help`
works and `/init` can report lifecycle counts through the pinned spec-spine
(no ad-hoc parsing of `.derived/**/*.json`: see
`.claude/rules/governed-artifact-reads.md`).

tenant-tail is verify-only: it has no emitter, no signing keys, and no
network surface. Governance is dogfooded through the **pinned spec-spine
devDependency** (`npx --no-install spec-spine ...`), not an in-tree binary.

## Process

### 1. Build the binary

```bash
cargo build --release -p tenant-tail-cli
```

Halt on non-zero exit and surface the failing step verbatim. The build
needs a Rust toolchain (the pinned version lives in `rust-toolchain.toml`).

### 2. Run the workspace tests and lints

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Halt on the first failure. Clippy must be clean (warnings are denied).

### 3. Smoke the CLI

```bash
target/release/tenant-tail --help
```

Confirm the binary runs and lists its two verbs (`verify-certificate`,
`verify-provenance`). Both cores are implemented; `--help` and `--version`
exit 0. A verb run exits 0 (verified/ok), 1 (verification failed or a
fail-closed flag fired), or 2 (usage / I/O error).

### 4. Verify the dogfood governance loop

The `specs/` corpus is governed by the pinned spec-spine. spec-spine
**commits** its compiled artifacts under `.derived/` (only
`build-meta.json` is gitignored), so the committed registry is the
reference for lifecycle queries. Smoke-test the gates `/init` and CI
depend on:

```bash
npx --no-install spec-spine compile         # regenerate the registry deterministically
npx --no-install spec-spine index check     # codebase index staleness gate
npx --no-install spec-spine lint --fail-on-warn   # corpus conformance
```

If `index check` exits non-zero the committed index is stale against
current inputs. Regenerate and re-commit it, then re-check. Do not parse
`.derived/**/*.json` directly to "verify" success.

### 5. Emit summary

Report exactly:

```
## setup: tenant-tail

**Build:** {ok / failed at <step>}
**Tests:** {pass / failed}
**Clippy:** {clean / N warnings}
**CLI smoke:** {help shown / failed}
**Governed loop:**
  - compile: {fresh registry / failed}
  - index check: {fresh / stale}
  - lint: {clean / N diagnostics}
**Lifecycle:** {N specs across <statuses>}  (from registry status-report)

Next: run `/init` to load full session context.
```

Do not invent counts. Only report values that came back from a command.

## Rules

- The build target is `cargo build --release -p tenant-tail-cli`. The
  governance loop runs through `npx --no-install spec-spine`, the pinned
  devDependency.
- Halt on first failure. Do not silently continue past a missing
  prerequisite or a failing gate.
- Never parse `.derived/**/*.json` directly in any verification step.
  Use the `spec-spine` subcommands.
- Verify-only: never add an emitter, signing-key handling, or a network
  surface as part of setup.
- Idempotent: safe to re-run. Cargo skips up-to-date crates; `compile`
  is deterministic.
