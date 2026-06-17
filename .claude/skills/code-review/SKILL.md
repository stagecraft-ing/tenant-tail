---
name: code-review
description: "Review the current diff for correctness bugs and spec drift, then emit an evidence-oriented findings list"
allowed-tools: Read, Grep, Glob, Bash(git status:*), Bash(git diff:*), Bash(git log:*), Bash(git show:*), Bash(git rev-parse:*), Bash(cargo:*), Bash(rustfmt:*), Bash(npx:*)
argument-hint: "[scope] - e.g. \"branch\", \"working tree\", \"crates/tenant-tail-core\""
---

# /code-review: correctness + spec drift

Reviews the current diff against two questions: does the change have
correctness or edge-case bugs, and does it still match its owning
spec's contract. Output is an evidence-oriented findings list, each
line citing `file:line`. Read-only: no files are modified unless the
user asks for a fix afterward.

This repo is a verify-only Rust workspace plus an npm and a PyPI
distribution shim. The build gate is `cargo`; the governance gate is the
**pinned spec-spine devDependency**, run as `npx --no-install spec-spine ...`.

## Step 0: scope the diff

```sh
git status --short && git diff --stat && git log --oneline -10
git diff origin/main...HEAD --stat   # committed delta
git diff HEAD --stat                 # uncommitted delta
```

Note which classes changed: Rust source (`crates/**/*.rs`, `Cargo.toml`),
specs (`specs/**/spec.md`), schemas/standards (`standards/**`), docs
(`docs/**`, `*.md`), distribution shims (`npm/**`, `py/**`), workflows
(`.github/**`).

## Step 1: gates stay green

The change must leave both the build and the corpus green. Run them and
capture the exact outputs as evidence:

```sh
cargo fmt --all --check
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
npx --no-install spec-spine compile
npx --no-install spec-spine lint --fail-on-warn      # corpus well-formedness
npx --no-install spec-spine index check              # staleness (committed .derived must be current)
npx --no-install spec-spine couple --base origin/main --head HEAD   # drift gate
```

- A `couple` failure is the headline finding: cite the file the gate
  named and the owning spec whose declared edges fail to cover it.
- A `lint` / `index check` / clippy / test failure is a gate finding:
  cite the diagnostic verbatim.

## Step 2: spec-contract match

For each changed source file, confirm the change is consistent with the
contract of its owning spec rather than only with the gate's mechanical
pass. Useful reads (governed, via the binary, not ad-hoc JSON parsing):

```sh
npx --no-install spec-spine registry show <spec-id>           # the owning spec's declared surface
npx --no-install spec-spine registry relationships <spec-id>  # its typed edges
```

Flag drift where code does something the spec's narrative or owned
authority units do not describe, even if `couple` happens to pass.
Cite the spec section and the `file:line`.

## Step 3: correctness pass

Read the changed source and look for, with a `file:line` and a
one-sentence evidence claim for each:

- Logic and edge-case bugs (off-by-one, unhandled `None`/`Err`, empty
  input, boundary values).
- The verify-only boundary: no emitter verb, no signing-key handling, no
  network/HTTP client, no writes into an audited project. `unsafe_code`
  is forbidden workspace-wide. A change that crosses this boundary is a
  headline finding regardless of correctness.
- Determinism hazards: unsorted map/set iteration, locale- or
  platform-dependent behavior, unstable ordering in emitted JSON or
  hashes. The cert self-hash and the provenance report are promised
  byte-deterministic, and the committed `.derived/` must be platform-
  independent.
- Error-path correctness: does the verb return the right exit-code class
  (0 verified/ok, 1 verification failed or a fail-closed flag fired,
  2 usage or I/O error)?
- Hygiene: stray debug prints, commented-out code, dead branches.

## Step 4: findings report

```
## Review: <scope>
Base: origin/main | Head: <branch> | Files: <n> | +<a>/-<d>
Gate: fmt <ok|FAIL> | build <ok|FAIL> | test <ok|FAIL> | clippy <ok|FAIL> | compile <ok|FAIL> | lint <ok|FAIL> | index check <ok|stale> | couple <ok|drift>

### Findings (severity-ordered)
- [CORRECTNESS|BOUNDARY|SPEC-DRIFT|GATE|HYGIENE] <claim> at `file:line`
  Evidence: <one sentence, cited>
  Fix: <specific recommendation>

### Clean
- <dimensions checked with nothing found>
```

If nothing is found, say so plainly and report the gate as the
evidence. To proceed with fixes, the user names the findings to apply.
