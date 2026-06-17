---
name: ship
description: "Governed pre-PR sequence: run the gate locally, review the diff, conventional commit on a feature branch, open a PR via gh"
allowed-tools: Bash, Read, Edit, Glob, Grep, Skill
argument-hint: "[optional scope note or PR title]"
---

# /ship: gate -> review -> commit -> PR

Sequences the steps that turn a working tree into a PR. Bound by
`.claude/rules/orchestrator-rules.md` (checkpoints are real stops) and
`.claude/rules/adversarial-prompt-refusal.md` (do not edit an owning
spec to make the gate pass).

tenant-tail is a verify-only Rust workspace plus an npm and a PyPI shim.
There are two gate layers: the **build** gate (`cargo`) and the
**governance** gate, the pinned spec-spine devDependency run as
`npx --no-install spec-spine ...` (the dogfood loop; CI runs the same).

## Step 0: preflight

- `git branch --show-current`. If on `main`, STOP and create a feature
  branch first (`NNN-short-name` when the work belongs to spec `NNN`).
  Never commit straight to the default branch.
- `git status --short`. Confirm the changes are the intended set;
  surface anything unexpected before proceeding.

## Step 1: run the gate locally

Run the build gate, then the governance gate, in order. Stop on the first
failure (orchestrator rule: halt, do not silently continue).

```sh
# Build gate (CI's `test` job)
cargo fmt --all --check
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings

# Governance gate (CI's `self-governance` job), via the pinned spec-spine
npx --no-install spec-spine compile                 # specs -> .derived/spec-registry/registry.json
npx --no-install spec-spine lint --fail-on-warn     # corpus well-formedness (exit 1 on a warn)
npx --no-install spec-spine index check             # staleness gate (committed .derived must be current)
npx --no-install spec-spine couple --base origin/main --head HEAD   # the drift gate (exit 1 on drift)
```

Outcomes:

- All pass: continue to Step 2.
- `index check` reports stale: the committed `.derived/` is behind current
  inputs (a changed spec, a touched workflow, new code). Regenerate with
  `npx --no-install spec-spine compile && npx --no-install spec-spine index`,
  then stage and commit the regenerated
  `.derived/spec-registry/registry.json` and
  `.derived/codebase-index/index.json` with your change. `.derived/` is a
  tracked artifact here (only `build-meta.json` is gitignored); CI runs the
  same staleness gate and the cross-platform determinism golden.
- `couple` reports drift: the changed code is not covered by its owning
  spec's declared edges. Two legitimate paths, chosen explicitly, never
  silently:
  1. **Fix the coupling.** Edit the owning `spec.md` so its relationship
     edges (`establishes:` / `extends:` / `refines:`) and owned authority
     units cover every changed path. Do NOT edit a spec to retroactively
     justify code that contradicts the spec's design: that is a
     coherence-guard halt (surface the contradiction and stop).
  2. **Waiver.** Add a cited `Spec-Drift-Waiver:` line documenting why the
     drift is accepted. CHECKPOINT: requires explicit user approval.

## Step 2: review the diff

Invoke the `code-review` skill on the working diff. Apply confirmed,
actionable fixes. If a fix touches any gate input (a `spec.md`, a
`Cargo.toml`, a schema, a workflow, an `npm/` or `py/` manifest), re-run
Step 1 before continuing.

## Step 3: commit

Invoke the `commit` skill (conventional, impact-focused message) on a
feature branch.

- Never add AI attribution: no "Generated with ...", no `Co-Authored-By`
  trailers, in commits or PR bodies.
- No em dash (U+2014) in the message or PR body (house style).
- If a waiver was chosen in Step 1, keep the `Spec-Drift-Waiver:` line
  with the change so the PR carries it.

## Step 4: CHECKPOINT, open the PR

PR creation is outward-facing. Confirm with the user, then:

```sh
git push -u origin "$(git branch --show-current)"
gh pr create --title "<conventional title>" --body "<Summary + Testing>"
```

- The PR body is Summary + Testing. Include the `Spec-Drift-Waiver:`
  line inline in the body if Step 1 chose the waiver path with user
  approval (CI's coupling gate reads it from the PR body).
- CI re-runs the same gates plus the cross-platform determinism golden,
  aggregated under the single `ci-gate` check. A local pass should mean a
  clean CI run; if CI still fails on a gate the local run passed, halt and
  present the divergence (orchestrator rule: halt on failure).

## Step 5: after creation

- After the PR merges, verify on-disk `main` (`git pull` + `git log`),
  not just the MERGED status.

## Release note

This skill ships code to a PR. It does NOT cut a release. A release is a
`v*` tag push (see `.github/workflows/release.yml`) and publishes to
crates.io / npm / PyPI; that is a separate, deliberate, human-initiated
step.
