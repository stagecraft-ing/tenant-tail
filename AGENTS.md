# AGENTS.md: tenant-tail

## New Sessions

Run `/init` as the mandatory first action of every new session. The command reads this section to derive its execution plan dynamically: any item added here is automatically picked up on the next init. This file is the cross-agent authority (read by Claude Code, Codex CLI, Cursor, Copilot, and any future agent via the AAIF/Linux Foundation AGENTS.md standard).

**Init protocol (executed by `/init`):**

> AGENTS.md is loaded implicitly as the protocol source: its contents
> are the protocol, so `/init` does not list AGENTS.md as a parallel
> identity read in Step 1 (avoiding the self-reference loop).

tenant-tail is a verify-only CLI that dogfoods spec-spine governance. Two binaries are in play and they are different: the **product** binary is `tenant-tail` (`cargo build --release -p tenant-tail-cli`), and **governance** runs through the **pinned spec-spine devDependency**, invoked as `npx --no-install spec-spine ...` (installed by `npm ci` from the committed lockfile). Do NOT build or invoke a local spec-spine; the pinned npm one is the governing toolchain.

0. **Load rules.** Read `.claude/rules/orchestrator-rules.md`,
   `.claude/rules/governed-artifact-reads.md`, AND
   `.claude/rules/adversarial-prompt-refusal.md`.
1. **Refresh the registry, then parallel reads.** Run `npx --no-install
   spec-spine compile` *first* (see **Registry freshness** below), then
   dispatch the following simultaneously:
   - `CLAUDE.md`: project overview, invariants, and conventions
   - `README.md`: full project description
   - `npx --no-install spec-spine index check`: staleness gate for the codebase index (non-fatal)
   - `npx --no-install spec-spine registry status-report --json --nonzero-only`: lifecycle counts per status
   - `npx --no-install spec-spine registry list --ids-only`: spec id list
   - `ls crates/`: the three-crate workspace (types / core / cli)
   - `ls specs/`: the spec corpus
   - `cargo build --release -p tenant-tail-cli`: build the product binary (fast check; skip if only reading)
   - `git log --oneline -10`: recent history
   - `git diff --stat HEAD~1`: last change summary
2. **Emit** the `## initialized: tenant-tail` summary block: a crate
   overview (types / core / cli + the npm and py shims), a `## lifecycle:`
   sub-section populated from the `registry status-report --nonzero-only`
   output, recent activity, and a "ready to help with" line.

**Read discipline:** the init protocol MUST NOT parse `.derived/**/*.json` directly (no `python`, `jq`, `awk`, `sed` against compiled artifacts). All structural and lifecycle data comes from the `spec-spine` subcommands (`registry`, `index`). See `.claude/rules/governed-artifact-reads.md`.

**Registry freshness:** this repo **commits** its compiled artifacts. The sharded `.derived/spec-registry/by-spec/*.json` and `.derived/codebase-index/by-spec,by-package/*.json` trees (spec-spine 0.5.0's layout) are tracked (only `.derived/**/build-meta.json` is gitignored), so the committed registry is the reference for lifecycle queries, and the coupling + staleness gates compare committed against current. `/init` still runs `compile` *first* because it is deterministic: on a fresh tree it is a no-op that leaves the tracked registry byte-identical; if it changes the registry, the committed copy was stale and the refreshed counts are the correct ones (regenerate and commit the registry before relying on it).

**Toolchain missing:** if `npx --no-install spec-spine` fails because the devDependency is not installed, run `npm ci` and continue. Do NOT fall back to ad-hoc parsing of `.derived/**`.

If any file is missing: log "not found" and continue.

## Available Agents

Agents live in `.claude/agents/`. Four pipeline agents handle the plan/explore/implement/review cycle:

- `architect`: plans and decomposes tasks, validates approaches against specs. Read-only.
- `explorer`: searches the codebase, traces dependencies, gathers context. Read-only.
- `implementer`: executes focused code changes from an existing plan. Produces minimal diffs.
- `reviewer`: post-change review for bugs, correctness, the verify-only boundary, and spec compliance. Read-only.

## Available Commands

Commands live in `.claude/skills/` (one `SKILL.md` per folder):

- `/init`: initialize a session (load context, lifecycle, recent activity)
- `/setup`: one-time contributor setup, build the `tenant-tail` binary and verify the dogfood compile then index then lint loop works
- `/commit`: create a git commit with an impact-focused conventional message
- `/code-review`: review the current diff for correctness bugs and spec drift
- `/ship`: gate (cargo + coupling), review, commit, and PR creation in one governed sequence

## Conventions

- Items added to the "New Sessions" init protocol are auto-loaded by `/init`.
- Agents must be self-contained within `.claude/agents/`: no cross-project dependencies.
- Orchestrated workflows must read compiled artifacts (`.derived/**`) through `spec-spine` subcommands, never via ad-hoc parsers: see `.claude/rules/governed-artifact-reads.md`.
- Verify-only by construction: no emitter verb, no signing-key handling, no network/identity surface; `unsafe_code` is forbidden workspace-wide.
- Governance is the pinned spec-spine npm devDependency (`npx --no-install spec-spine`), not an in-tree binary. The product binary is `tenant-tail`.
- No em dash (U+2014) anywhere (house style); use a colon, comma, parentheses, or two sentences.
