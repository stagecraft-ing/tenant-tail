#!/usr/bin/env bash
# Git merge driver `tenant-tail-derived-regen` for the committed derived
# artifacts (spec-spine 0.5.0 shards them per-spec / per-package):
#   .derived/spec-registry/by-spec/*.json                 (compiler output)
#   .derived/codebase-index/by-spec/*.json, by-package/*.json (indexer output)
#
# Each shard carries a content hash, so two branches that each regenerated them
# conflict textually on the hash line. This driver resolves that conflict
# deterministically: it regenerates BOTH artifacts from the merged working tree
# (via the pinned spec-spine governing binary) and hands the fresh artifact named
# by %P back to git as the resolution.
#
# Enable in this clone (opt-in, one command):
#   ./.githooks/enable-merge-driver.sh
#
# Path assignment lives in committed .gitattributes:
#   .derived/**/*.json   merge=tenant-tail-derived-regen
#
# Git invokes:  <driver> %O %A %B %P
#   $1 = %O  ancestor version  (unused: both artifacts are fully derived)
#   $2 = %A  ours temp file     (the driver MUST leave the merged result here and exit 0)
#   $3 = %B  theirs version     (unused)
#   $4 = %P  pathname being merged
#
# Fail-closed: if no spec-spine governing binary is found or regeneration fails,
# exit 1 and leave the conflict in place. The CI staleness gate
# (`spec-spine index check`) remains the freshness source of truth; this driver
# is a convenience over the conflict, never a replacement for the gate.
#
# Mirror of spec-spine's `.githooks/merge-derived-index.sh`. tenant-tail dogfoods
# the PINNED spec-spine library (a devDependency), so the regen runs through
# `npx --no-install spec-spine` rather than a local spec-spine build.

set -eu

OURS="${2:?merge driver expects %A as \$2}"
PATHNAME="${4:-<unknown>}"

root="$(git rev-parse --show-toplevel)"
cd "$root"

# Resolve the governing binary: prefer the pinned dogfood toolchain
# (`npx --no-install spec-spine`), then a `spec-spine` already on PATH.
run_ss() {
  if npx --no-install spec-spine --version >/dev/null 2>&1; then
    npx --no-install spec-spine "$@"
  elif command -v spec-spine >/dev/null 2>&1; then
    spec-spine "$@"
  else
    return 127
  fi
}

if ! run_ss --version >/dev/null 2>&1; then
  cat >&2 <<EOF
[merge-derived-index] no spec-spine governing binary found; cannot auto-resolve $PATHNAME.
            Install the pinned toolchain (\`npm ci\`), then re-run the rebase/merge,
            or resolve manually:
                npx --no-install spec-spine compile && npx --no-install spec-spine index && git add .derived/
EOF
  exit 1
fi

# Regenerate BOTH artifacts from the merged working tree. The compiler/indexer
# are deterministic for a given committed input set, so the regenerated pair is
# the correct union of both branches' input changes.
if ! run_ss compile >/dev/null 2>&1 || ! run_ss index >/dev/null 2>&1; then
  cat >&2 <<EOF
[merge-derived-index] \`spec-spine compile && index\` failed; leaving conflict in
            $PATHNAME for manual resolution
            (\`npx --no-install spec-spine compile && npx --no-install spec-spine index && git add .derived/\`).
EOF
  exit 1
fi

# Hand the freshly regenerated artifact named by %P back to git as the result.
if [ ! -f "$PATHNAME" ]; then
  echo "[merge-derived-index] regenerated tree has no $PATHNAME; leaving conflict." >&2
  exit 1
fi
cp "$PATHNAME" "$OURS"
echo "[merge-derived-index] regenerated $PATHNAME from the merged tree." >&2
exit 0
