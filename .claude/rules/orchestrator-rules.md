# Orchestrator rules

- Execute phased work in order; stop at human checkpoints.
- Write output files where the spec says; do not invent locations.
- Keep the working tree green; never leave the coupling gate red.
- Recompute derived artifacts via the pinned spec-spine (`npx --no-install spec-spine compile`, then `... index`) before opening a PR.
