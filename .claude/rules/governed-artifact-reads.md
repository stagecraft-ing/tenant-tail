# Governed artifact reads

tenant-tail is verify-only: it does not produce its own corpus artifacts. Its
`specs/` corpus is governed by the **pinned spec-spine library** (the dogfood
pattern), and spec-spine's compiled artifacts under `.derived/` are consumed
**only** through `spec-spine` subcommands (`npx --no-install spec-spine registry`,
`... index`), never via ad-hoc `jq`/grep over the JSON. Typed reads make schema
drift fail at the deserializer with a clean error instead of silently encoding
stale assumptions.
