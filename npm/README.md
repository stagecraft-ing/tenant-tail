# tenant-tail (npm)

Prebuilt-binary npm distribution of the `tenant-tail` verify-only CLI. No Rust
toolchain required: `npm i -D tenant-tail` installs the matching
`@tenant-tail/cli-<os>-<cpu>` optional dependency and a thin launcher
(`bin/tenant-tail.js`) exec's it.

```sh
npm i -D tenant-tail
npx --no-install tenant-tail verify-certificate <cert-path> [--artifact-dir <run-dir>]
npx --no-install tenant-tail verify-provenance <args>
```

Pin it as an exact-version devDependency next to `spec-spine`; `npm ci` verifies
the sha512 lockfile integrity of the package and its `@tenant-tail/cli-*`
subpackages. One pin covers every verb.

This wrapper mirrors spec-spine's `npm/` shape exactly (launcher + platform
resolver + publish-time platform-package generator). The platform packages and
the binaries they carry are assembled from the release archives at publish time
and are never committed.

See the repo root `README.md` and OAP spec 219-tenant-tail-verifier-toolkit for
the toolkit's scope and status.
