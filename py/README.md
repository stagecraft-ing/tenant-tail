# tenant-tail (Python / uvx)

The `tenant-tail` verification toolkit for Python users: re-check a factory's
run-side paperwork (governance certificate, provenance) with no trust in the
producer. Ships the prebuilt binary; **no Rust toolchain required**.

```sh
uvx tenant-tail verify-certificate    # run the CLI with no install
uv tool install tenant-tail           # or install it as a persistent tool
pip install tenant-tail               # or into a project/venv
```

## How it works

This is a **binary distribution**, not a Python binding. There is no native
extension and the engine is never called from Python. The project publishes:

- **five platform wheels**, one per supported target, each carrying the prebuilt
  `tenant-tail` binary in the wheel's scripts directory. pip/uv select the one
  matching your host by its platform tag and install the binary onto `PATH`. On a
  supported host there is **no Python in the run path and no network at install**
  beyond fetching the wheel itself; it works offline from a warm cache or a
  private mirror, and under `--no-binary`-free resolution.
- **one sdist**, the unsupported-host fallback. It builds only when no wheel
  matches (musl/Alpine, win-arm64, 32-bit), and its `tenant-tail` command prints a
  clear message pointing at `cargo install tenant-tail-cli`.

This mirrors the npm shim (spec 003): npm uses `os`/`cpu`-gated
`optionalDependencies`; Python uses wheel platform tags. One project, many
wheels.

## Supported targets

| host | wheel platform tag | release triple |
|---|---|---|
| macOS arm64 | `macosx_11_0_arm64` | `aarch64-apple-darwin` |
| macOS x86_64 | `macosx_10_12_x86_64` | `x86_64-apple-darwin` |
| Linux x86_64 (glibc) | `manylinux_2_17_x86_64` | `x86_64-unknown-linux-gnu` |
| Linux arm64 (glibc) | `manylinux_2_17_aarch64` | `aarch64-unknown-linux-gnu` |
| Windows x86_64 | `win_amd64` | `x86_64-pc-windows-msvc` |

Linux binaries are **glibc**. Alpine/musl hosts have no wheel and must use
`cargo install tenant-tail-cli` or a glibc-based image.

## License

Apache-2.0. See [LICENSE](./LICENSE).
