"""Spec: specs/003-distribution/spec.md (unsupported hosts fail clearly).

The `tenant-tail` console entry point shipped by the sdist. It is reached only on
a host with no prebuilt wheel (musl/Alpine, win-arm64, 32-bit, ...), because on a
supported host the platform wheel's bundled binary IS the `tenant-tail` command
and this module is never installed. Its whole job is to name the host, explain
why there is no binary, and point at the source-build escape hatch: the exact
posture of npm/lib/platform.js's unsupported-host message. It never tries to run
anything; it exits non-zero.
"""

from __future__ import annotations

import sys

from . import platform_map


def main() -> int:
    host = platform_map.detect_host()
    sys.stderr.write(
        platform_map.unsupported_message(host["os"], host["cpu"], host["reason"]) + "\n"
    )
    return 1


if __name__ == "__main__":  # `python -m tenant_tail._refuse`
    raise SystemExit(main())
