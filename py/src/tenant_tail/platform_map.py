"""Spec: specs/003-distribution/spec.md.

The single (os, cpu) -> target table for the Python/uvx channel, plus host
detection and the unsupported-host message. This is the Python-side mirror of
npm/lib/platform.js's SUPPORTED map and the platform table in spec 003: the five
triples, the in-archive binary name, and the per-target wheel platform tag are
ONE FACT, and this module is its home on the Python side. A drift between this
table, release.yml's matrix, and npm/lib/platform.js is a governed change
(spec 003, now four places).

Pure data + pure functions: no filesystem or network on the mapping path, so the
table is unit-tested directly (test/test_platform_map.py). Used by three
consumers: scripts/generate_wheels.py (publish time), _refuse.py (runtime, on the
unsupported path), and the tests.
"""

from __future__ import annotations

import glob
import os
import platform as _platform
import sys
import sysconfig

# platform key -> release triple, npm-style (os, cpu), wheel platform tag, and
# whether the in-archive binary is `.exe`. The wheel platform tag is what makes
# pip/uv install only the matching wheel on a host: the Python analogue of
# npm's os/cpu fields. glibc is encoded by the `manylinux_*` tags: a musl host
# matches none of these and falls through to the sdist refusal (§3.4 parity).
TARGETS: dict[str, dict] = {
    "darwin-arm64": {
        "triple": "aarch64-apple-darwin",
        "os": "darwin",
        "cpu": "arm64",
        "wheel_platform": "macosx_11_0_arm64",
        "windows": False,
    },
    "darwin-x64": {
        "triple": "x86_64-apple-darwin",
        "os": "darwin",
        "cpu": "x64",
        "wheel_platform": "macosx_10_12_x86_64",
        "windows": False,
    },
    "linux-x64": {
        "triple": "x86_64-unknown-linux-gnu",
        "os": "linux",
        "cpu": "x64",
        "wheel_platform": "manylinux_2_17_x86_64",
        "windows": False,
    },
    "linux-arm64": {
        "triple": "aarch64-unknown-linux-gnu",
        "os": "linux",
        "cpu": "arm64",
        "wheel_platform": "manylinux_2_17_aarch64",
        "windows": False,
    },
    "win32-x64": {
        "triple": "x86_64-pc-windows-msvc",
        "os": "win32",
        "cpu": "x64",
        "wheel_platform": "win_amd64",
        "windows": True,
    },
}

# The Python distribution name and the importable package / data-dir stem. PyPI
# normalizes "tenant-tail" <-> "tenant_tail"; the .data/scripts and .dist-info
# directories inside a wheel use the underscore form.
DIST_NAME = "tenant-tail"
DIST_STEM = "tenant_tail"


class UnsupportedHostError(RuntimeError):
    """Raised when the running host has no prebuilt binary."""


def binary_name(windows: bool) -> str:
    """In-archive / in-wheel binary name: `.exe` on Windows, bare elsewhere."""
    return "tenant-tail.exe" if windows else "tenant-tail"


def target_for(os_name: str, cpu: str) -> dict:
    """(os, cpu) -> target record. Raises UnsupportedHostError for any host with
    no prebuilt binary. `os`/`cpu` are the npm-style names ('darwin'/'linux'/
    'win32', 'x64'/'arm64'), not Python's ('linux2', 'x86_64')."""
    key = f"{os_name}-{cpu}"
    rec = TARGETS.get(key)
    if rec is None:
        raise UnsupportedHostError(unsupported_message(os_name, cpu))
    return {"key": key, **rec, "binary_name": binary_name(rec["windows"])}


# --- runtime host detection (the unsupported / sdist path) -------------------

def _normalize_machine(machine: str) -> str | None:
    m = machine.lower()
    if m in ("arm64", "aarch64"):
        return "arm64"
    if m in ("x86_64", "amd64", "x64"):
        return "x64"
    return None  # i686/ppc64/etc. -> unsupported, surfaced clearly


def is_musl_linux() -> bool:
    """True on a musl (non-glibc) Linux. Permissive: if we cannot tell, assume
    glibc and let resolution fail loudly later (mirrors npm's isMuslLinux).

    `platform.libc_ver()` returns `('', '')` on musl (it only ever recognizes
    glibc), so an empty/non-glibc result alone is ambiguous, not proof of musl.
    Corroborate it with a second, independent signal before concluding musl:
    a musl-tagged sysconfig platform, a musl dynamic loader on disk, or a
    `CS_GNU_LIBC_VERSION` value that names musl. Any single positive signal is
    enough; genuine inability to tell falls through to the permissive `False`.
    """
    if sys.platform != "linux":
        return False
    try:
        if "musl" in (sysconfig.get_platform() or ""):
            return True
        libc, _ver = _platform.libc_ver()
        not_glibc = "glibc" not in libc.lower()
        if not_glibc and glob.glob("/lib/ld-musl-*"):
            return True
        try:
            gnu_libc_version = os.confstr("CS_GNU_LIBC_VERSION")
        except (AttributeError, ValueError, OSError):
            gnu_libc_version = None
        if gnu_libc_version and "musl" in gnu_libc_version.lower():
            return True
        return False
    except Exception:
        return False


def detect_host() -> dict:
    """Best-effort host classification for messaging. Returns a dict with `key`
    (platform key or None), `os`, `cpu`, and `reason` ('musl' | 'arch' | None)."""
    os_map = {"darwin": "darwin", "linux": "linux", "win32": "win32"}
    os_name = os_map.get(sys.platform, sys.platform)
    cpu = _normalize_machine(_platform.machine())
    if os_name == "linux" and is_musl_linux():
        return {"key": None, "os": os_name, "cpu": cpu or "?", "reason": "musl"}
    if cpu is None or f"{os_name}-{cpu}" not in TARGETS:
        return {"key": None, "os": os_name, "cpu": cpu or _platform.machine().lower(),
                "reason": "arch"}
    return {"key": f"{os_name}-{cpu}", "os": os_name, "cpu": cpu, "reason": None}


def unsupported_message(os_name: str, cpu: str, reason: str | None = None) -> str:
    host = f"{os_name}-{cpu}" + (" (musl libc)" if reason == "musl" else "")
    lines = [
        f"tenant-tail: no prebuilt binary for {host}.",
        "Prebuilt wheels cover darwin-arm64, darwin-x64, linux-x64 (glibc),",
        "linux-arm64 (glibc), and win32-x64. Install from source instead:",
        "    cargo install tenant-tail-cli",
    ]
    if reason == "musl":
        lines.append(
            "(Alpine/musl: use a glibc-based image, or cargo install tenant-tail-cli.)"
        )
    lines.append(
        "(If you are on a supported host and reached this message, you likely "
        "installed with --no-binary; reinstall allowing wheels.)"
    )
    return "\n".join(lines)
