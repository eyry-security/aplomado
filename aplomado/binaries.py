"""Locate the pre-installed bug-hunter binaries inside the scan sandbox.

The Aplomado sandbox image ships nuclei, ffuf, dalfox, katana, sqlmap, and
curl at fixed paths. Tools only verify that their binary is present; they
never bootstrap downloads at scan time. That keeps scoring deterministic
without relaxing the sandbox command policy.
"""

from __future__ import annotations

import shlex

from pinnace.sandbox import Sandbox

BIN_DIR = "/usr/local/bin"


def binary_path(name: str, bin_dir: str = BIN_DIR) -> str:
    """Return the expected absolute path for a bundled sandbox binary."""
    return f"{bin_dir}/{name}"


def require_binary(
    sandbox: Sandbox,
    name: str,
    *,
    label: str | None = None,
    bin_dir: str = BIN_DIR,
) -> str | None:
    """Return None when *name* is executable, else a model-visible error.

    No network fetch, no package install: if the sandbox image is missing a
    tool the model is told to continue with the remaining tools/manual HTTP.
    """
    label = label or name
    path = binary_path(name, bin_dir)
    try:
        probe = sandbox.exec(f"test -x {shlex.quote(path)}", timeout=30.0)
    except Exception as exc:  # noqa: BLE001 - surface to the model
        return f"error: can't probe for {label}: {exc}"
    if probe.exit_code == 0:
        return None
    return (
        f"error: {label} is not installed in the sandbox image ({path}). "
        "Rebuild the Aplomado sandbox image with the bug-hunter toolchain; "
        "no runtime download is attempted."
    )
