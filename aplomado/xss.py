"""dalfox XSS-scanner tool for Aplomado bug-hunting scans.

dalfox has the lowest false-positive rate of any automated XSS scanner
(100% reflected/stored detection, ~zero FPs in a published benchmark).
Pipe mode keeps it pipeline-native. DOM XSS is out of scope for automation.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .auth import CookieJar

DALFOX_VERSION = "v2.8.3"
DALFOX_BIN = "dalfox"
DALFOX_TARBALL_URL = (
    "https://github.com/hahwul/dalfox/releases/download/"
    f"{DALFOX_VERSION}/dalfox_{DALFOX_VERSION.lstrip('v')}_linux_amd64.tar.gz"
)

MAX_DALFOX_OUTPUT = 20_000


def _ensure_dalfox(sandbox: Sandbox) -> str | None:
    try:
        probe = sandbox.exec(f"test -x ./{DALFOX_BIN}", timeout=30.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: can't probe for the dalfox binary: {e}"
    if probe.exit_code == 0:
        return None
    code = (
        "import os, tarfile, urllib.request; "
        f"urllib.request.urlretrieve({DALFOX_TARBALL_URL!r}, 'dalfox.tar.gz'); "
        f"tarfile.open('dalfox.tar.gz').extract({DALFOX_BIN!r}); "
        f"os.chmod({DALFOX_BIN!r}, 0o755); "
        "os.remove('dalfox.tar.gz')"
    )
    try:
        dl = sandbox.exec("python3 -c " + shlex.quote(code), timeout=300.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: dalfox download failed: {e}"
    if dl.exit_code != 0:
        return f"error: dalfox download failed: {dl.stderr.strip()[:300]}"
    return None


def dalfox_tool(sandbox: Sandbox, cookie_jar: CookieJar | None = None) -> BaseTool:
    """Build the dalfox XSS-scanner tool bound to *sandbox*."""
    ready: dict = {}

    def dalfox(url: str) -> str:
        """Scan a URL for XSS with dalfox (reflected + stored).

        url: target URL — include query parameters to test, e.g.
        https://host/search?q=test. dalfox uses context-aware payloads
        with a very low false-positive rate. Confirm any finding by
        re-running the exact PoC with curl before reporting.
        """
        if not ready.get("binary"):
            err = _ensure_dalfox(sandbox)
            if err:
                return err
            ready["binary"] = True
        cmd = (
            f"echo {shlex.quote(url)} | ./{DALFOX_BIN} pipe "
            f"--format json --skip-discovery"
        )
        if cookie_jar is not None:
            header = cookie_jar.cookie_header()
            if header:
                cmd += f" -H {shlex.quote(header)}"
        try:
            result = sandbox.exec(cmd, timeout=600.0)
        except Exception as e:  # noqa: BLE001 - surface to the model
            return f"error: dalfox run failed: {e}"
        out = f"$ dalfox pipe < {url}\n[exit {result.exit_code}]\n{result.stdout}"
        if result.stderr.strip():
            out += f"\n[stderr]\n{result.stderr.strip()[:500]}"
        if len(out) > MAX_DALFOX_OUTPUT:
            out = out[:MAX_DALFOX_OUTPUT] + (
                f"\n…[truncated at {MAX_DALFOX_OUTPUT} chars]"
            )
        return out

    return StructuredTool.from_function(
        dalfox,
        name="dalfox",
        description=(
            "XSS scan with dalfox: reflected and stored XSS with very low "
            "false positives. Give it URLs with parameters to test. Confirm "
            "findings with curl before reporting."
        ),
    )
