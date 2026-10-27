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
from .binaries import require_binary
from .buffers import FullOutput

DALFOX_VERSION = "v3.2.4"
DALFOX_BIN = "dalfox"

MAX_DALFOX_OUTPUT = 20_000


def _ensure_dalfox(sandbox: Sandbox) -> str | None:
    """Verify the dalfox binary is pre-installed in the sandbox image."""
    return require_binary(sandbox, DALFOX_BIN, label="dalfox")


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
            f"echo {shlex.quote(url)} | {DALFOX_BIN} pipe "
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
            return FullOutput(
                out[:MAX_DALFOX_OUTPUT]
                + f"\n…[truncated at {MAX_DALFOX_OUTPUT} chars]",
                full=out,
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
