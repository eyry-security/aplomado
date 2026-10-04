"""Sandboxed Python scratchpad tool for Aplomado scans."""

from __future__ import annotations

from collections.abc import Callable

from langchain_core.tools import BaseTool, StructuredTool
from pinnace import Sandbox, builtin_tools

SCRATCHPAD_PATH = "_scratchpad.py"
SCRATCHPAD_TIMEOUT_SECONDS = 30.0
SandboxProvider = Sandbox | Callable[[], Sandbox]


def _resolve_sandbox(provider: SandboxProvider) -> Sandbox:
    return provider() if callable(provider) else provider


def _format_exec(command: str, result) -> str:
    output = f"$ {command}\n{result.stdout}"
    if result.stderr.strip():
        output += f"\n[stderr]\n{result.stderr}"
    output += f"\n[exit {result.exit_code}]"
    if result.truncated:
        output += " (truncated)"
    return output


def python_scratchpad_tool(sandbox: SandboxProvider) -> BaseTool:
    """Build a tool that writes and runs Python code inside ``sandbox``."""

    def python_scratchpad(code: str) -> str:
        """Run Python 3 code in the scan sandbox and return its output.

        Use this for custom analysis, parsing, data munging, and calculations.
        Code runs from a fixed scratch file with a 30-second timeout. The
        standard library is available; package installs and network access are
        not guaranteed.
        """
        try:
            active_sandbox = _resolve_sandbox(sandbox)
            active_sandbox.write_file(SCRATCHPAD_PATH, code)
            result = active_sandbox.exec(
                f"python3 {SCRATCHPAD_PATH}",
                timeout=SCRATCHPAD_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 - return failures to the model
            return f"error: {exc}"
        return _format_exec(f"python3 {SCRATCHPAD_PATH}", result)

    return StructuredTool.from_function(
        python_scratchpad,
        name="python_scratchpad",
        description=(
            "Run Python 3 code (standard library) in the scan sandbox. "
            "Returns stdout, stderr, and exit code."
        ),
    )


def scratchpad_tools(sandbox: SandboxProvider) -> list[BaseTool]:
    """Return the Aplomado tool unless Pinnace already provides it.

    ``builtin_tools`` only closes over the sandbox while constructing schemas,
    so a deferred provider is safe here and keeps Pinnace responsible for
    creating its default sandbox.
    """
    if any(tool.name == "python_scratchpad" for tool in builtin_tools(sandbox)):  # type: ignore[arg-type]
        return []
    return [python_scratchpad_tool(sandbox)]
