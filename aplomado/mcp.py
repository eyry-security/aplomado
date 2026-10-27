"""MCP server registration metadata for Aplomado's browser toolkit.

The sandbox image preinstalls ``chrome-devtools-mcp``; Aplomado registers it as
the ``chrome-devtools`` server and wraps its standard tools as agent tools
(see :mod:`aplomado.browser`). The browser itself is started by the bridge so
the same Chrome instance is reused for every call in a run.
"""

from __future__ import annotations

CHROME_DEVTOOLS_MCP_SERVER = "chrome-devtools"
CHROME_DEVTOOLS_MCP_BIN = "chrome-devtools-mcp"
CHROME_DEVTOOLS_MCP_PACKAGE = "chrome-devtools-mcp"


def chrome_devtools_mcp_config(
    *,
    browser_url: str | None = None,
    executable_path: str | None = None,
    headless: bool = True,
) -> dict:
    """Return the MCP server registration for Chrome DevTools.

    ``browser_url`` connects the MCP server to the persistent Chrome instance
    the Aplomado bridge already launched; ``executable_path`` is only needed
    when the server should launch Chrome itself.
    """
    args = [
        CHROME_DEVTOOLS_MCP_BIN,
        "--no-page-id-routing",
        "--no-usage-statistics",
        "--no-performance-crux",
    ]
    if headless:
        args.insert(1, "--headless")
    if browser_url:
        args.extend(["--browserUrl", browser_url])
    elif executable_path:
        args.extend(["--executablePath", executable_path])
    return {
        "name": CHROME_DEVTOOLS_MCP_SERVER,
        "command": args[0],
        "args": args[1:],
        "env": {
            "CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS": "1",
            "CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS": "1",
        },
    }


def mcp_server_registry() -> dict:
    """Return all MCP servers Aplomado registers with the agent loop."""
    config = chrome_devtools_mcp_config()
    return {config["name"]: config}
