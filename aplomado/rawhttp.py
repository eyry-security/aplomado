"""Raw HTTP tool for Aplomado scans, built on curl inside the sandbox.

The shell can already run curl, but a dedicated tool gives the agent a typed
request surface (method, headers, body, TLS/redirect controls) and keeps the
auth cookie jar applied automatically. This is the tool for replaying a
finding's exact request/response as evidence.
"""

from __future__ import annotations

import re
import shlex

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .auth import CookieJar
from .buffers import FullOutput

MAX_HTTP_OUTPUT = 30_000
_METHOD_RE = re.compile(r"^[A-Z]{3,10}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+:\s*.*$")


def _header_args(headers: str) -> tuple[list[str], str | None]:
    args: list[str] = []
    for raw in (headers or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not _HEADER_RE.match(line):
            return [], f"error: invalid header line {line!r}"
        args.extend(["-H", shlex.quote(line)])
    return args, None


def curl_tool(sandbox: Sandbox, cookie_jar: CookieJar | None = None) -> BaseTool:
    """Build the raw-HTTP curl tool bound to *sandbox*."""

    def curl(
        url: str,
        method: str = "GET",
        headers: str = "",
        data: str = "",
        follow_redirects: bool = True,
        include_headers: bool = True,
        timeout: int = 30,
    ) -> str:
        """Send one raw HTTP request with curl and return the response.

        url: absolute target URL (http:// or https://).
        method: HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
        headers: optional newline-separated request headers, e.g.
        "Content-Type: application/json". data: optional raw request body.
        follow_redirects: follow 3xx (default true). include_headers: prefix
        response headers (default true). timeout: seconds (default 30).
        The configured auth cookie jar is sent automatically.
        """
        target = (url or "").strip()
        if not target.lower().startswith(("http://", "https://")):
            return "error: url must start with http:// or https://"
        verb = (method or "GET").strip().upper()
        if not _METHOD_RE.match(verb):
            return f"error: invalid HTTP method {method!r}"
        try:
            seconds = max(1, min(int(timeout), 300))
        except (TypeError, ValueError):
            return "error: timeout must be an integer number of seconds"
        header_args, err = _header_args(headers)
        if err:
            return err

        cmd = [
            "curl", "-sk", "--max-time", str(seconds), "-X", verb,
        ]
        if follow_redirects:
            cmd.append("-L")
        if include_headers:
            cmd.append("-i")
        cmd.extend(header_args)
        if cookie_jar is not None:
            for extra in cookie_jar.extra_headers():
                cmd.extend(["-H", shlex.quote(extra)])
        if data:
            cmd.extend(["--data-raw", shlex.quote(data)])
        cmd.append(shlex.quote(target))
        shown = f"{verb} {target}" + (" [body]" if data else "")

        try:
            result = sandbox.exec(" ".join(cmd), timeout=float(seconds + 15))
        except Exception as e:  # noqa: BLE001 - surface to the model
            return f"error: curl failed: {e}"
        out = (
            f"$ curl {shown}\n[exit {result.exit_code}]\n{result.stdout}"
        )
        if result.stderr.strip():
            out += f"\n[stderr]\n{result.stderr.strip()}"
        if len(out) > MAX_HTTP_OUTPUT:
            return FullOutput(
                out[:MAX_HTTP_OUTPUT]
                + f"\n…[truncated at {MAX_HTTP_OUTPUT} chars]",
                full=out,
            )
        return out

    return StructuredTool.from_function(
        curl,
        name="curl",
        description=(
            "Send a raw HTTP request with curl (any method, custom headers, "
            "request body, redirect/TLS options). The auth cookie jar is "
            "applied automatically. Use this to replay a finding's exact "
            "request and capture request/response evidence."
        ),
    )
