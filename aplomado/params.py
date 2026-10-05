"""Parameter-discovery tool for Aplomado bug-hunting scans.

Hidden parameters (debug flags, mass-assignment fields, pagination keys,
SSRF sinks) are where scanners never look. This tool does arjun-style
GET-parameter bruteforcing with curl only (no extra binary): it measures
the baseline response, then appends each candidate parameter and reports
the ones that change status code or body length.

Pure curl → works in every sandbox. Quiet: one request per candidate.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .auth import CookieJar

# Common hidden-parameter candidates (debug, admin, pagination, SSRF sinks…).
PARAM_WORDLIST = [
    "id", "page", "limit", "offset", "debug", "test", "admin", "user",
    "username", "password", "token", "key", "api_key", "apikey", "redirect",
    "url", "next", "return", "returnTo", "callback", "cb", "file", "path",
    "dir", "folder", "name", "q", "query", "search", "s", "lang", "locale",
    "format", "type", "action", "do", "cmd", "exec", "order", "sort",
    "filter", "category", "cat", "mode", "view", "template", "theme",
    "callback_url", "redirect_uri", "dest", "destination", "continue",
    "ref", "referer", "host", "domain", "site", "proxy", "fetch",
]

MAX_PARAMS_OUTPUT = 15_000


def param_discovery_tool(
    sandbox: Sandbox, cookie_jar: CookieJar | None = None
) -> BaseTool:
    """Build the parameter-discovery tool bound to *sandbox*."""

    def _get(url: str) -> tuple[int, int]:
        """Return (status_code, body_length) for a GET."""
        cmd = (
            f"curl -sk -o /dev/null -w '%{{http_code}} %{{size_download}}' "
            f"--max-time 20 {shlex.quote(url)}"
        )
        if cookie_jar is not None:
            header = cookie_jar.cookie_header()
            if header:
                cmd += f" -H {shlex.quote(header)}"
        try:
            result = sandbox.exec(cmd, timeout=60.0)
        except Exception:  # noqa: BLE001 - treat as miss
            return 0, 0
        parts = result.stdout.strip().split()
        try:
            return int(parts[0]), int(parts[1])
        except (IndexError, ValueError):
            return 0, 0

    def discover_params(url: str) -> str:
        """Bruteforce hidden GET parameters on a URL.

        url: target URL (existing query string is kept).
        Appends ~60 candidate parameter names one at a time and reports
        those that change the status code or body length vs baseline —
        those are live inputs worth fuzzing. Quiet: one request per
        candidate, no payloads.
        """
        sep = "&" if "?" in url else "?"
        base_code, base_len = _get(url)
        if base_code == 0:
            return f"error: baseline request to {url} failed"
        hits: list[str] = []
        for param in PARAM_WORDLIST:
            code, length = _get(f"{url}{sep}{param}=x")
            if code != base_code or abs(length - base_len) > 50:
                hits.append(
                    f"{param}: {base_code}/{base_len} → {code}/{length}"
                )
        out = (
            f"$ discover_params {url}\n"
            f"baseline: {base_code} {base_len} bytes\n"
            f"[{len(hits)} live parameters]\n" + "\n".join(hits)
        )
        if len(out) > MAX_PARAMS_OUTPUT:
            out = out[:MAX_PARAMS_OUTPUT] + (
                f"\n…[truncated at {MAX_PARAMS_OUTPUT} chars]"
            )
        return out

    return StructuredTool.from_function(
        discover_params,
        name="discover_params",
        description=(
            "Find hidden GET parameters on a URL (debug flags, admin "
            "toggles, pagination keys, redirect/file params). One quiet "
            "request per candidate; reports params that change the "
            "response. Feed hits to dalfox/sqli."
        ),
    )
