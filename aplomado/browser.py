"""Headless-Chrome tools for Aplomado: authenticated screenshots + DevTools.

One headless Chrome instance lives for the whole scan (state under
``scratch/.browser/``), so calls reuse the same browser and the same session
as the curl tools. Authentication comes from the canonical jar
``scratch/cookies.txt``; cookies set by the browser are written back there.

The DevTools surface is the standard ``chrome-devtools-mcp`` server, shipped
in the sandbox image. Each tool call talks to the persistent Chrome through a
small Node bridge; the bridge starts Chrome once and proxies MCP calls.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import shlex
import time
from pathlib import Path
from urllib.parse import urlsplit

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import create_model

from pinnace.sandbox import Sandbox

from .auth import CookieJar
from .command_policy import resolve_shell_timeout

SHOT_DIR = "scratch/shots"
BROWSER_STATE_DIR = "scratch/.browser"
BRIDGE_PATH = f"{BROWSER_STATE_DIR}/bridge.mjs"
BROWSER_TIMEOUT_SECONDS = 120.0
MAX_BROWSER_OUTPUT = 30_000

# URL/title hints that mean "this is the login page, not the app".
_LOGIN_SEGMENTS = {
    "login", "log-in", "log_in", "signin", "sign-in", "sign_in",
    "auth", "authenticate", "sso", "session/new", "users/sign_in",
}
_LOGIN_TITLE_HINTS = ("login", "log in", "sign in", "signin")


class BrowserError(RuntimeError):
    """A browser action failed before producing a usable result."""


def _browser_timeout(value: float | None) -> float:
    return resolve_shell_timeout(
        BROWSER_TIMEOUT_SECONDS if value is None else value
    )


def _safe_component(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", (value or "").strip())
    return (safe.strip(".") or "shot")[:80]


def screenshot_path(url: str, full_page: bool = True) -> str:
    """Return the scratch path for a shot of *url* (stable per URL)."""
    host = urlsplit(url).hostname or "page"
    digest = hashlib.sha1(
        f"{url}|{bool(full_page)}".encode("utf-8", "replace")
    ).hexdigest()[:10]
    return f"{SHOT_DIR}/{_safe_component(host)}_{digest}.png"


def is_login_url(
    final_url: str,
    original_url: str = "",
    title: str = "",
) -> bool:
    """True when *final_url* looks like a login screen rather than the app."""
    try:
        parsed = urlsplit(final_url or "")
    except ValueError:
        return False
    path = (parsed.path or "/").strip("/").lower()
    segments = {segment for segment in path.split("/") if segment}
    if segments & _LOGIN_SEGMENTS:
        return True
    if any(hint in path for hint in ("login", "signin", "sign-in", "sign_in")):
        return True
    lowered_title = (title or "").strip().lower()
    if any(hint in lowered_title for hint in _LOGIN_TITLE_HINTS):
        if not any(word in lowered_title for word in ("logout", "log out", "sign out")):
            return True
    return False


def _format_mcp_result(result: dict) -> str:
    """Render an MCP tools/call result as agent-facing text."""
    content = result.get("content") if isinstance(result, dict) else None
    if not isinstance(content, list):
        return json.dumps(result, ensure_ascii=False) if result else "(no output)"
    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            parts.append(str(item))
            continue
        if item.get("type") == "text":
            parts.append(str(item.get("text") or ""))
        elif item.get("type") in {"image", "blob"}:
            parts.append("[binary browser output omitted; use the screenshot tool]")
        else:
            parts.append(json.dumps(item, ensure_ascii=False))
    text = "\n".join(part for part in parts if part)
    if len(text) > MAX_BROWSER_OUTPUT:
        text = text[:MAX_BROWSER_OUTPUT] + (
            f"\n…[truncated at {MAX_BROWSER_OUTPUT} chars]"
        )
    return text or "(no output)"


class BrowserSession:
    """A single persistent headless-Chrome session bound to one sandbox."""

    def __init__(
        self,
        sandbox: Sandbox,
        cookie_jar: CookieJar | None = None,
        *,
        runner=None,
    ) -> None:
        self.sandbox = sandbox
        self.cookie_jar = cookie_jar or CookieJar(sandbox)
        self.runner = runner
        self._bridge_written = False

    # -- bridge plumbing -------------------------------------------------
    def _write_bridge(self) -> None:
        if self._bridge_written:
            return
        source = Path(__file__).with_name("browser_bridge.mjs").read_text(
            encoding="utf-8"
        )
        self.sandbox.write_file(BRIDGE_PATH, source)
        self._bridge_written = True

    def _call(self, payload: dict, timeout: float) -> dict:
        payload.setdefault("state_dir", BROWSER_STATE_DIR)
        payload.setdefault("timeout_ms", int(timeout * 1000))
        if self.runner is not None:
            result = self.runner(payload, timeout)
        else:
            self._write_bridge()
            command = (
                f"node {shlex.quote(BRIDGE_PATH)} "
                f"{shlex.quote(json.dumps(payload, separators=(',', ':')))}"
            )
            result = self.sandbox.exec(command, timeout=timeout)
            text = (result.stdout or "").strip()
            lines = [line for line in text.splitlines() if line.strip()]
            if not lines:
                detail = (result.stderr or "").strip().splitlines()
                detail_text = f": {detail[0]}" if detail else ""
                raise BrowserError(
                    f"browser bridge produced no result "
                    f"(exit {result.exit_code}){detail_text}"
                )
            try:
                result = json.loads(lines[-1])
            except json.JSONDecodeError as exc:
                raise BrowserError(
                    f"browser bridge returned invalid JSON: {exc}"
                ) from exc
        if not isinstance(result, dict):
            raise BrowserError("browser bridge returned an invalid result")
        if not result.get("ok", False):
            raise BrowserError(str(result.get("error") or "browser action failed"))
        cookies = result.get("cookies")
        if isinstance(cookies, list) and cookies:
            self.cookie_jar.save_browser_cookies(cookies)
        return result

    # -- actions ---------------------------------------------------------
    def capture(
        self,
        url: str,
        *,
        full_page: bool = True,
        timeout_seconds: float | None = None,
    ) -> dict:
        """Capture a PNG of *url* and return path/title/final URL metadata."""
        timeout = _browser_timeout(timeout_seconds)
        output_path = screenshot_path(url, full_page)
        result = self._call(
            {
                "action": "screenshot",
                "url": url,
                "full_page": bool(full_page),
                "output_path": output_path,
                "cookies": self.cookie_jar.browser_cookies(url),
            },
            timeout,
        )
        final_url = str(result.get("final_url") or url)
        title = str(result.get("title") or "")
        return {
            "path": str(result.get("path") or output_path),
            "title": title,
            "final_url": final_url,
            "login": is_login_url(final_url, url, title),
        }

    def auth(self, url: str, *, timeout_seconds: float | None = None) -> int:
        """Load the canonical jar's cookies into the browser for *url*."""
        timeout = _browser_timeout(timeout_seconds)
        cookies = self.cookie_jar.browser_cookies(url)
        self._call(
            {
                "action": "auth",
                "url": url,
                "cookies": cookies,
            },
            timeout,
        )
        return len(cookies)

    def call(
        self,
        tool: str,
        arguments: dict | None = None,
        *,
        url: str = "",
        timeout_seconds: float | None = None,
    ) -> str:
        """Call one standard DevTools MCP tool against the persistent browser."""
        timeout = _browser_timeout(timeout_seconds)
        payload = {
            "action": "mcp",
            "tool": tool,
            "arguments": arguments or {},
            "url": url,
        }
        if url:
            payload["cookies"] = self.cookie_jar.browser_cookies(url)
        result = self._call(payload, timeout)
        return _format_mcp_result(result.get("result") or {})


def format_screenshot(result: dict) -> str:
    """Format a capture result for the agent, including auth expiry."""
    lines = [
        f"screenshot: {result['path']}",
        f"title: {result.get('title') or '(untitled)'}",
        f"final_url: {result.get('final_url') or ''}",
    ]
    if result.get("login"):
        lines.append(
            "warning: final URL looks like the login page — auth likely "
            "expired. Re-login through scratch/cookies.txt and retry."
        )
    return "\n".join(lines)


def screenshot_tool(
    sandbox: Sandbox,
    cookie_jar: CookieJar | None = None,
    *,
    session: BrowserSession | None = None,
    runner=None,
) -> BaseTool:
    """Build the authenticated ``screenshot`` tool."""
    active = session or BrowserSession(
        sandbox, cookie_jar, runner=runner
    )

    def screenshot(url: str, full_page: bool = True) -> str:
        """Capture a PNG of a URL with the run's authenticated session.

        url: page to load. full_page: capture the whole page (default true).
        Cookies are read from scratch/cookies.txt and set for the target host
        before navigation, so behind-login pages render authenticated. Returns
        the PNG path under scratch/shots/, the page title, and the final URL.
        If the final URL is the login page, the result says auth likely expired.
        """
        try:
            result = active.capture(url, full_page=full_page)
        except Exception as exc:  # noqa: BLE001 - the agent sees failures
            return f"error: screenshot failed: {exc}"
        return format_screenshot(result)

    return StructuredTool.from_function(
        screenshot,
        name="screenshot",
        description=(
            "Capture an authenticated PNG screenshot with headless Chrome. "
            "Loads the URL with cookies from scratch/cookies.txt, saves under "
            "scratch/shots/, and returns the path, page title, and final URL. "
            "Warns when the final URL is the login page (auth expired)."
        ),
    )


def browser_auth_tool(
    sandbox: Sandbox,
    cookie_jar: CookieJar | None = None,
    *,
    session: BrowserSession | None = None,
    runner=None,
) -> BaseTool:
    """Build the explicit ``browser_auth`` helper."""
    active = session or BrowserSession(sandbox, cookie_jar, runner=runner)

    def browser_auth(url: str) -> str:
        """Load scratch/cookies.txt cookies into the browser for a URL's host.

        Call before browser work if you want to be explicit; navigate_page
        also does this automatically. Cookie changes made by the browser are
        written back to scratch/cookies.txt.
        """
        try:
            count = active.auth(url)
        except Exception as exc:  # noqa: BLE001
            return f"error: browser auth failed: {exc}"
        host = urlsplit(url).hostname or url
        return (
            f"browser auth: loaded {count} cookie(s) for {host} from "
            "scratch/cookies.txt"
        )

    return StructuredTool.from_function(
        browser_auth,
        name="browser_auth",
        description=(
            "Load the canonical cookie jar (scratch/cookies.txt) into the "
            "headless browser for a URL's domain. navigate_page also applies "
            "the jar automatically; use this to re-auth explicitly."
        ),
    )


# Standard chrome-devtools-mcp surface. Each tuple is
# (name, description, [(param, annotation, required/default), ...]).
_DEVTOOLS_SURFACE = [
    ("navigate_page", "Navigate the browser to a URL.", [("url", str, True)]),
    ("new_page", "Open a new browser page at a URL.", [("url", str, True)]),
    ("list_pages", "List open browser pages.", []),
    ("select_page", "Select a page by its index.", [("pageIdx", int, True)]),
    ("close_page", "Close a page by its index.", [("pageIdx", int, True)]),
    (
        "evaluate_script",
        "Evaluate JavaScript in the page and return the result.",
        [("function", str, True)],
    ),
    ("take_snapshot", "Read the rendered DOM/accessibility snapshot.", []),
    ("take_screenshot", "Take a DevTools screenshot of the current page.", []),
    ("list_console_messages", "Read console messages from the page.", []),
    ("list_network_requests", "Read network requests from the page.", []),
    (
        "get_network_request",
        "Read one network request by id.",
        [("reqid", str, True)],
    ),
    ("click", "Click an element by snapshot uid.", [("uid", str, True)]),
    (
        "fill",
        "Fill an input by snapshot uid.",
        [("uid", str, True), ("value", str, True)],
    ),
    (
        "fill_form",
        "Fill multiple form fields by snapshot uid.",
        [("elements", list, True)],
    ),
    ("type_text", "Type text into the focused element.", [("text", str, True)]),
    ("press_key", "Press a keyboard key.", [("key", str, True)]),
    ("hover", "Hover an element by snapshot uid.", [("uid", str, True)]),
    (
        "wait_for",
        "Wait for text or a condition in the page.",
        [("text", str, False)],
    ),
    (
        "handle_dialog",
        "Accept or dismiss a browser dialog.",
        [("action", str, True)],
    ),
    (
        "resize_page",
        "Resize the browser viewport.",
        [("width", int, True), ("height", int, True)],
    ),
]

DEVTOOLS_TOOL_NAMES = tuple(item[0] for item in _DEVTOOLS_SURFACE)


def _make_devtools_tool(name: str, description: str, parameters, active):
    def invoke(**kwargs):
        timeout = kwargs.pop("timeout_seconds", BROWSER_TIMEOUT_SECONDS)
        url = str(kwargs.get("url") or "")
        try:
            return active.call(
                name,
                kwargs,
                url=url,
                timeout_seconds=timeout,
            )
        except Exception as exc:  # noqa: BLE001 - the agent sees failures
            return f"error: {name} failed: {exc}"

    invoke.__name__ = name
    invoke.__doc__ = description
    signature = []
    for param_name, annotation, required in parameters:
        if required:
            signature.append(
                inspect.Parameter(
                    param_name,
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=annotation,
                )
            )
        else:
            default = "" if annotation is str else None
            signature.append(
                inspect.Parameter(
                    param_name,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=annotation,
                )
            )
    signature.append(
        inspect.Parameter(
            "timeout_seconds",
            inspect.Parameter.KEYWORD_ONLY,
            default=BROWSER_TIMEOUT_SECONDS,
            annotation=float,
        )
    )
    invoke.__signature__ = inspect.Signature(signature)
    fields = {}
    for param_name, annotation, required in parameters:
        fields[param_name] = (
            annotation,
            ... if required else ("" if annotation is str else None),
        )
    fields["timeout_seconds"] = (float, BROWSER_TIMEOUT_SECONDS)
    schema = create_model(f"{name.title().replace('_', '')}Input", **fields)
    return StructuredTool.from_function(
        invoke,
        name=name,
        description=(
            f"{description} Uses the shared headless Chrome DevTools session. "
            "timeout_seconds defaults to 120 and is capped at 1200."
        ),
        args_schema=schema,
    )


def browser_tools(
    sandbox: Sandbox,
    cookie_jar: CookieJar | None = None,
    *,
    session: BrowserSession | None = None,
    runner=None,
) -> list[BaseTool]:
    """Return [browser_auth, standard chrome-devtools-mcp tools]."""
    active = session or BrowserSession(sandbox, cookie_jar, runner=runner)
    tools = [browser_auth_tool(sandbox, cookie_jar, session=active, runner=runner)]
    tools.extend(
        _make_devtools_tool(name, description, parameters, active)
        for name, description, parameters in _DEVTOOLS_SURFACE
    )
    return tools


def capture_screenshot(
    sandbox: Sandbox,
    url: str,
    *,
    full_page: bool = True,
    cookie_jar: CookieJar | None = None,
    session: BrowserSession | None = None,
    runner=None,
    timeout_seconds: float | None = None,
) -> dict:
    """Convenience API: capture one screenshot and return its metadata."""
    active = session or BrowserSession(sandbox, cookie_jar, runner=runner)
    return active.capture(
        url,
        full_page=full_page,
        timeout_seconds=timeout_seconds,
    )
