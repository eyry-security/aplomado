"""Authenticated-scanning glue for Aplomado bug-hunting scans.

The highest-payout surface sits behind login. This module provides:

- :class:`CookieJar` — an in-memory session store. The operator pastes
  browser-exported cookies (or a bearer token) once; every bughunter tool
  built with the same jar injects them via ``-H "Cookie: …"`` / header
  flags. Two jars with two accounts enable IDOR differential testing.
- :func:`auth_tools` — the agent-facing tools: ``set_auth_session``
  stores credentials, ``show_auth_status`` reports what's configured
  (never echoes secret values back).

Secrets are never logged: status reports show presence, not content.
"""

from __future__ import annotations

from langchain_core.tools import BaseTool, StructuredTool


class CookieJar:
    """In-memory session credentials shared across bughunter tools."""

    def __init__(self) -> None:
        self._cookies: str = ""
        self._auth_header: str = ""

    def set_cookies(self, cookies: str) -> None:
        """Store a browser-exported cookie string (``a=b; c=d``)."""
        self._cookies = cookies.strip()

    def set_auth_header(self, value: str) -> None:
        """Store an Authorization header value (e.g. ``Bearer …``)."""
        value = value.strip()
        if value and not value.lower().startswith("bearer "):
            value = "Bearer " + value
        self._auth_header = value

    def cookie_header(self) -> str:
        """Return the ``Cookie: …`` header line, or ``""`` if unset."""
        if not self._cookies:
            return ""
        return f"Cookie: {self._cookies}"

    def extra_headers(self) -> list[str]:
        """All configured header lines (Cookie and/or Authorization)."""
        headers: list[str] = []
        if self._cookies:
            headers.append(f"Cookie: {self._cookies}")
        if self._auth_header:
            headers.append(f"Authorization: {self._auth_header}")
        return headers

    def configured(self) -> bool:
        return bool(self._cookies or self._auth_header)

    def status(self) -> str:
        """Presence-only status — never echoes credential content."""
        parts = [
            "cookies: set" if self._cookies else "cookies: not set",
            "authorization: set" if self._auth_header else "authorization: not set",
        ]
        return ", ".join(parts)


def auth_tools(cookie_jar: CookieJar) -> list[BaseTool]:
    """Return [set_auth_session, show_auth_status] bound to *cookie_jar*."""

    def set_auth_session(cookies: str = "", authorization: str = "") -> str:
        """Store session credentials for authenticated scanning.

        cookies: browser-exported cookie string, e.g.
        "session=abc123; csrftoken=xyz" (DevTools → Application →
        Cookies). authorization: bearer token or full "Authorization: …"
        value. Stored ONCE, then injected into every bughunter tool
        (katana, nuclei, dalfox, ffuf, curl checks). Values are never
        echoed back or logged.
        """
        if cookies.strip():
            cookie_jar.set_cookies(cookies)
        if authorization.strip():
            cookie_jar.set_auth_header(authorization)
        if not cookie_jar.configured():
            return "error: no credentials provided — pass cookies and/or authorization"
        return (
            "auth session stored. All bughunter tools will now send it. "
            f"Status: {cookie_jar.status()}."
        )

    def show_auth_status() -> str:
        """Check whether an auth session is configured (presence only)."""
        return f"auth status: {cookie_jar.status()}."

    return [
        StructuredTool.from_function(
            set_auth_session,
            name="set_auth_session",
            description=(
                "Store login session credentials ONCE for authenticated "
                "scanning: paste browser cookies and/or a bearer token. "
                "Every bughunter tool then sends them automatically. "
                "Never echoed back."
            ),
        ),
        StructuredTool.from_function(
            show_auth_status,
            name="show_auth_status",
            description=(
                "Check whether an authenticated session is configured "
                "(reports presence only, never secret values)."
            ),
        ),
    ]
