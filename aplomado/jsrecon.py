"""JavaScript recon tool for Aplomado bug-hunting scans.

Collects the target's JS bundles (page <script src> tags) and mines them
for hidden API endpoints and hardcoded secrets with regex patterns
(LinkFinder/SecretFinder style). Endpoints feed IDOR/injection testing;
verified secrets are high-value findings.

Pure curl + grep -E → works in every sandbox. Read-only: never executes JS.
"""

from __future__ import annotations

import re
import shlex

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .auth import CookieJar

MAX_JSRECON_OUTPUT = 25_000
MAX_JS_FILES = 20

# Endpoint-ish patterns worth reporting.
_ENDPOINT_RE = re.compile(
    r"""(?:"|')(/(?:api|v\d|graphql|rest|internal|admin)[A-Za-z0-9_\-./{}]*)"""
)
_URL_RE = re.compile(r"""https?://[A-Za-z0-9_\-./?=&%]+""")

# High-confidence secret patterns (name → regex). Report only; the agent
# must verify a key is live before claiming it.
_SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "slack_token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "stripe_key": r"sk_live_[0-9a-zA-Z]{16,}",
    "github_token": r"ghp_[0-9A-Za-z]{30,}",
    "firebase_key": r"AIza[0-9A-Za-z\-_]{35}",
    "generic_secret_assign": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][0-9A-Za-z\-_.]{16,}['\"]",
}


def js_recon_tool(sandbox: Sandbox, cookie_jar: CookieJar | None = None) -> BaseTool:
    """Build the JS-recon tool bound to *sandbox*."""

    def _fetch(url: str) -> str:
        cmd = f"curl -sk --max-time 25 {shlex.quote(url)}"
        if cookie_jar is not None:
            header = cookie_jar.cookie_header()
            if header:
                cmd += f" -H {shlex.quote(header)}"
        try:
            result = sandbox.exec(cmd, timeout=60.0)
        except Exception:  # noqa: BLE001 - surface to the model
            return ""
        return result.stdout

    def js_recon(url: str) -> str:
        """Mine a page's JavaScript for endpoints and secrets.

        url: target page URL.
        Fetches the page, collects <script src> bundles (up to 20),
        downloads each, and extracts: API-ish endpoint paths, absolute
        URLs, and high-confidence secret patterns. Endpoints are leads
        for IDOR/injection testing; secrets must be verified live
        before reporting.
        """
        page = _fetch(url)
        if not page:
            return f"error: could not fetch {url}"
        scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', page, re.IGNORECASE
        )
        # Resolve relative script URLs against the page origin.
        origin = re.match(r"(https?://[^/]+)", url)
        base = origin.group(1) if origin else url
        js_urls: list[str] = []
        for src in scripts[:MAX_JS_FILES]:
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("//"):
                js_urls.append("https:" + src)
            elif src.startswith("/"):
                js_urls.append(base + src)
        endpoints: set[str] = set()
        abs_urls: set[str] = set()
        secrets: dict[str, set[str]] = {k: set() for k in _SECRET_PATTERNS}
        for js_url in js_urls:
            body = _fetch(js_url)
            if not body:
                continue
            for m in _ENDPOINT_RE.finditer(body):
                endpoints.add(m.group(1))
            for m in _URL_RE.finditer(body):
                abs_urls.add(m.group(0)[:120])
            for name, pat in _SECRET_PATTERNS.items():
                for m in re.finditer(pat, body):
                    secrets[name].add(m.group(0)[:80])
        out = [f"$ js_recon {url}", f"[{len(js_urls)} JS bundles fetched]"]
        out.append(f"\n[{len(endpoints)} endpoint paths]")
        out.extend(sorted(endpoints)[:100])
        live_secrets = {k: v for k, v in secrets.items() if v}
        out.append(f"\n[{sum(len(v) for v in live_secrets.values())} secret-pattern hits]")
        for name, vals in live_secrets.items():
            for v in sorted(vals)[:5]:
                out.append(f"  {name}: {v}")
        out.append(
            "\nNOTE: secret hits are CANDIDATES — verify a key is live "
            "(e.g. provider API check) before reporting."
        )
        text = "\n".join(out)
        if len(text) > MAX_JSRECON_OUTPUT:
            text = text[:MAX_JSRECON_OUTPUT] + (
                f"\n…[truncated at {MAX_JSRECON_OUTPUT} chars]"
            )
        return text

    return StructuredTool.from_function(
        js_recon,
        name="js_recon",
        description=(
            "Mine a page's JavaScript bundles for hidden API endpoints and "
            "hardcoded secrets. Returns endpoint paths (leads for IDOR / "
            "injection testing) and secret-pattern hits (verify live "
            "before reporting)."
        ),
    )
