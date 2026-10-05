"""Web-crawler tools for Aplomado bug-hunting scans: katana + hakrawler.

Both binaries are fetched from GitHub releases on first use and cached in
the sandbox workdir (same pattern as aplomado.fuzz). Katana is the primary
crawler (JS parsing, form extraction, known-files); hakrawler is the fast
supplemental crawler — hunters run both and merge outputs since each finds
unique URLs.

TREAD LIGHTLY: default depth is conservative; the agent must stay in scope.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .auth import CookieJar

KATANA_VERSION = "v1.1.0"
KATANA_BIN = "katana"
KATANA_ZIP_URL = (
    "https://github.com/projectdiscovery/katana/releases/download/"
    f"{KATANA_VERSION}/katana_{KATANA_VERSION.lstrip('v')}_linux_amd64.zip"
)
HAKRAWLER_BIN = "hakrawler"
# hakrawler does not keep versioned assets reliably; use the latest release.
HAKRAWLER_URL = (
    "https://github.com/hakluke/hakrawler/releases/latest/download/"
    "hakrawler-linux-amd64"
)

MAX_CRAWL_OUTPUT = 30_000


def _ensure_binary(
    sandbox: Sandbox, ready: dict, bin_name: str, fetch_cmd: str, probe: str
) -> str | None:
    """Download *bin_name* into the sandbox workdir if not present yet."""
    try:
        result = sandbox.exec(probe, timeout=30.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: can't probe for the {bin_name} binary: {e}"
    if result.exit_code == 0:
        return None
    try:
        result = sandbox.exec(fetch_cmd, timeout=300.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: {bin_name} download failed: {e}"
    if result.exit_code != 0:
        detail = result.stderr.strip()[:300]
        return f"error: {bin_name} download failed (exit {result.exit_code}): {detail}"
    return None


def _python_fetch(url: str, dest: str, unzip: str | None = None) -> str:
    """Build a python3 one-liner that downloads (and optionally unzips) a file.

    python3 (not curl/tar) does the download: the slim sandbox image is only
    guaranteed to have a shell and python.
    """
    code = (
        "import os, urllib.request; "
        f"urllib.request.urlretrieve({url!r}, {dest!r}); "
    )
    if unzip:
        code += (
            "import zipfile; "
            f"zipfile.ZipFile({dest!r}).extractall('.'); "
            f"os.chmod({unzip!r}, 0o755); "
        )
    else:
        code += f"os.chmod({dest!r}, 0o755); "
    return "python3 -c " + shlex.quote(code)


def _auth_flags(cookie_jar: CookieJar | None) -> str:
    if cookie_jar is None:
        return ""
    header = cookie_jar.cookie_header()
    if not header:
        return ""
    return f" -H {shlex.quote(header)}"


def _cap(out: str, limit: int = MAX_CRAWL_OUTPUT) -> str:
    if len(out) > limit:
        out = out[:limit] + f"\n…[truncated at {limit} chars]"
    return out


def katana_tool(sandbox: Sandbox, cookie_jar: CookieJar | None = None) -> BaseTool:
    """Build the katana web-crawler tool bound to *sandbox*."""
    ready: dict = {}

    def katana(url: str, depth: int = 3) -> str:
        """Crawl a target with katana: URLs, JS files, forms, endpoints.

        url: the target URL or domain to crawl (stays in scope automatically).
        depth: crawl depth, 1-5 (default 3; use 5 only for a single small
        target, 2 for broad host lists). -jc parses JavaScript, -kf all
        fetches known files (robots.txt etc.), -fx strips noise.
        Returns discovered URLs, one per line (JSONL parsed to URLs).
        """
        depth = max(1, min(5, int(depth)))
        err = _ensure_binary(
            sandbox,
            ready,
            KATANA_BIN,
            _python_fetch(KATANA_ZIP_URL, "katana.zip", KATANA_BIN),
            f"test -x ./{KATANA_BIN}",
        )
        if err:
            return err
        cmd = (
            f"./{KATANA_BIN} -u {shlex.quote(url)} -d {depth} "
            f"-jc -kf all -fx -silent -jsonl{_auth_flags(cookie_jar)}"
        )
        try:
            result = sandbox.exec(cmd, timeout=600.0)
        except Exception as e:  # noqa: BLE001 - surface to the model
            return f"error: katana run failed: {e}"
        urls: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # JSONL: {"request":{"endpoint":"https://..."}}
            ep = line
            if '"endpoint"' in line:
                try:
                    import json

                    ep = json.loads(line)["request"]["endpoint"]
                except Exception:  # noqa: BLE001 - keep raw line
                    pass
            urls.append(ep)
        seen: list[str] = []
        for u in urls:
            if u not in seen:
                seen.append(u)
        out = (
            f"$ katana -u {url} -d {depth}\n"
            f"[{len(seen)} unique URLs]\n" + "\n".join(seen)
        )
        if result.stderr.strip():
            out += f"\n[stderr]\n{result.stderr.strip()[:500]}"
        return _cap(out)

    return StructuredTool.from_function(
        katana,
        name="katana",
        description=(
            "Crawl a web target with katana: discovers URLs, JavaScript files, "
            "forms, and endpoints. Primary attack-surface mapper — run it early "
            "on every target. Stays in scope automatically. depth 1-5 "
            "(default 3). Returns unique discovered URLs."
        ),
    )


def hakrawler_tool(sandbox: Sandbox, cookie_jar: CookieJar | None = None) -> BaseTool:
    """Build the hakrawler supplemental crawler tool bound to *sandbox*."""
    ready: dict = {}

    def hakrawler(url: str, depth: int = 2) -> str:
        """Crawl a target with hakrawler (fast supplemental crawler).

        Run AFTER katana and merge outputs — each crawler finds unique URLs.
        url: the target URL. depth: 1-3 (default 2). Returns discovered
        URLs, one per line.
        """
        depth = max(1, min(3, int(depth)))
        err = _ensure_binary(
            sandbox,
            ready,
            HAKRAWLER_BIN,
            _python_fetch(HAKRAWLER_URL, HAKRAWLER_BIN),
            f"test -x ./{HAKRAWLER_BIN}",
        )
        if err:
            return err
        cmd = (
            f"echo {shlex.quote(url)} | ./{HAKRAWLER_BIN} "
            f"-depth {depth} -plain{_auth_flags(cookie_jar)}"
        )
        try:
            result = sandbox.exec(cmd, timeout=600.0)
        except Exception as e:  # noqa: BLE001 - surface to the model
            return f"error: hakrawler run failed: {e}"
        urls = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        seen: list[str] = []
        for u in urls:
            if u not in seen:
                seen.append(u)
        out = (
            f"$ hakrawler -url {url} -depth {depth}\n"
            f"[{len(seen)} unique URLs]\n" + "\n".join(seen)
        )
        return _cap(out)

    return StructuredTool.from_function(
        hakrawler,
        name="hakrawler",
        description=(
            "Supplemental fast web crawler. Run AFTER katana on the same "
            "target and merge outputs — each crawler finds unique URLs the "
            "other misses. depth 1-3 (default 2)."
        ),
    )


def crawl_tools(
    sandbox: Sandbox, cookie_jar: CookieJar | None = None
) -> list[BaseTool]:
    """Return [katana_tool, hakrawler_tool] bound to *sandbox*."""
    return [katana_tool(sandbox, cookie_jar), hakrawler_tool(sandbox, cookie_jar)]
