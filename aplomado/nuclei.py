"""nuclei vulnerability-scanner tool for Aplomado bug-hunting scans.

Scoped per hunter best practice: curated template categories (cves,
exposures, misconfiguration, takeovers), severity critical+high only,
dos/fuzz tags excluded, rate-limited. Full-template runs are noise;
targeted runs find real bugs (CVEs, dangling-CNAME takeovers, .git/.env,
default creds).

TREAD LIGHTLY: rate limit is enforced in the invocation; the tool refuses
to run without the curated scope.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .auth import CookieJar
from .binaries import require_binary
from .buffers import FullOutput

NUCLEI_VERSION = "v3.3.9"
NUCLEI_BIN = "nuclei"
NUCLEI_TEMPLATES_DIR = "/opt/nuclei-templates"

# Curated, high-signal template selection. Never run the full library.
NUCLEI_TEMPLATES = [
    f"{NUCLEI_TEMPLATES_DIR}/http/cves/",
    f"{NUCLEI_TEMPLATES_DIR}/http/exposures/",
    f"{NUCLEI_TEMPLATES_DIR}/http/misconfiguration/",
    f"{NUCLEI_TEMPLATES_DIR}/http/takeovers/",
]
NUCLEI_SEVERITY = "critical,high"
NUCLEI_EXCLUDE_TAGS = "dos,fuzz"
NUCLEI_RATE_LIMIT = 50  # requests/second cap — tread lightly

MAX_NUCLEI_OUTPUT = 30_000


def _ensure_nuclei(sandbox: Sandbox) -> str | None:
    """Verify nuclei and its template library are pre-installed."""
    err = require_binary(sandbox, NUCLEI_BIN, label="nuclei")
    if err:
        return err
    try:
        probe = sandbox.exec(
            f"test -d {shlex.quote(NUCLEI_TEMPLATES_DIR)}", timeout=30.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: can't probe for the nuclei templates: {e}"
    if probe.exit_code != 0:
        return (
            f"error: nuclei templates are not installed in the sandbox image "
            f"({NUCLEI_TEMPLATES_DIR}); rebuild the Aplomado sandbox image. "
            "No runtime download is attempted."
        )
    return None


def nuclei_tool(sandbox: Sandbox, cookie_jar: CookieJar | None = None) -> BaseTool:
    """Build the nuclei scanner tool bound to *sandbox* (curated scope)."""
    ready: dict = {}

    def nuclei(target: str) -> str:
        """Scan a target with nuclei (curated high-signal templates).

        target: URL or host to scan.
        Runs ONLY: cves/, exposures/, misconfiguration/, takeovers/ at
        severity critical,high — rate-limited to 50 req/s. Finds real CVEs,
        exposed .git/.env/backups, misconfigured panels, subdomain
        takeovers, default logins. Verify every hit with curl before
        reporting — templates can false-positive.
        """
        if not ready.get("binary"):
            err = _ensure_nuclei(sandbox)
            if err:
                return err
            ready["binary"] = True
        t_flags = " ".join(f"-t {shlex.quote(t)}" for t in NUCLEI_TEMPLATES)
        cmd = (
            f"{NUCLEI_BIN} -u {shlex.quote(target)} {t_flags} "
            f"-severity {NUCLEI_SEVERITY} "
            f"-exclude-tags {NUCLEI_EXCLUDE_TAGS} "
            f"-rate-limit {NUCLEI_RATE_LIMIT} -silent -jsonl -nc"
        )
        if cookie_jar is not None:
            header = cookie_jar.cookie_header()
            if header:
                cmd += f" -H {shlex.quote(header)}"
        try:
            result = sandbox.exec(cmd, timeout=900.0)
        except Exception as e:  # noqa: BLE001 - surface to the model
            return f"error: nuclei run failed: {e}"
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        out = (
            f"$ nuclei -u {target} [{','.join(NUCLEI_TEMPLATES)} "
            f"severity={NUCLEI_SEVERITY}]\n"
            f"[{len(lines)} findings]\n" + "\n".join(lines)
        )
        if len(out) > MAX_NUCLEI_OUTPUT:
            return FullOutput(
                out[:MAX_NUCLEI_OUTPUT]
                + f"\n…[truncated at {MAX_NUCLEI_OUTPUT} chars]",
                full=out,
            )
        return out

    return StructuredTool.from_function(
        nuclei,
        name="nuclei",
        description=(
            "Vulnerability scan with nuclei (curated scope only): CVEs, "
            "exposures, misconfigurations, takeovers at severity "
            "critical,high — rate-limited. Finds real CVEs, exposed files, "
            "dangling subdomains. VERIFY every hit with curl before "
            "reporting."
        ),
    )
