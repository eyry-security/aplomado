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

NUCLEI_VERSION = "v3.3.9"
NUCLEI_BIN = "nuclei"
NUCLEI_ZIP_URL = (
    "https://github.com/projectdiscovery/nuclei/releases/download/"
    f"{NUCLEI_VERSION}/nuclei_{NUCLEI_VERSION.lstrip('v')}_linux_amd64.zip"
)

# Curated, high-signal template selection. Never run the full library.
NUCLEI_TEMPLATES = ["cves/", "exposures/", "misconfiguration/", "takeovers/"]
NUCLEI_SEVERITY = "critical,high"
NUCLEI_EXCLUDE_TAGS = "dos,fuzz"
NUCLEI_RATE_LIMIT = 50  # requests/second cap — tread lightly

MAX_NUCLEI_OUTPUT = 30_000


def _ensure_nuclei(sandbox: Sandbox) -> str | None:
    try:
        probe = sandbox.exec(f"test -x ./{NUCLEI_BIN}", timeout=30.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: can't probe for the nuclei binary: {e}"
    if probe.exit_code == 0:
        return None
    code = (
        "import os, urllib.request, zipfile; "
        f"urllib.request.urlretrieve({NUCLEI_ZIP_URL!r}, 'nuclei.zip'); "
        "zipfile.ZipFile('nuclei.zip').extractall('.'); "
        f"os.chmod({NUCLEI_BIN!r}, 0o755); "
    )
    try:
        dl = sandbox.exec("python3 -c " + shlex.quote(code), timeout=300.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: nuclei download failed: {e}"
    if dl.exit_code != 0:
        return f"error: nuclei download failed: {dl.stderr.strip()[:300]}"
    # One-time template library fetch.
    try:
        upd = sandbox.exec(f"./{NUCLEI_BIN} -update-templates -silent", timeout=900.0)
    except Exception as e:  # noqa: BLE001 - surface to the model
        return f"error: nuclei template update failed: {e}"
    if upd.exit_code != 0:
        return f"error: nuclei template update failed: {upd.stderr.strip()[:300]}"
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
            f"./{NUCLEI_BIN} -u {shlex.quote(target)} {t_flags} "
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
            out = out[:MAX_NUCLEI_OUTPUT] + (
                f"\n…[truncated at {MAX_NUCLEI_OUTPUT} chars]"
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
