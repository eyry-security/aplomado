"""ffuf content-discovery tool for Aplomado scans.

The Aplomado sandbox image ships the static ffuf binary at /usr/local/bin.
Tools verify it is present and never download anything at scan time.
"""

from __future__ import annotations

import os
import shlex

from langchain_core.tools import BaseTool, StructuredTool

from pinnace.sandbox import Sandbox

from .binaries import require_binary
from .buffers import FullOutput

FFUF_VERSION = "v2.1.0"
FFUF_BIN = "ffuf"
WORDLIST_NAME = "scratch/_ffuf_default.txt"
# Cap tool output so one chatty fuzz run can't eat the context window.
MAX_FFUF_OUTPUT = 20_000

# Sequences that would let extra_args break out of the ffuf invocation into
# a second shell command. Kept deliberately simple: reject, don't escape.
_FORBIDDEN_ARG_CHUNKS = (";", "|", "&", "`", "$(")

DEFAULT_WORDLIST = [
    "admin",
    "administrator",
    "login",
    "signin",
    "signup",
    "register",
    "api",
    "api/v1",
    "api/v2",
    "dashboard",
    "panel",
    "console",
    "manager",
    "debug",
    "test",
    "dev",
    "staging",
    "backup",
    "backups",
    "db",
    "config",
    "config.php",
    ".env",
    ".env.bak",
    ".git/HEAD",
    ".git/config",
    ".svn/entries",
    ".DS_Store",
    "robots.txt",
    "security.txt",
    ".well-known/security.txt",
    "sitemap.xml",
    "server-status",
    "phpinfo.php",
    "wp-admin",
    "docker-compose.yml",
    "package.json",
    "README.md",
    "CHANGELOG.md",
    ".htaccess",
]


def _with_fuzz_keyword(url: str) -> str:
    """Ensure the URL carries ffuf's FUZZ keyword; append /FUZZ if missing."""
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    return url


def _check_extra_args(extra_args: str) -> str | None:
    """Return an error string if extra_args holds shell metacharacters."""
    for chunk in _FORBIDDEN_ARG_CHUNKS:
        if chunk in extra_args:
            return f"error: extra_args contains forbidden sequence {chunk!r}"
    return None


def _ensure_ffuf(sandbox: Sandbox) -> str | None:
    """Verify the ffuf binary is pre-installed in the sandbox image."""
    return require_binary(sandbox, FFUF_BIN, label="ffuf")


def _wordlist_arg(sandbox: Sandbox, wordlist: str) -> tuple[str, str | None]:
    """Resolve the -w argument. Returns (path, None) or ("", error)."""
    if wordlist == "default":
        try:
            sandbox.write_file(WORDLIST_NAME, "\n".join(DEFAULT_WORDLIST) + "\n")
        except Exception as e:  # noqa: BLE001 - surface to the model
            return "", f"error: can't write the default wordlist: {e}"
        return WORDLIST_NAME, None
    if os.path.isabs(wordlist) or ".." in wordlist.split("/"):
        return "", "error: wordlist must be a path inside the sandbox workdir"
    return wordlist, None


def ffuf_tool(sandbox: Sandbox) -> BaseTool:
    """Build the ffuf content-discovery tool bound to *sandbox*."""
    ready = {"binary": False}

    def ffuf(url: str, wordlist: str = "default", extra_args: str = "") -> str:
        """Run ffuf content discovery against a URL inside the sandbox.

        The URL must contain the FUZZ keyword (it is appended as /FUZZ when
        missing). wordlist is "default" for a built-in ~40-entry list of
        common paths, or a path (relative to the sandbox workdir) to a custom
        list. extra_args passes extra ffuf flags through; anything looking
        like shell metacharacters is rejected.
        """
        bad = _check_extra_args(extra_args)
        if bad:
            return bad
        target = _with_fuzz_keyword(url)
        wl, err = _wordlist_arg(sandbox, wordlist)
        if err:
            return err
        if not ready["binary"]:
            err = _ensure_ffuf(sandbox)
            if err:
                return err
            ready["binary"] = True
        cmd = f"{FFUF_BIN} -u {shlex.quote(target)} -w {shlex.quote(wl)} -t 40"
        if extra_args.strip():
            cmd += f" {extra_args.strip()}"
        try:
            result = sandbox.exec(cmd, timeout=180.0)
        except Exception as e:  # noqa: BLE001 - surface to the model
            return f"error: ffuf run failed: {e}"
        out = f"$ ffuf -u {target} -w {wl}\n[exit {result.exit_code}]\n{result.stdout}"
        if result.stderr.strip():
            out += f"\n[stderr]\n{result.stderr}"
        if len(out) > MAX_FFUF_OUTPUT:
            return FullOutput(
                out[:MAX_FFUF_OUTPUT]
                + f"\n…[truncated at {MAX_FFUF_OUTPUT} chars]",
                full=out,
            )
        return out

    return StructuredTool.from_function(
        ffuf,
        name="ffuf",
        description=(
            "Discover hidden content on a web target with ffuf (content "
            "discovery / directory fuzzing). The URL must contain the FUZZ "
            "keyword — it is added automatically if missing, e.g. "
            "http://host/FUZZ. Use it to find admin panels, backup files, "
            "exposed .git/.env, and other hidden paths. Keep scans small: "
            'wordlist="default" uses a built-in ~40-entry list. The ffuf '
            "binary is pre-installed in the sandbox image."
        ),
    )
