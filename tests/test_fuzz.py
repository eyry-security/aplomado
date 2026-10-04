"""Tests for the ffuf content-discovery tool (aplomado.fuzz).

Everything runs against a stub sandbox — no Docker, no network, no API keys.
"""

import pytest
from langchain_core.tools import BaseTool

from aplomado.fuzz import (
    DEFAULT_WORDLIST,
    FFUF_BIN,
    FFUF_TARBALL_URL,
    MAX_FFUF_OUTPUT,
    WORDLIST_NAME,
    _check_extra_args,
    _with_fuzz_keyword,
    ffuf_tool,
)
from pinnace.sandbox import ExecResult


class StubSandbox:
    """Minimal in-memory Sandbox: scripted exec responses, recorded commands."""

    def __init__(self):
        self.commands = []
        self.files = {}
        self.exec_scripts = {}  # command prefix -> ExecResult

    def exec(self, cmd, timeout=120.0):
        self.commands.append(cmd)
        for prefix, result in self.exec_scripts.items():
            if cmd.startswith(prefix):
                return result
        return ExecResult("", "", 0)

    def read_file(self, path):
        return self.files[path]

    def write_file(self, path, content):
        self.files[path] = content

    def close(self):
        pass


def _binary_present(sb):
    sb.exec_scripts[f"test -x ./{FFUF_BIN}"] = ExecResult("", "", 0)


def _run_commands(sb):
    return [c for c in sb.commands if c.startswith(f"./{FFUF_BIN} ")]


# --- module helpers ---------------------------------------------------------


def test_with_fuzz_keyword_appends_when_missing():
    assert _with_fuzz_keyword("http://h/") == "http://h/FUZZ"
    assert _with_fuzz_keyword("http://h") == "http://h/FUZZ"


def test_with_fuzz_keyword_preserves_existing():
    assert _with_fuzz_keyword("http://h/FUZZ") == "http://h/FUZZ"
    assert _with_fuzz_keyword("http://h/x?u=FUZZ") == "http://h/x?u=FUZZ"


@pytest.mark.parametrize(
    "extra",
    ["-x; rm -rf /", "-x | tee out", "-x & echo pwn", "-x `id`", "-x $(id)"],
)
def test_extra_args_rejects_shell_metacharacters(extra):
    assert _check_extra_args(extra).startswith("error:")


def test_extra_args_allows_plain_flags():
    assert _check_extra_args("-mc 200,301 -recursion") is None
    assert _check_extra_args("") is None


def test_default_wordlist_is_sane():
    assert 35 <= len(DEFAULT_WORDLIST) <= 60
    for must in ("admin", "login", "api", ".git/HEAD", ".env", "robots.txt"):
        assert must in DEFAULT_WORDLIST


# --- tool wiring ------------------------------------------------------------


def test_ffuf_tool_is_a_langchain_tool():
    sb = StubSandbox()
    tool = ffuf_tool(sb)
    assert isinstance(tool, BaseTool)
    assert tool.name == "ffuf"
    assert "FUZZ" in tool.description


def test_run_writes_default_wordlist_and_fuzzes():
    sb = StubSandbox()
    _binary_present(sb)
    sb.exec_scripts[f"./{FFUF_BIN}"] = ExecResult("admin  [Status: 200]\n", "", 0)
    tool = ffuf_tool(sb)
    out = tool.invoke({"url": "http://h/"})
    assert WORDLIST_NAME in sb.files
    content = sb.files[WORDLIST_NAME]
    assert "admin" in content.splitlines()
    assert ".git/HEAD" in content.splitlines()
    (cmd,) = _run_commands(sb)
    assert "FUZZ" in cmd
    assert f"-w {WORDLIST_NAME}" in cmd
    assert "[exit 0]" in out
    assert "admin" in out


def test_custom_wordlist_path_used_verbatim():
    sb = StubSandbox()
    _binary_present(sb)
    tool = ffuf_tool(sb)
    tool.invoke({"url": "http://h/FUZZ", "wordlist": "mine.txt"})
    assert WORDLIST_NAME not in sb.files  # default list not written
    (cmd,) = _run_commands(sb)
    assert "-w mine.txt" in cmd


@pytest.mark.parametrize("bad", ["/etc/passwd", "../escape.txt", "a/../../b"])
def test_custom_wordlist_rejects_path_escape(bad):
    sb = StubSandbox()
    _binary_present(sb)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ", "wordlist": bad})
    assert out.startswith("error:")
    assert not _run_commands(sb)


def test_dangerous_extra_args_never_reach_shell():
    sb = StubSandbox()
    _binary_present(sb)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ", "extra_args": "-x; id"})
    assert out.startswith("error:")
    assert not _run_commands(sb)


def test_extra_args_appended_when_safe():
    sb = StubSandbox()
    _binary_present(sb)
    ffuf_tool(sb).invoke(
        {"url": "http://h/FUZZ", "extra_args": "-mc 200,403 -t 10"}
    )
    (cmd,) = _run_commands(sb)
    assert cmd.endswith("-mc 200,403 -t 10")


# --- binary provisioning ----------------------------------------------------


def test_binary_downloaded_on_first_use_and_cached():
    sb = StubSandbox()
    sb.exec_scripts[f"test -x ./{FFUF_BIN}"] = ExecResult("", "", 1)  # missing
    sb.exec_scripts["python3 -c"] = ExecResult("", "", 0)  # download succeeds
    tool = ffuf_tool(sb)
    tool.invoke({"url": "http://h/FUZZ"})
    tool.invoke({"url": "http://h/FUZZ"})
    downloads = [c for c in sb.commands if c.startswith("python3 -c")]
    assert len(downloads) == 1
    dl = downloads[0]
    assert FFUF_TARBALL_URL in dl
    assert "urlretrieve" in dl and "tarfile" in dl
    assert len(_run_commands(sb)) == 2  # both invocations still ran ffuf


def test_download_failure_returns_error_not_crash():
    sb = StubSandbox()
    sb.exec_scripts[f"test -x ./{FFUF_BIN}"] = ExecResult("", "", 1)
    sb.exec_scripts["python3 -c"] = ExecResult("", "network unreachable", 1)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert out.startswith("error:")
    assert "download" in out
    assert not _run_commands(sb)


def test_probe_failure_returns_error_not_crash():
    class BrokenProbe(StubSandbox):
        def exec(self, cmd, timeout=120.0):
            raise RuntimeError("sandbox exploded")

    out = ffuf_tool(BrokenProbe()).invoke({"url": "http://h/FUZZ"})
    assert out.startswith("error:")


# --- output handling --------------------------------------------------------


def test_output_is_truncated_with_marker():
    sb = StubSandbox()
    _binary_present(sb)
    sb.exec_scripts[f"./{FFUF_BIN}"] = ExecResult("x" * 60_000, "", 0)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert len(out) <= MAX_FFUF_OUTPUT + 100
    assert "truncated" in out
    assert "[exit 0]" in out


def test_stderr_and_exit_code_surface_in_output():
    sb = StubSandbox()
    _binary_present(sb)
    sb.exec_scripts[f"./{FFUF_BIN}"] = ExecResult("", "connection refused", 1)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert "[stderr]" in out
    assert "connection refused" in out
    assert "[exit 1]" in out
