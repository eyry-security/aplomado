"""Tests for the ffuf content-discovery tool (aplomado.fuzz).

Everything runs against a stub sandbox — no Docker, no network, no API keys.
"""

import json

import pytest
from langchain_core.tools import BaseTool

from aplomado.fuzz import (
    DEFAULT_WORDLIST,
    FATHOM_BIN,
    FFUF_BIN,
    MAX_FFUF_OUTPUT,
    WORDLIST_NAME,
    _check_extra_args,
    _fathom_path,
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


def _no_fathom(sb):
    sb.exec_scripts[f"test -x /usr/local/bin/{FATHOM_BIN}"] = ExecResult("", "", 1)


def _binary_present(sb):
    _no_fathom(sb)
    sb.exec_scripts[f"test -x /usr/local/bin/{FFUF_BIN}"] = ExecResult("", "", 0)


def _run_commands(sb):
    return [c for c in sb.commands if c.startswith(f"{FFUF_BIN} ")]


def _fathom_commands(sb, path="/usr/local/bin/fathom"):
    return [c for c in sb.commands if c.startswith(f"{path} http ")]


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
    sb.exec_scripts[f"{FFUF_BIN} "] = ExecResult("admin  [Status: 200]\n", "", 0)
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


def test_binary_probe_is_cached():
    sb = StubSandbox()
    _binary_present(sb)
    tool = ffuf_tool(sb)
    tool.invoke({"url": "http://h/FUZZ"})
    tool.invoke({"url": "http://h/FUZZ"})
    probes = [c for c in sb.commands
              if c == f"test -x /usr/local/bin/{FFUF_BIN}"]
    assert len(probes) == 1
    assert len(_run_commands(sb)) == 2


def test_missing_binary_returns_error_without_download():
    sb = StubSandbox()
    _no_fathom(sb)
    sb.exec_scripts[f"test -x /usr/local/bin/{FFUF_BIN}"] = ExecResult("", "", 1)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert out.startswith("error:")
    assert "not installed" in out
    assert not any("python3 -c" in c or "urlretrieve" in c for c in sb.commands)
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
    sb.exec_scripts[f"{FFUF_BIN} "] = ExecResult("x" * 60_000, "", 0)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert len(out) <= MAX_FFUF_OUTPUT + 100
    assert "truncated" in out
    assert "[exit 0]" in out


def test_stderr_and_exit_code_surface_in_output():
    sb = StubSandbox()
    _binary_present(sb)
    sb.exec_scripts[f"{FFUF_BIN} "] = ExecResult("", "connection refused", 1)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert "[stderr]" in out
    assert "connection refused" in out
    assert "[exit 1]" in out


# --- fathom engine preference ----------------------------------------------


def test_fathom_is_preferred_and_jsonl_is_parsed():
    sb = StubSandbox()
    sb.exec_scripts[f"test -x /usr/local/bin/{FATHOM_BIN}"] = ExecResult("", "", 0)
    canned = "\n".join([
        json.dumps({
            "type": "result",
            "input": {"FUZZ": "admin"},
            "url": "http://h/admin",
            "final_url": "http://h/admin",
            "method": "GET",
            "status": 200,
            "size": 42,
            "words": 5,
            "lines": 2,
            "duration_ms": 7,
        }),
        json.dumps({"type": "stats", "requests": 1, "errors": 0,
                    "kept": 1, "filtered": 0, "elapsed_ms": 9,
                    "rps": 111.0}),
    ])
    sb.exec_scripts[f"/usr/local/bin/{FATHOM_BIN} http "] = ExecResult(
        canned, "", 0)
    out = ffuf_tool(sb).invoke({"url": "http://h/"})
    (cmd,) = _fathom_commands(sb)
    assert " http -u http://h/FUZZ " in cmd
    assert f"-w {WORDLIST_NAME}" in cmd
    assert "--format jsonl" in cmd
    assert "http://h/admin" in out
    assert "Status: 200" in out
    assert "Size: 42" in out
    assert not _run_commands(sb)


def test_configured_fathom_bin_uses_that_path(monkeypatch):
    monkeypatch.setenv("FATHOM_BIN", "/opt/tools/fathom")
    sb = StubSandbox()
    sb.exec_scripts["test -x /opt/tools/fathom"] = ExecResult("", "", 0)
    sb.exec_scripts["/opt/tools/fathom http "] = ExecResult(
        json.dumps({"type": "result", "input": {"FUZZ": "login"},
                    "url": "http://h/login", "status": 403,
                    "size": 1, "words": 1, "lines": 1}) + "\n",
        "", 0)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert _fathom_path() == "/opt/tools/fathom"
    (cmd,) = _fathom_commands(sb, "/opt/tools/fathom")
    assert cmd.startswith("/opt/tools/fathom http ")
    assert "http://h/login" in out
    assert "Status: 403" in out


def test_absent_fathom_falls_back_to_ffuf():
    sb = StubSandbox()
    _binary_present(sb)
    sb.exec_scripts[f"{FFUF_BIN} "] = ExecResult(
        "admin  [Status: 200]\n", "", 0)
    out = ffuf_tool(sb).invoke({"url": "http://h/FUZZ"})
    assert _fathom_commands(sb) == []
    (cmd,) = _run_commands(sb)
    assert cmd.startswith(f"{FFUF_BIN} ")
    assert "admin" in out
