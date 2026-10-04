"""Tests for Aplomado's sandboxed Python scratchpad tool."""

import json
from types import SimpleNamespace

from langchain_core.messages import AIMessage

from aplomado import scratchpad as scratchpad_module
from aplomado.scanner import run_scan
from aplomado.scratchpad import (
    SCRATCHPAD_PATH,
    SCRATCHPAD_TIMEOUT_SECONDS,
    python_scratchpad_tool,
    scratchpad_tools,
)
from pinnace import ExecResult, LocalSandbox
from pinnace.session import SessionStore


class MockSandbox:
    def __init__(self, result=None, write_error=None, exec_error=None):
        self.result = result or ExecResult("", "", 0)
        self.write_error = write_error
        self.exec_error = exec_error
        self.written = {}
        self.exec_calls = []

    def write_file(self, path, content):
        if self.write_error:
            raise self.write_error
        self.written[path] = content

    def exec(self, command, timeout=120.0):
        self.exec_calls.append((command, timeout))
        if self.exec_error:
            raise self.exec_error
        return self.result


def test_scratchpad_writes_code_and_returns_stdout():
    sandbox = MockSandbox(ExecResult("hello\n", "", 0))

    output = python_scratchpad_tool(sandbox).invoke({"code": "print('hello')"})

    assert sandbox.written == {SCRATCHPAD_PATH: "print('hello')"}
    assert sandbox.exec_calls == [
        (f"python3 {SCRATCHPAD_PATH}", SCRATCHPAD_TIMEOUT_SECONDS)
    ]
    assert output == f"$ python3 {SCRATCHPAD_PATH}\nhello\n\n[exit 0]"


def test_scratchpad_formats_stderr_exit_and_truncation():
    sandbox = MockSandbox(ExecResult("partial", "boom", 2, truncated=True))

    output = python_scratchpad_tool(sandbox).invoke(
        {"code": "raise SystemExit(2)"}
    )

    assert "[stderr]\nboom" in output
    assert output.endswith("[exit 2] (truncated)")


def test_scratchpad_surfaces_write_failure_without_execution():
    sandbox = MockSandbox(write_error=OSError("disk full"))

    output = python_scratchpad_tool(sandbox).invoke({"code": "pass"})

    assert output == "error: disk full"
    assert sandbox.exec_calls == []


def test_scratchpad_surfaces_execution_failure():
    sandbox = MockSandbox(exec_error=RuntimeError("runner unavailable"))

    output = python_scratchpad_tool(sandbox).invoke({"code": "pass"})

    assert output == "error: runner unavailable"


def test_scratchpad_tools_skips_duplicate_harness_builtin(monkeypatch):
    monkeypatch.setattr(
        scratchpad_module,
        "builtin_tools",
        lambda sandbox: [SimpleNamespace(name="python_scratchpad")],
    )

    assert scratchpad_tools(MockSandbox()) == []


def _tool_call(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


class ScratchpadModel:
    def __init__(self):
        self.calls = 0
        self.tool_names = []
        self.scratchpad_output = None

    def bind_tools(self, tools):
        self.tool_names = [tool.name for tool in tools]
        return self

    def invoke(self, messages):
        self.calls += 1
        if self.calls == 1:
            return AIMessage(
                content="",
                tool_calls=[
                    _tool_call(
                        "python_scratchpad",
                        {"code": "print(sum([2, 3, 5]))"},
                        1,
                    )
                ],
            )
        self.scratchpad_output = messages[-1].content
        payload = json.dumps({"summary": "calculated", "findings": []})
        return AIMessage(
            content="",
            tool_calls=[_tool_call("finish", {"result": payload}, 2)],
        )


def test_run_scan_exposes_and_executes_scratchpad(tmp_path):
    model = ScratchpadModel()
    workdir = tmp_path / "work"

    envelope = run_scan(
        "https://example.com",
        model=model,
        sandbox=LocalSandbox(str(workdir), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
    )

    assert model.tool_names.count("python_scratchpad") == 1
    assert model.scratchpad_output == f"$ python3 {SCRATCHPAD_PATH}\n10\n\n[exit 0]"
    assert (workdir / SCRATCHPAD_PATH).read_text() == "print(sum([2, 3, 5]))"
    assert envelope["summary"] == "calculated"
