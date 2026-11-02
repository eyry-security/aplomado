"""LR-47: a host review can only act on its assigned host."""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage, ToolMessage
from pinnace import DockerSandbox, ExecResult
from pinnace.session import SessionStore
from test_fuzz import StubSandbox

from aplomado.scanner import run_scan
from aplomado.subagents import SUBAGENT_TASK_MARKER


def _tc(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


def _finish(summary="done"):
    return AIMessage(
        content="",
        tool_calls=[_tc("finish", {
            "result": json.dumps({"summary": summary, "findings": []})
        }, 99)],
    )


class IsolatedStubSandbox(StubSandbox, DockerSandbox):
    pass


class ScriptedModel:
    def __init__(self, parent_script, child_script=None):
        self.parent_script = list(parent_script)
        self.child_script = list(child_script or [])
        self.parent_calls = 0
        self.child_calls = 0
        self.requests = []

    def bind_tools(self, tools):
        return self

    def _is_child(self, messages):
        for message in messages:
            content = getattr(message, "content", "")
            if isinstance(content, str) and SUBAGENT_TASK_MARKER in content:
                return True
        return False

    def invoke(self, messages):
        self.requests.append((self._is_child(messages), list(messages)))
        if self._is_child(messages):
            self.child_calls += 1
            index = min(self.child_calls - 1, len(self.child_script) - 1)
            return self.child_script[index]
        self.parent_calls += 1
        index = min(self.parent_calls - 1, len(self.parent_script) - 1)
        return self.parent_script[index]


def _sandbox():
    sandbox = IsolatedStubSandbox()
    sandbox.exec_scripts["[ -L"] = ExecResult("", "", 1)
    return sandbox


def _run(tmp_path, model, sandbox, log):
    return run_scan(
        "https://a.example",
        model=model,
        sandbox=sandbox,
        session_store=SessionStore(tmp_path / "sessions"),
        log=log.append,
    )


def _tool_contents(model, name):
    return [
        message.content
        for child, messages in model.requests
        for message in messages
        if not child
        and isinstance(message, ToolMessage)
        and message.name == name
    ]


def test_roaming_tool_call_is_rejected_before_execution(tmp_path):
    sandbox = _sandbox()
    log = []
    model = ScriptedModel([
        AIMessage(content="", tool_calls=[
            _tc("shell", {"command": "curl -sk https://b.example/"}, 1),
        ]),
        AIMessage(content="", tool_calls=[
            _tc("nuclei", {"target": "https://b.example"}, 2),
        ]),
        _finish(),
    ])

    _run(tmp_path, model, sandbox, log)

    assert not any("b.example" in cmd for cmd in sandbox.commands)
    shell_results = _tool_contents(model, "shell")
    assert any("out of scope" in text and "a.example" in text
               for text in shell_results)
    nuclei_results = _tool_contents(model, "nuclei")
    assert any("out of scope" in text and "b.example" in text
               for text in nuclei_results)
    assert any("target-rejected" in line for line in log)


def test_delegate_brief_naming_another_host_is_rejected(tmp_path):
    sandbox = _sandbox()
    trace = []
    log = []
    model = ScriptedModel([
        AIMessage(content="", tool_calls=[
            _tc("delegate_task", {
                "task": "run nuclei against three hosts",
                "context": "b.example is the second target",
            }, 1),
        ]),
        _finish(),
    ])

    run_scan(
        "https://a.example",
        model=model,
        sandbox=sandbox,
        session_store=SessionStore(tmp_path / "sessions"),
        log=log.append,
        trace=trace.append,
    )

    results = _tool_contents(model, "delegate_task")
    assert any("out of scope" in text and "a.example" in text
               for text in results)
    assert not any(e.get("type") == "subagent.started" for e in trace)
    assert model.child_calls == 0


def test_reference_lookup_to_allowlisted_service_still_runs(tmp_path):
    sandbox = _sandbox()
    sandbox.exec_scripts["curl -sk https://crt.sh"] = ExecResult(
        "certificate records\n", "", 0)
    model = ScriptedModel([
        AIMessage(content="", tool_calls=[
            _tc("shell", {
                "command": "curl -sk https://crt.sh/?q=a.example",
            }, 1),
        ]),
        _finish(),
    ])

    _run(tmp_path, model, sandbox, [])

    assert any("crt.sh" in cmd for cmd in sandbox.commands)
    results = _tool_contents(model, "shell")
    assert results and all("out of scope" not in text for text in results)


def test_subagent_inherits_the_parent_binding(tmp_path):
    sandbox = _sandbox()
    log = []
    parent = [
        AIMessage(content="", tool_calls=[
            _tc("delegate_task", {
                "task": "check the response headers on a.example",
                "context": "assigned host: a.example",
            }, 1),
        ]),
        _finish("parent done"),
    ]
    child = [
        AIMessage(content="", tool_calls=[
            _tc("shell", {"command": "curl -sk https://b.example/"}, 2),
        ]),
        _finish("child done"),
    ]
    model = ScriptedModel(parent, child)

    _run(tmp_path, model, sandbox, log)

    assert model.child_calls == 2
    assert not any("b.example" in cmd for cmd in sandbox.commands)
    assert any(
        "subagent sub-1" in line and "target-rejected" in line
        for line in log
    )
