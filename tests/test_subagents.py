"""Tests for depth-1 sub-agents and output elision, with a stubbed model."""

from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from pinnace import DockerSandbox, ExecResult
from pinnace.session import SessionStore
from test_fuzz import StubSandbox

from aplomado.scanner import run_scan
from aplomado.subagents import (
    DEFAULT_SUBAGENT_TURNS,
    MAX_SUBAGENT_TURNS,
    SUBAGENT_TASK_MARKER,
    SubAgentRunner,
    clamp_subagent_turns,
)


def _tc(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


def _finish(summary):
    payload = json.dumps({"summary": summary, "findings": []})
    return AIMessage(
        content="",
        tool_calls=[_tc("finish", {"result": payload}, 99)],
    )


class IsolatedStubSandbox(StubSandbox, DockerSandbox):
    pass


class ScriptedModel:
    """Replays separate parent/child scripts based on the sub-agent marker."""

    def __init__(self, parent_script, child_script):
        self.parent_script = list(parent_script)
        self.child_script = list(child_script)
        self.parent_calls = 0
        self.child_calls = 0
        self.bound_tools = []
        self.requests = []

    def bind_tools(self, tools):
        self.bound_tools.append([tool.name for tool in tools])
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


def _run(tmp_path, model, sandbox=None, trace=None, log=None):
    return run_scan(
        "https://example.com",
        model=model,
        sandbox=sandbox or _sandbox(),
        session_store=SessionStore(tmp_path / "sessions"),
        log=log or (lambda *args: None),
        trace=trace,
    )


def test_delegate_runs_child_returns_summary_and_tags_trace(tmp_path):
    trace = []
    log = []
    parent_script = [
        AIMessage(
            content="",
            tool_calls=[
                _tc(
                    "delegate_task",
                    {"task": "check response headers", "context": "target"},
                    1,
                )
            ],
        ),
        _finish("parent done"),
    ]
    child_script = [
        AIMessage(
            content="",
            tool_calls=[
                _tc("shell", {"command": "echo child", "timeout_seconds": 300}, 2)
            ],
        ),
        _finish("child found X"),
    ]
    model = ScriptedModel(parent_script, child_script)

    envelope = _run(tmp_path, model, trace=trace.append, log=log.append)

    assert envelope["summary"] == "parent done"
    assert model.child_calls == 2
    assert any(e["type"] == "subagent.started" for e in trace)
    finished = [e for e in trace if e["type"] == "subagent.finished"]
    assert finished and finished[0]["subagent_id"] == "sub-1"
    assert finished[0]["summary"] == "child found X"
    assert all(
        e.get("subagent_id") == "sub-1"
        for e in trace
        if e["type"].startswith("subagent.")
    )
    assert any(
        "subagent sub-1" in line and "tool: shell" in line for line in log
    )
    assert any(
        "subagent sub-1" in line and "turn 1/30" in line for line in log
    )

    # The parent gets the child summary as the delegate_task tool result.
    child_result = [
        message
        for message in model.requests[-1][1]
        if isinstance(message, ToolMessage) and message.name == "delegate_task"
    ]
    assert child_result[-1].content == "child found X"

    # The child is bound without delegation tools; the parent has them.
    assert any("delegate_task" in names for names in model.bound_tools)
    assert any("delegate_task" not in names for names in model.bound_tools)


def test_delegate_turn_budget_is_capped_at_60(tmp_path):
    trace = []
    parent_script = [
        AIMessage(
            content="",
            tool_calls=[
                _tc(
                    "delegate_task",
                    {"task": "wide work", "context": "", "max_turns": 500},
                    1,
                )
            ],
        ),
        _finish("parent done"),
    ]
    model = ScriptedModel(parent_script, [_finish("child done")])

    _run(tmp_path, model, trace=trace.append)

    started = [e for e in trace if e["type"] == "subagent.started"]
    assert started[0]["max_turns"] == MAX_SUBAGENT_TURNS


def test_child_cannot_delegate_again(tmp_path):
    log = []
    parent_script = [
        AIMessage(
            content="",
            tool_calls=[_tc("delegate_task", {"task": "outer"}, 1)],
        ),
        _finish("parent done"),
    ]
    child_script = [
        AIMessage(
            content="",
            tool_calls=[
                _tc("delegate_task", {"task": "inner"}, 2),
            ],
        ),
        _finish("child done"),
    ]
    model = ScriptedModel(parent_script, child_script)

    _run(tmp_path, model, log=log.append)

    assert model.child_calls == 2
    assert any(
        "subagent sub-1" in line
        and "error: unknown tool 'delegate_task'" in line
        for line in log
    )


def test_runner_refuses_nested_depth_directly():
    runner = SubAgentRunner(
        model=ScriptedModel([_finish("never")], [_finish("never")]),
        sandbox=_sandbox(),
        tools=[],
        system_prompt="",
    )

    assert runner.run("nested", depth=1).startswith("error: nested delegation")


def test_elide_returns_only_the_extracted_answer(tmp_path):
    trace = []
    source = "verbose dump\n" + ("row data\n" * 500)
    parent_script = [
        AIMessage(
            content="",
            tool_calls=[
                _tc(
                    "elide",
                    {
                        "source": source,
                        "question": "what is the admin username?",
                    },
                    1,
                )
            ],
        ),
        _finish("parent done"),
    ]
    child_script = [_finish("admin username is root")]
    model = ScriptedModel(parent_script, child_script)

    _run(tmp_path, model, trace=trace.append)

    elide_result = [
        message
        for message in model.requests[-1][1]
        if isinstance(message, ToolMessage) and message.name == "elide"
    ][-1]
    assert elide_result.content == "admin username is root"
    assert "row data" not in elide_result.content
    assert any(
        e["type"] == "subagent.finished"
        and e["summary"] == "admin username is root"
        for e in trace
    )
    assert all("row data" not in json.dumps(event) for event in trace)


def test_elide_reads_a_scratch_file_without_returning_it(tmp_path):
    sandbox = _sandbox()
    sandbox.files["scratch/dump.txt"] = "field=username value=root\n" * 100
    parent_script = [
        AIMessage(
            content="",
            tool_calls=[
                _tc(
                    "elide",
                    {
                        "source": "scratch/dump.txt",
                        "question": "which field is present?",
                    },
                    1,
                )
            ],
        ),
        _finish("parent done"),
    ]
    child_script = [_finish("the username field")]
    model = ScriptedModel(parent_script, child_script)

    _run(tmp_path, model, sandbox=sandbox)

    elide_result = [
        message
        for message in model.requests[-1][1]
        if isinstance(message, ToolMessage) and message.name == "elide"
    ][-1]
    assert elide_result.content == "the username field"
    assert "field=username" not in elide_result.content
    child_request = [messages for child, messages in model.requests if child][0]
    assert any(
        "field=username" in str(getattr(message, "content", ""))
        for message in child_request
    )


def test_turn_budget_helper_defaults_and_caps():
    assert DEFAULT_SUBAGENT_TURNS == 30
    assert clamp_subagent_turns(None) == 30
    assert clamp_subagent_turns(10) == 10
    assert clamp_subagent_turns(1000) == 60
    with pytest.raises(ValueError):
        clamp_subagent_turns(0)
