"""Per-turn thinking scan events, with a scripted fake model."""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage
from pinnace import LocalSandbox
from pinnace.session import SessionStore

from aplomado.agent import THINKING_EVENT_MAX_CHARS
from aplomado.scanner import run_scan
from aplomado.subagents import SUBAGENT_TASK_MARKER

FINISH = json.dumps({"summary": "done", "findings": []})


def _tc(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


class ScriptedModel:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        return self.script[min(self.calls - 1, len(self.script) - 1)]


class ParentChildModel:
    def __init__(self, parent_script, child_script):
        self.parent_script = list(parent_script)
        self.child_script = list(child_script)
        self.parent_calls = 0
        self.child_calls = 0

    def bind_tools(self, tools):
        return self

    @staticmethod
    def _is_child(messages):
        return any(
            isinstance(getattr(message, "content", None), str)
            and SUBAGENT_TASK_MARKER in message.content
            for message in messages
        )

    def invoke(self, messages):
        if self._is_child(messages):
            self.child_calls += 1
            return self.child_script[
                min(self.child_calls - 1, len(self.child_script) - 1)
            ]
        self.parent_calls += 1
        return self.parent_script[
            min(self.parent_calls - 1, len(self.parent_script) - 1)
        ]


def _run(tmp_path, model, *, trace=None, log=None):
    return run_scan(
        "https://example.com",
        model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        trace=trace,
        log=log or (lambda *args: None),
    )


def _thinking(events):
    return [event for event in events if event.get("event") == "thinking"]


def test_thinking_events_precede_tool_calls_and_carry_host_and_turn(tmp_path):
    trace = []
    logs = []
    model = ScriptedModel([
        AIMessage(
            content="  First inspect the response headers.\n",
            tool_calls=[_tc("shell", {"command": "printf one"}, 1)],
        ),
        AIMessage(
            content="   \n",
            tool_calls=[_tc("shell", {"command": "printf two"}, 2)],
        ),
        AIMessage(
            content="The surface is quiet; finish with what I have.",
            tool_calls=[_tc("finish", {"result": FINISH}, 3)],
        ),
    ])

    _run(tmp_path, model, trace=trace.append, log=logs.append)

    thinking = _thinking(trace)
    assert [event["turn"] for event in thinking] == [1, 3]
    assert all(event["host"] == "example.com" for event in thinking)
    assert thinking[0]["text"] == "First inspect the response headers."
    assert thinking[1]["text"] == (
        "The surface is quiet; finish with what I have."
    )

    def index(needle, start=0):
        return next(
            i for i, line in enumerate(logs[start:], start) if needle in line
        )

    turn_one = index("turn 1/")
    turn_two = index("turn 2/")
    turn_three = index("turn 3/")
    assert turn_one < index("thinking: First inspect") < index("tool: shell")
    assert turn_two < index("tool: shell", turn_two)
    assert not any(
        "thinking:" in line for line in logs[turn_two:turn_three]
    )
    assert turn_three < index("thinking: The surface is quiet")


def test_thinking_event_text_is_capped_with_ellipsis(tmp_path):
    trace = []
    model = ScriptedModel([
        AIMessage(
            content="x" * (THINKING_EVENT_MAX_CHARS + 500),
            tool_calls=[_tc("shell", {"command": "printf ok"}, 1)],
        ),
        AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 2)]),
    ])

    _run(tmp_path, model, trace=trace.append)

    (event,) = _thinking(trace)
    assert len(event["text"]) == THINKING_EVENT_MAX_CHARS + 1
    assert event["text"] == "x" * THINKING_EVENT_MAX_CHARS + "…"


def test_turns_without_assistant_text_emit_no_thinking(tmp_path):
    trace = []
    model = ScriptedModel([
        AIMessage(
            content="",
            tool_calls=[_tc("shell", {"command": "printf one"}, 1)],
        ),
        AIMessage(
            content="  \n\t",
            tool_calls=[_tc("shell", {"command": "printf two"}, 2)],
        ),
        AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 3)]),
    ])

    _run(tmp_path, model, trace=trace.append)

    assert _thinking(trace) == []


def test_child_thinking_uses_parent_host_and_is_tagged_subagent(tmp_path):
    trace = []
    logs = []
    model = ParentChildModel(
        parent_script=[
            AIMessage(
                content="Delegate the header review.",
                tool_calls=[
                    _tc("delegate_task", {"task": "review headers"}, 1)
                ],
            ),
            AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 2)]),
        ],
        child_script=[
            AIMessage(
                content="The child inspects the cache headers.",
                tool_calls=[_tc("shell", {"command": "printf child"}, 3)],
            ),
            AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 4)]),
        ],
    )

    _run(tmp_path, model, trace=trace.append, log=logs.append)

    child = [
        event for event in _thinking(trace)
        if event.get("subagent") is True
    ]
    assert len(child) == 1
    assert child[0]["host"] == "example.com"
    assert child[0]["turn"] == 1
    assert child[0]["text"] == "The child inspects the cache headers."
    assert any(
        "thinking: The child inspects the cache headers." in line
        for line in logs
    )
