"""Regression tests for tool-message pairing, 400 recovery, and compaction."""

from __future__ import annotations

import json

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from aplomado.agent import _compact_messages
from aplomado.history import (
    SYNTHETIC_TOOL_RESULT_KEY,
    is_tool_pairing_error,
    repair_tool_pairs,
)
from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore


def _tc(name, args, i):
    return {"name": name, "args": args, "id": f"call-{i}", "type": "tool_call"}


def _assert_paired(messages):
    index = 0
    while index < len(messages):
        message = messages[index]
        assert not isinstance(message, ToolMessage), "orphan tool message"
        calls = getattr(message, "tool_calls", None) or []
        if not calls:
            index += 1
            continue
        expected = [call["id"] for call in calls]
        seen = []
        index += 1
        while index < len(messages) and isinstance(messages[index], ToolMessage):
            seen.append(messages[index].tool_call_id)
            index += 1
        assert seen == expected


def _has_synthetic(messages):
    return any(
        isinstance(message, ToolMessage)
        and isinstance(message.additional_kwargs, dict)
        and message.additional_kwargs.get(SYNTHETIC_TOOL_RESULT_KEY)
        for message in messages
    )


class RecordingModel:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0
        self.requests = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.requests.append(list(messages))
        self.calls += 1
        return self.script[min(self.calls - 1, len(self.script) - 1)]


_FINISH_PAYLOAD = json.dumps(
    {
        "target": "https://example.com",
        "summary": "done",
        "findings": [{"severity": "high", "title": "kept", "detail": "d"}],
    }
)


def test_scan79_parallel_elided_results_produce_paired_history(tmp_path):
    work = tmp_path / "work"
    (work / "scratch").mkdir(parents=True)
    (work / "scratch" / "big.txt").write_text("A" * 7000)
    model = RecordingModel(
        [
            AIMessage(
                content="",
                tool_calls=[
                    _tc("read_file", {"path": "scratch/big.txt"}, 1),
                    _tc(
                        "write_file",
                        {"path": "scratch/small.txt", "content": "ok"},
                        2,
                    ),
                ],
            ),
            AIMessage(
                content="",
                tool_calls=[_tc("finish", {"result": _FINISH_PAYLOAD}, 3)],
            ),
        ]
    )

    env = run_scan(
        "https://example.com",
        model=model,
        sandbox=LocalSandbox(str(work), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        log=lambda *a: None,
    )

    assert env["findings"][0]["title"] == "kept"
    assert len(model.requests) == 2
    for request in model.requests:
        _assert_paired(request)
    tool_messages = [
        message for message in model.requests[1] if isinstance(message, ToolMessage)
    ]
    assert [message.tool_call_id for message in tool_messages] == [
        "call-1",
        "call-2",
    ]
    assert "large output withheld" in tool_messages[0].content


def test_compaction_boundary_does_not_split_a_tool_call_group():
    calls = [
        _tc("todos_update", {"index_or_text": 1, "status": "done"}, 1),
        _tc("todos_update", {"index_or_text": 2, "status": "done"}, 2),
        _tc("todos_update", {"index_or_text": 3, "status": "done"}, 3),
    ]
    messages = [
        SystemMessage(content="system"),
        HumanMessage(content="start"),
        AIMessage(content="", tool_calls=calls),
        ToolMessage(
            content="[large output withheld: buffer buf-15]",
            tool_call_id="call-1",
            name="todos_update",
        ),
        ToolMessage(
            content="[large output withheld: buffer buf-16]",
            tool_call_id="call-2",
            name="todos_update",
        ),
        ToolMessage(
            content="[large output withheld: buffer buf-17]",
            tool_call_id="call-3",
            name="todos_update",
        ),
        AIMessage(content="next"),
        HumanMessage(content="continue"),
        AIMessage(content="more"),
        HumanMessage(content="again"),
    ]
    model = RecordingModel([AIMessage(content="summary")])

    compacted = _compact_messages(
        model, messages, keep_last=7, log=lambda *a: None
    )

    assert len(model.requests) == 1
    assert not _has_synthetic(model.requests[0])
    assert not _has_synthetic(compacted)
    _assert_paired(model.requests[0])
    _assert_paired(compacted)
    assert [m.tool_call_id for m in compacted if isinstance(m, ToolMessage)] == [
        "call-1",
        "call-2",
        "call-3",
    ]


def test_repair_inserts_synthetic_result_and_drops_orphan():
    messages = [
        AIMessage(content="", tool_calls=[_tc("shell", {"command": "x"}, 1)]),
        HumanMessage(content="hello"),
        ToolMessage(content="orphan", tool_call_id="call-9", name="shell"),
    ]

    repaired = repair_tool_pairs(messages)

    _assert_paired(repaired)
    assert isinstance(repaired[1], ToolMessage)
    assert repaired[1].tool_call_id == "call-1"
    assert _has_synthetic(repaired)
    assert not any(
        isinstance(message, ToolMessage) and message.tool_call_id == "call-9"
        for message in repaired
    )


class PairingThenFinishModel:
    def __init__(self):
        self.calls = 0
        self.requests = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.requests.append(list(messages))
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError(
                "Error code: 400 - invalid_request_error: An assistant message "
                "with 'tool_calls' must be followed by tool messages responding "
                "to each 'tool_call_id'. (insufficient tool messages following "
                "tool_calls message)"
            )
        return AIMessage(
            content="",
            tool_calls=[_tc("finish", {"result": _FINISH_PAYLOAD}, 1)],
        )


def test_pairing_400_is_retried_and_run_continues(tmp_path, monkeypatch):
    sleeps = []
    monkeypatch.setattr("aplomado.agent.time.sleep", sleeps.append)
    model = PairingThenFinishModel()

    env = run_scan(
        "https://example.com",
        model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        log=lambda *a: None,
    )

    assert model.calls == 2
    assert sleeps == [0.25]
    assert env["findings"][0]["title"] == "kept"
    for request in model.requests:
        _assert_paired(request)


def test_pairing_error_detection_is_not_provider_specific():
    assert is_tool_pairing_error(
        RuntimeError(
            "An assistant message with 'tool_calls' must be followed by tool "
            "messages responding to each 'tool_call_id'."
        )
    )
    assert is_tool_pairing_error(
        RuntimeError(
            "messages with role 'tool' must be a response to a preceding "
            "message with 'tool_calls'"
        )
    )
    assert not is_tool_pairing_error(RuntimeError("rate limit exceeded"))
