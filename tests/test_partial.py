"""Partial-finish salvage when pairing retries are exhausted."""

from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore


def _tc(name, args, i):
    return {"name": name, "args": args, "id": f"call-{i}", "type": "tool_call"}


def _pairing_error():
    return RuntimeError(
        "Error code: 400 - invalid_request_error: An assistant message with "
        "'tool_calls' must be followed by tool messages responding to each "
        "'tool_call_id'. (insufficient tool messages following tool_calls "
        "message)"
    )


def _salvage_request(messages):
    return (
        len(messages) == 2
        and isinstance(messages[0], SystemMessage)
        and isinstance(messages[1], HumanMessage)
        and str(messages[1].content).startswith("PARTIAL-SCAN SALVAGE")
    )


class PairingSalvageModel:
    def __init__(self, payload, *, prior_turns=None, fail_salvage=False):
        self.payload = payload
        self.prior_turns = list(prior_turns or [])
        self.fail_salvage = fail_salvage
        self.requests = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.requests.append(list(messages))
        if _salvage_request(messages):
            if self.fail_salvage:
                raise RuntimeError("salvage provider call failed")
            return AIMessage(
                content="",
                tool_calls=[
                    _tc(
                        "finish",
                        {"result": json.dumps(self.payload)},
                        99,
                    )
                ],
            )
        if self.prior_turns:
            return self.prior_turns.pop(0)
        raise _pairing_error()


class NonPairingModel:
    def __init__(self):
        self.calls = 0
        self.requests = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.requests.append(list(messages))
        self.calls += 1
        if self.calls == 1:
            return AIMessage(
                content="",
                tool_calls=[
                    _tc("shell", {"command": "echo recon-ok"}, 1),
                ],
            )
        raise RuntimeError("rate limit exceeded")


_FINISH_PAYLOAD = json.dumps(
    {
        "target": "https://example.com",
        "summary": "done",
        "findings": [{"severity": "high", "title": "kept", "detail": "d"}],
    }
)


def _run(tmp_path, model):
    return run_scan(
        "https://example.com",
        model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        log=lambda *a: None,
    )


def test_pairing_exhaustion_salvages_partial_finish(tmp_path, monkeypatch):
    monkeypatch.setattr("aplomado.agent.time.sleep", lambda *_: None)
    model = PairingSalvageModel(
        {
            "target": "https://example.com",
            "summary": (
                "PARTIAL scan — target https://example.com; no completed tool "
                "calls; no classes attempted."
            ),
            "findings": [
                {"severity": "high", "title": "Salvaged issue", "detail": "d"}
            ],
        }
    )

    env = _run(tmp_path, model)

    assert env["partial"] is True
    assert env["findings"][0]["title"] == "Salvaged issue"
    assert env["coverage"].startswith("Partial-scan coverage:")
    assert "https://example.com" in env["coverage"]
    assert "partial" in env["summary"].lower()
    assert len(model.requests) == 5
    salvage = model.requests[-1]
    assert _salvage_request(salvage)
    assert not any(isinstance(message, ToolMessage) for message in salvage)


def test_salvage_failure_reraises_original_exhaustion(tmp_path, monkeypatch):
    monkeypatch.setattr("aplomado.agent.time.sleep", lambda *_: None)
    model = PairingSalvageModel(
        {"summary": "unused", "findings": []}, fail_salvage=True
    )

    with pytest.raises(RuntimeError, match="insufficient tool messages"):
        _run(tmp_path, model)

    assert len(model.requests) == 5
    assert _salvage_request(model.requests[-1])


def test_successful_scan_has_no_partial_flag(tmp_path):
    class FinishModel:
        def __init__(self):
            self.calls = 0

        def bind_tools(self, tools):
            return self

        def invoke(self, messages):
            self.calls += 1
            return AIMessage(
                content="",
                tool_calls=[
                    _tc("finish", {"result": _FINISH_PAYLOAD}, 1),
                ],
            )

    env = _run(tmp_path, FinishModel())

    assert env["summary"] == "done"
    assert env["findings"][0]["title"] == "kept"
    assert "partial" not in env
    assert "coverage" not in env


def test_non_pairing_error_propagates_without_salvage(tmp_path):
    model = NonPairingModel()

    with pytest.raises(RuntimeError, match="rate limit exceeded"):
        _run(tmp_path, model)

    assert model.calls == 2
    assert not any(_salvage_request(request) for request in model.requests)


def test_coverage_uses_completed_tool_calls_from_run_state(tmp_path, monkeypatch):
    monkeypatch.setattr("aplomado.agent.time.sleep", lambda *_: None)
    prior = AIMessage(
        content="",
        tool_calls=[
            _tc(
                "shell",
                {"command": "curl -s https://example.com/login"},
                1,
            )
        ],
    )
    model = PairingSalvageModel(
        {
            "summary": "PARTIAL scan — coverage carried.",
            "findings": [],
        },
        prior_turns=[prior],
    )

    env = _run(tmp_path, model)

    assert env["partial"] is True
    assert "shell x1" in env["coverage"]
    assert "example.com" in env["coverage"]
