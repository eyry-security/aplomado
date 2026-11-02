"""G1: the turn budget is the run-control; token usage is only a ceiling."""

import json

from langchain_core.messages import AIMessage

from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore

FINISH = json.dumps({
    "target": "https://example.com",
    "summary": "done",
    "findings": [],
})


def _tc(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


def _usage(inp, out):
    return {"input_tokens": inp, "output_tokens": out,
            "total_tokens": inp + out}


class ScriptedModel:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        return self.script[min(self.calls - 1, len(self.script) - 1)]


def _run(tmp_path, script, **kwargs):
    kwargs.setdefault("token_budget", 10_000_000)
    kwargs.setdefault("sandbox",
                      LocalSandbox(str(tmp_path / "work"), unsafe_ok=True))
    kwargs.setdefault("session_store", SessionStore(tmp_path / "sessions"))
    kwargs.setdefault("log", lambda *a: None)
    return run_scan(
        "https://example.com",
        model=ScriptedModel(script),
        **kwargs,
    )


def test_multi_tool_call_response_costs_one_turn(tmp_path):
    script = [
        AIMessage(
            content="",
            usage_metadata=_usage(100, 10),
            tool_calls=[
                _tc("shell", {"command": "echo one"}, 1),
                _tc("shell", {"command": "echo two"}, 2),
            ],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(50, 5),
            tool_calls=[_tc("finish", {"result": FINISH}, 3)],
        ),
    ]
    env = _run(tmp_path, script, max_turns=10)

    assert env["turn_budget"]["used"] == 2
    assert env["turn_budget"]["exhausted"] is False
    assert env["token_budget"]["used"] == 165


def test_compaction_call_costs_no_budget_turn_but_is_metered(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "aplomado.agent.needs_compaction",
        lambda messages, max_tokens: True,
    )
    store = SessionStore(tmp_path / "sessions")
    store.save("history", [
        AIMessage(content=f"older message {i}") for i in range(12)
    ])
    script = [
        AIMessage(content="summary", usage_metadata=_usage(40, 4)),
        AIMessage(
            content="",
            usage_metadata=_usage(100, 10),
            tool_calls=[_tc("finish", {"result": FINISH}, 1)],
        ),
    ]
    env = _run(tmp_path, script, max_turns=10,
               session_id="history", session_store=store)

    assert env["turn_budget"]["used"] == 1
    assert env["token_budget"]["used"] == 154


def test_wrapup_calls_cost_no_budget_turn_but_are_metered(tmp_path):
    script = [
        AIMessage(
            content="",
            usage_metadata=_usage(100, 10),
            tool_calls=[_tc("shell", {"command": "echo one"}, 1)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(100, 10),
            tool_calls=[_tc("shell", {"command": "echo two"}, 2)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(50, 5),
            tool_calls=[_tc("finish", {"result": FINISH}, 3)],
        ),
    ]
    env = _run(tmp_path, script, max_turns=2)

    assert env["summary"] == "done"
    assert env["turn_budget"] == {
        "limit": 2, "used": 2, "exhausted": True}
    assert env["token_budget"]["used"] == 275


def test_run_past_old_token_leash_continues_to_finish(tmp_path):
    script = [
        AIMessage(
            content="",
            usage_metadata=_usage(500_000, 0),
            tool_calls=[_tc("shell", {"command": f"echo {i}"}, i)],
        )
        for i in range(1, 5)
    ]
    script.append(AIMessage(
        content="",
        usage_metadata=_usage(500_000, 0),
        tool_calls=[_tc("finish", {"result": FINISH}, 9)],
    ))
    env = _run(tmp_path, script, max_turns=10)

    assert env["summary"] == "done"
    assert env["turn_budget"]["used"] == 5
    assert env["token_budget"]["used"] == 2_500_000
    assert env["token_budget"]["exhausted"] is False
