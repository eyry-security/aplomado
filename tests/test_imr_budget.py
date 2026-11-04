"""$1 IMR per-host budget: cost math, prompt line, and wrap-up behavior."""

from __future__ import annotations

import json
from decimal import Decimal

from langchain_core.messages import AIMessage, SystemMessage

from aplomado.budget import (
    RateCard,
    ScanBudget,
    budget_line,
    cost_from_usage,
)
from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore

FINISH = json.dumps({
    "target": "https://example.com",
    "summary": "done",
    "findings": [{
        "severity": "high",
        "title": "Confirmed issue",
        "detail": "verified",
        "evidence": "HTTP 200",
    }],
})

ENV_NAMES = (
    "EYRY_AI_SCAN_BUDGET_USD_PER_HOST",
    "EYRY_DEEPSEEK_USD_PER_M_INPUT_MISS",
    "EYRY_DEEPSEEK_USD_PER_M_INPUT_HIT",
    "EYRY_DEEPSEEK_USD_PER_M_OUTPUT",
)


def _clear_budget_env(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def _tc(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


def _usage(inp, out=0, cache_read=None):
    usage = {
        "input_tokens": inp,
        "output_tokens": out,
        "total_tokens": inp + out,
    }
    if cache_read is not None:
        usage["input_token_details"] = {"cache_read": cache_read}
    return usage


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


def _run(tmp_path, model, **kwargs):
    kwargs.setdefault(
        "sandbox", LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    )
    kwargs.setdefault("session_store", SessionStore(tmp_path / "sessions"))
    kwargs.setdefault("log", lambda *a: None)
    return run_scan("https://example.com", model=model, **kwargs)


def _budget_lines(request):
    return [
        str(message.content)
        for message in request
        if isinstance(message, SystemMessage)
        and str(message.content).startswith("[BUDGET]")
    ]


def test_cost_math_uses_miss_hit_and_output_rates(monkeypatch):
    _clear_budget_env(monkeypatch)
    rates = RateCard.from_env()
    cost = cost_from_usage({
        "prompt_cache_miss_tokens": 1_000_000,
        "prompt_cache_hit_tokens": 1_000_000,
        "completion_tokens": 1_000_000,
    }, rates)
    assert cost == Decimal("1.506")


def test_cost_math_without_cache_split_bills_all_prompt_as_miss(monkeypatch):
    _clear_budget_env(monkeypatch)
    rates = RateCard.from_env()
    cost = cost_from_usage({
        "prompt_tokens": 1_000_000,
        "completion_tokens": 0,
    }, rates)
    assert cost == Decimal("0.300")


def test_standard_usage_metadata_split_is_used(monkeypatch):
    _clear_budget_env(monkeypatch)
    rates = RateCard.from_env()
    cost = cost_from_usage({
        "input_tokens": 1_000_000,
        "output_tokens": 0,
        "input_token_details": {"cache_read": 500_000},
    }, rates)
    assert cost == Decimal("0.153")


def test_tracker_accumulates_spent_and_remaining(monkeypatch):
    _clear_budget_env(monkeypatch)
    budget = ScanBudget("1.00", RateCard.from_env())
    budget.record_usage({
        "prompt_cache_miss_tokens": 1_000_000,
        "prompt_cache_hit_tokens": 0,
        "completion_tokens": 0,
    })
    budget.record_usage({
        "prompt_cache_miss_tokens": 0,
        "prompt_cache_hit_tokens": 0,
        "completion_tokens": 100_000,
    })
    assert budget.spent == Decimal("0.420")
    assert budget.remaining == Decimal("0.580")
    assert budget.exhausted is False


def test_budget_line_at_turns_two_and_three(tmp_path, monkeypatch):
    _clear_budget_env(monkeypatch)
    model = RecordingModel([
        AIMessage(
            content="",
            usage_metadata=_usage(100_000),
            tool_calls=[_tc("shell", {"command": "echo one"}, 1)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(100_000),
            tool_calls=[_tc("shell", {"command": "echo two"}, 2)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(100_000),
            tool_calls=[_tc("finish", {"result": FINISH}, 3)],
        ),
    ])
    env = _run(tmp_path, model, max_turns=10)

    assert env["budget"]["limit_usd"] == 1.0
    assert env["budget"]["exhausted"] is False
    assert "outcome" not in env

    turn2 = _budget_lines(model.requests[1])
    assert len(turn2) == 1
    assert (
        "spent $0.03 of its $1.00 budget; $0.97 remains" in turn2[0]
    )
    assert "about" not in turn2[0]
    assert "File each finding as you confirm it." in turn2[0]

    turn3 = _budget_lines(model.requests[2])
    assert len(turn3) == 1
    assert (
        "spent $0.06 of its $1.00 budget; $0.94 remains" in turn3[0]
    )
    assert "(about 31 turns at the recent pace)" in turn3[0]


def test_ninety_percent_switches_to_wrap_up_order(tmp_path, monkeypatch):
    _clear_budget_env(monkeypatch)
    model = RecordingModel([
        AIMessage(
            content="",
            usage_metadata=_usage(3_100_000),
            tool_calls=[_tc("shell", {"command": "echo one"}, 1)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(0),
            tool_calls=[_tc("finish", {"result": FINISH}, 2)],
        ),
    ])
    env = _run(tmp_path, model, max_turns=10)

    assert env["budget"]["exhausted"] is False
    line = _budget_lines(model.requests[1])[0]
    assert "spent $0.93 of its $1.00 budget; $0.07 remains" in line
    assert "stop opening new lines of investigation" in line
    assert "file outstanding findings now" in line


def test_hundred_percent_gets_one_final_turn_and_budget_outcome(
    tmp_path, monkeypatch
):
    _clear_budget_env(monkeypatch)
    model = RecordingModel([
        AIMessage(
            content="",
            usage_metadata=_usage(4_000_000),
            tool_calls=[_tc("shell", {"command": "echo one"}, 1)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(0),
            tool_calls=[_tc("finish", {"result": FINISH}, 2)],
        ),
    ])
    events = []

    class Sink:
        def emit(self, event):
            events.append(event)

        def close(self):
            pass

    env = _run(tmp_path, model, max_turns=10, event_sink=Sink())

    assert model.calls == 2
    final_request = model.requests[1]
    line = _budget_lines(final_request)[0]
    assert "The budget is exhausted." in line
    assert "This is the final wrap-up turn" in line
    assert "Only finish() may be called." in line
    assert (
        "BUDGET EXHAUSTED" in final_request[-1].content
    )

    assert env["outcome"] == "budget_exhausted"
    assert env["budget"]["exhausted"] is True
    assert env["budget"]["spent_usd"] == 1.2
    assert env["findings"][0]["title"] == "Confirmed issue"
    assert events[0]["data"]["outcome"] == "budget_exhausted"
    assert events[0]["data"]["ok"] is True


def test_budget_exhausted_final_turn_is_filing_only(tmp_path, monkeypatch):
    _clear_budget_env(monkeypatch)
    model = RecordingModel([
        AIMessage(
            content="",
            usage_metadata=_usage(4_000_000),
            tool_calls=[_tc("shell", {"command": "echo one"}, 1)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(0),
            tool_calls=[_tc(
                "write_file",
                {"path": "scratch/not-allowed.txt", "content": "no"},
                2,
            )],
        ),
    ])
    env = _run(tmp_path, model, max_turns=10)

    assert model.calls == 2
    assert env["outcome"] == "budget_exhausted"
    assert not (tmp_path / "work" / "scratch" / "not-allowed.txt").exists()
    assert env["summary"] == "scan ended with the budget exhausted"


def test_default_budget_applies_without_any_budget_env(tmp_path, monkeypatch):
    _clear_budget_env(monkeypatch)
    model = RecordingModel([
        AIMessage(
            content="",
            usage_metadata=_usage(4_000_000),
            tool_calls=[_tc("shell", {"command": "echo one"}, 1)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(0),
            tool_calls=[_tc("finish", {"result": FINISH}, 2)],
        ),
    ])
    env = _run(tmp_path, model, max_turns=10)

    assert env["budget"]["limit_usd"] == 1.0
    assert env["outcome"] == "budget_exhausted"


def test_budget_env_overrides_default(tmp_path, monkeypatch):
    _clear_budget_env(monkeypatch)
    monkeypatch.setenv("EYRY_AI_SCAN_BUDGET_USD_PER_HOST", "0.50")
    model = RecordingModel([
        AIMessage(
            content="",
            usage_metadata=_usage(2_000_000),
            tool_calls=[_tc("shell", {"command": "echo one"}, 1)],
        ),
        AIMessage(
            content="",
            usage_metadata=_usage(0),
            tool_calls=[_tc("finish", {"result": FINISH}, 2)],
        ),
    ])
    env = _run(tmp_path, model, max_turns=10)

    assert env["budget"]["limit_usd"] == 0.5
    assert env["outcome"] == "budget_exhausted"


def test_budget_line_helper_formats_live_numbers(monkeypatch):
    _clear_budget_env(monkeypatch)
    budget = ScanBudget("1.00", RateCard.from_env())
    budget.record_usage({
        "prompt_cache_miss_tokens": 1_400_000,
        "prompt_cache_hit_tokens": 0,
        "completion_tokens": 0,
    })
    line = budget_line(budget, completed_turns=2)
    assert line.startswith(
        "[BUDGET] This host review has spent $0.42 of its $1.00 budget; "
        "$0.58 remains"
    )
    assert "(about 3 turns at the recent pace)" in line
