"""Thinking narration tests: no credentials, containers, or network."""

from __future__ import annotations

from types import SimpleNamespace

from langchain_core.messages import AIMessage

from aplomado.cli import build_parser
from aplomado.scanner import run_scan
from aplomado.thinking import (
    COMPACT_MAX_CHARS,
    THINKING_BUDGET_TOKENS,
    THINKING_MAX_TOKENS,
    ThinkingModel,
    extract_thinking,
    prepare_thinking_model,
    render_thinking,
)
from pinnace import LocalSandbox
from pinnace.session import SessionStore


def test_extract_thinking_from_blocks_and_metadata_without_duplicates():
    response = AIMessage(
        content=[
            {"type": "thinking", "thinking": "inspect headers"},
            {"type": "redacted_thinking", "data": "opaque"},
            {"type": "text", "text": "answer"},
        ],
        additional_kwargs={"reasoning_content": "inspect headers"},
        response_metadata={"reasoning": "compare responses"},
    )
    assert extract_thinking(response) == (
        "inspect headers\n[redacted thinking]\ncompare responses"
    )


def test_extract_thinking_accepts_object_blocks():
    response = SimpleNamespace(
        content=[SimpleNamespace(type="reasoning", text="object reasoning")],
        additional_kwargs={},
        response_metadata={},
    )
    assert extract_thinking(response) == "object reasoning"


def test_extract_thinking_empty_for_plain_text():
    assert extract_thinking(AIMessage(content="plain response")) == ""


def test_compact_render_is_single_line_and_bounded():
    output = render_thinking("first\n\nsecond " + "x" * 500, "compact")
    assert output.startswith("thinking: first second ")
    assert "\n" not in output
    assert len(output) <= len("thinking: ") + COMPACT_MAX_CHARS + 1
    assert output.endswith("…")


def test_verbose_render_preserves_lines():
    assert render_thinking("first\nsecond", "verbose") == (
        "thinking (verbose):\n  first\n  second"
    )


class FakeModel:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        response = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        return response


def _tc(name, args, index):
    return {"name": name, "args": args, "id": f"call-{index}", "type": "tool_call"}


def test_thinking_model_reports_each_reasoning_response():
    logs = []
    model = ThinkingModel(
        FakeModel([AIMessage(content=[{"type": "thinking", "thinking": "check input"}])]),
        "compact",
        logs.append,
    )
    response = model.bind_tools([]).invoke([])
    assert isinstance(response, AIMessage)
    assert logs == ["thinking: check input"]


def test_prepare_thinking_model_builds_supported_extended_model(monkeypatch):
    seen = {}
    fake = FakeModel([AIMessage(content="done")])

    def fake_init(name, model_provider=None, **kwargs):
        seen.update(name=name, provider=model_provider, kwargs=kwargs)
        return fake

    monkeypatch.setattr("langchain.chat_models.init_chat_model", fake_init)
    prepared = prepare_thinking_model("anthropic:claude-opus-4-6", "compact")
    assert prepared is fake
    assert seen["provider"] == "anthropic"
    assert seen["kwargs"]["thinking"] == {
        "type": "enabled",
        "budget_tokens": THINKING_BUDGET_TOKENS,
    }
    assert seen["kwargs"]["max_tokens"] == THINKING_MAX_TOKENS


def test_prepare_thinking_model_off_preserves_lazy_resolution():
    assert prepare_thinking_model(None, None) is None


def test_cli_thinking_modes():
    compact = build_parser().parse_args(["scan", "--target", "example.com", "--thinking"])
    verbose = build_parser().parse_args(
        ["scan", "--target", "example.com", "--thinking", "verbose"]
    )
    disabled = build_parser().parse_args(["scan", "--target", "example.com"])
    assert compact.thinking == "compact"
    assert verbose.thinking == "verbose"
    assert disabled.thinking is None


def test_run_scan_emits_thinking_through_log_callback(tmp_path):
    payload = '{"summary":"done","findings":[]}'
    model = FakeModel(
        [
            AIMessage(
                content=[{"type": "thinking", "thinking": "inspect the response"}],
                tool_calls=[_tc("shell", {"command": "printf ok"}, 1)],
            ),
            AIMessage(
                content="",
                tool_calls=[_tc("finish", {"result": payload}, 2)],
            ),
        ]
    )
    logs = []
    envelope = run_scan(
        "example.com",
        model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        thinking="compact",
        log=logs.append,
    )
    assert envelope["summary"] == "done"
    assert "thinking: inspect the response" in logs


def test_run_scan_default_does_not_emit_thinking(tmp_path):
    logs = []
    run_scan(
        "example.com",
        model=FakeModel([AIMessage(content="done")]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        log=logs.append,
    )
    assert not any(message.startswith("thinking") for message in logs)
