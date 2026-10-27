"""Tests for large-output elision through scratch buffers."""

from __future__ import annotations

from langchain_core.messages import AIMessage, ToolMessage
from pinnace import ExecResult

from aplomado.buffers import (
    BUFFER_THRESHOLD,
    BufferStore,
    FullOutput,
)
from aplomado.scanner import run_scan
from test_fuzz import StubSandbox
from test_subagents import ScriptedModel, _finish, _sandbox, _tc


def _store(sandbox=None, **kwargs):
    trace = kwargs.pop("trace", [])
    store = BufferStore(sandbox or StubSandbox(), trace=trace.append, **kwargs)
    return store, trace


def _shell_result(model):
    return [
        message
        for message in model.requests[-1][1]
        if isinstance(message, ToolMessage) and message.name == "shell"
    ][-1]


def test_output_at_or_below_threshold_passes_through_untouched():
    store, trace = _store()
    text = "x" * BUFFER_THRESHOLD

    assert store.maybe_buffer("shell", text) == text
    assert store.sandbox.files == {}
    assert trace == []


def test_oversized_output_is_buffered_with_notice_and_full_file():
    sandbox = StubSandbox()
    store, trace = _store(sandbox)
    text = "row data\n" * 1_000

    out = store.maybe_buffer("shell", text)

    assert out.startswith("[large output withheld: shell returned")
    assert "buf-1" in out
    assert "scratch/buffers/buf-1.txt" in out
    assert 'mode="snippet"' in out
    assert 'mode="search"' in out
    assert 'mode="describe"' in out
    assert 'mode="save"' in out
    assert text not in out
    assert sandbox.files["scratch/buffers/buf-1.txt"] == text
    created = [event for event in trace if event["type"] == "buffer.created"]
    assert created[0]["buffer_id"] == "buf-1"
    assert created[0]["size"] == len(text)
    assert created[0]["tool"] == "shell"


def test_full_output_attribute_buffers_uncapped_wrapper_text():
    sandbox = StubSandbox()
    store, _ = _store(sandbox, threshold=500)
    full = "full output line\n" * 100
    visible = FullOutput(full[:100] + "…[truncated]", full=full)

    out = store.maybe_buffer("nuclei", visible)

    assert "large output withheld" in out
    assert sandbox.files["scratch/buffers/buf-1.txt"] == full


def test_snippet_mode_supports_head_tail_lines_and_chars():
    sandbox = StubSandbox()
    store, _ = _store(sandbox, threshold=1_000_000)
    text = "one\ntwo\nthree\nfour\nfive\n"
    sandbox.files["scratch/buffers/buf-1.txt"] = text

    assert store.read("buf-1", "snippet", head=2) == "one\ntwo\n"
    assert store.read("buf-1", "snippet", tail=2) == "four\nfive\n"
    assert store.read("buf-1", "snippet", offset=1, limit=2) == "two\nthree\n"
    assert store.read(
        "buf-1", "snippet", unit="chars", offset=4, limit=7
    ) == "two\nthr"


def test_search_mode_returns_matches_with_context_and_line_numbers():
    sandbox = StubSandbox()
    store, _ = _store(sandbox, threshold=1_000_000)
    text = "alpha\nneedle one\nbravo\ncharlie\nneedle two\ndelta\n"
    sandbox.files["scratch/buffers/buf-1.txt"] = text

    out = store.read("buf-1", "search", pattern="needle", context=1)

    assert "[2 matching lines]" in out
    assert "2: needle one" in out
    assert "1- alpha" in out
    assert "3- bravo" in out
    assert "5: needle two" in out
    assert "4- charlie" in out


def test_save_mode_copies_full_buffer_or_a_slice_to_scratch():
    sandbox = StubSandbox()
    store, trace = _store(sandbox, threshold=1_000_000)
    text = "one\ntwo\nthree\n"
    sandbox.files["scratch/buffers/buf-1.txt"] = text

    out = store.read("buf-1", "save", path="scratch/copy.txt")
    assert "saved buffer buf-1" in out
    assert sandbox.files["scratch/copy.txt"] == text

    store.read("buf-1", "save", path="scratch/head.txt", head=2)
    assert sandbox.files["scratch/head.txt"] == "one\ntwo\n"
    assert any(event["type"] == "buffer.saved" for event in trace)


def test_save_rejects_paths_outside_scratch():
    sandbox = StubSandbox()
    store, _ = _store(sandbox, threshold=1_000_000)
    sandbox.files["scratch/buffers/buf-1.txt"] = "data\n"

    out = store.read("buf-1", "save", path="../escape.txt")

    assert out.startswith("error:")
    assert "../escape.txt" not in sandbox.files


def test_oversized_mode_result_is_buffered_again_instead_of_dumped():
    sandbox = StubSandbox()
    store, _ = _store(sandbox, threshold=50)
    text = "\n".join(f"line {index}" for index in range(500)) + "\n"
    store.store("shell", text)

    out = store.read("buf-1", "snippet", head=500)

    assert out.startswith("[large output withheld: buffer_read[snippet] returned")
    assert "buf-2" in out
    assert sandbox.files["scratch/buffers/buf-2.txt"] == text
    assert text not in out


def test_shell_output_just_under_threshold_is_not_buffered(tmp_path):
    sandbox = _sandbox()
    text = "small output\n" * 100
    sandbox.exec_scripts["cat small"] = ExecResult(text, "", 0)
    model = ScriptedModel(
        [
            AIMessage(
                content="",
                tool_calls=[_tc("shell", {"command": "cat small"}, 1)],
            ),
            _finish("done"),
        ],
        [_finish("unused")],
    )
    trace = []

    run_scan(
        "https://example.com",
        model=model,
        sandbox=sandbox,
        log=lambda *args: None,
        trace=trace.append,
    )

    assert text in _shell_result(model).content
    assert not any(path.startswith("scratch/buffers/") for path in sandbox.files)
    assert not any(event["type"].startswith("buffer.") for event in trace)


def test_shell_output_over_threshold_is_buffered_and_traced(tmp_path):
    sandbox = _sandbox()
    text = "row data\n" * 1_000
    sandbox.exec_scripts["cat dump"] = ExecResult(text, "", 0)
    model = ScriptedModel(
        [
            AIMessage(
                content="",
                tool_calls=[_tc("shell", {"command": "cat dump"}, 1)],
            ),
            _finish("done"),
        ],
        [_finish("unused")],
    )
    trace = []

    run_scan(
        "https://example.com",
        model=model,
        sandbox=sandbox,
        log=lambda *args: None,
        trace=trace.append,
    )

    result = _shell_result(model).content
    assert result.startswith("[large output withheld: shell returned")
    assert "buf-1" in result
    assert text not in result
    buffered = sandbox.files["scratch/buffers/buf-1.txt"]
    assert text in buffered
    assert buffered.startswith("$ cat dump\n")
    created = [event for event in trace if event["type"] == "buffer.created"]
    assert created[0]["buffer_id"] == "buf-1"
    assert created[0]["size"] == len(buffered)


def test_describe_mode_uses_a_subagent_and_returns_only_the_answer(tmp_path):
    sandbox = _sandbox()
    text = "field=username value=root\n" * 500
    sandbox.exec_scripts["cat dump"] = ExecResult(text, "", 0)
    model = ScriptedModel(
        [
            AIMessage(
                content="",
                tool_calls=[_tc("shell", {"command": "cat dump"}, 1)],
            ),
            AIMessage(
                content="",
                tool_calls=[
                    _tc(
                        "buffer_read",
                        {
                            "buffer_id": "buf-1",
                            "mode": "describe",
                            "question": "what is the username?",
                        },
                        2,
                    )
                ],
            ),
            _finish("done"),
        ],
        [_finish("the username is root")],
    )
    trace = []

    run_scan(
        "https://example.com",
        model=model,
        sandbox=sandbox,
        log=lambda *args: None,
        trace=trace.append,
    )

    described = [
        message
        for message in model.requests[-1][1]
        if isinstance(message, ToolMessage) and message.name == "buffer_read"
    ][-1]
    assert described.content == "the username is root"
    assert "field=username" not in described.content
    assert any(
        event["type"] == "subagent.finished"
        and event["summary"] == "the username is root"
        for event in trace
    )
    assert any(event["type"] == "buffer.read" for event in trace)
    child_request = [messages for child, messages in model.requests if child][0]
    assert any(
        "field=username" in str(getattr(message, "content", ""))
        for message in child_request
    )
