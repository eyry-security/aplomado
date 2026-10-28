"""Tests for the persistent todo tools."""

from __future__ import annotations

import json

from pinnace import LocalSandbox

from aplomado.todos import (
    TODO_STATUSES,
    TODOS_PATH,
    format_todos,
    load_todos,
    todo_tools,
)


def _tools(tmp_path):
    sandbox = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    return sandbox, {tool.name: tool for tool in todo_tools(sandbox)}


def _saved(tmp_path):
    path = tmp_path / "work" / TODOS_PATH
    return json.loads(path.read_text())


def test_todos_write_update_round_trip_persists(tmp_path):
    sandbox, tools = _tools(tmp_path)

    output = tools["todos_write"].invoke(
        {"items": ["recon the target", "test the login flow"]}
    )
    assert "replaced list" in output
    assert "done=0 open=2 total=2" in output
    assert "recon the target" not in output
    assert "test the login flow" not in output
    assert _saved(tmp_path) == [
        {"text": "recon the target", "status": "pending", "note": ""},
        {"text": "test the login flow", "status": "pending", "note": ""},
    ]

    output = tools["todos_update"].invoke(
        {
            "index_or_text": 0,
            "status": "done",
            "note": "scratch/recon.txt",
        }
    )
    assert "1. [done] recon the target — scratch/recon.txt" in output
    assert _saved(tmp_path)[0]["status"] == "done"
    assert _saved(tmp_path)[0]["note"] == "scratch/recon.txt"

    output = tools["todos_update"].invoke(
        {
            "index_or_text": "login flow",
            "status": "skipped",
            "note": "out of scope",
        }
    )
    assert "2. [skipped] test the login flow — out of scope" in output
    assert load_todos(sandbox) == _saved(tmp_path)


def test_todos_update_by_one_based_index(tmp_path):
    _, tools = _tools(tmp_path)
    tools["todos_write"].invoke({"items": ["first", "second"]})

    output = tools["todos_update"].invoke(
        {"index_or_text": 2, "status": "in_progress"}
    )

    assert "2. [in_progress] second" in output
    assert _saved(tmp_path)[1]["status"] == "in_progress"


def test_todos_update_rejects_unknown_status_without_changing_file(tmp_path):
    _, tools = _tools(tmp_path)
    tools["todos_write"].invoke({"items": ["first"]})
    before = _saved(tmp_path)

    output = tools["todos_update"].invoke(
        {"index_or_text": 1, "status": "blocked"}
    )

    assert output.startswith("error:")
    assert _saved(tmp_path) == before


def test_todos_update_requires_an_existing_list(tmp_path):
    _, tools = _tools(tmp_path)

    output = tools["todos_update"].invoke(
        {"index_or_text": 1, "status": "done"}
    )

    assert output.startswith("error:")
    assert not (tmp_path / "work" / TODOS_PATH).exists()


def test_todos_write_replaces_and_formats_the_list(tmp_path):
    sandbox, tools = _tools(tmp_path)
    tools["todos_write"].invoke({"items": ["old"]})

    output = tools["todos_write"].invoke({"items": ["new one", "new two"]})

    assert "old" not in output
    assert [item["text"] for item in load_todos(sandbox)] == [
        "new one",
        "new two",
    ]
    assert all(status in TODO_STATUSES for status in TODO_STATUSES)
    assert format_todos([]) == "todos: (empty)"


def test_todos_update_delta_is_compact_for_large_list(tmp_path):
    sandbox, tools = _tools(tmp_path)
    items = [f"task {n}: " + ("x" * 180) for n in range(1, 26)]
    tools["todos_write"].invoke({"items": items})

    output = tools["todos_update"].invoke(
        {"index_or_text": 13, "status": "done", "note": "scratch/result.txt"}
    )

    assert len(output) < 600
    assert "done=1 open=24 total=25" in output
    assert "13. [done] task 13:" in output
    assert "task 25:" not in output
    persisted = json.loads(sandbox.read_file(TODOS_PATH))
    assert len(persisted) == 25
    assert persisted[12]["status"] == "done"
