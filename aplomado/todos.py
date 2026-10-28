"""Persistent todo list tools for Aplomado scans.

Todos live in ``scratch/todos.json`` inside the scan workdir, so they survive
across turns and are shared by the parent and any sub-agent using the same
sandbox.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from langchain_core.tools import BaseTool, StructuredTool
from pinnace import Sandbox

TODOS_PATH = "scratch/todos.json"
TODO_STATUSES = ("pending", "in_progress", "done", "skipped")
SandboxProvider = Sandbox | Callable[[], Sandbox]


def _resolve_sandbox(provider: SandboxProvider) -> Sandbox:
    return provider() if callable(provider) else provider


def load_todos(sandbox: SandboxProvider) -> list[dict]:
    """Read the persisted todo list, treating a missing file as empty."""
    try:
        raw = _resolve_sandbox(sandbox).read_file(TODOS_PATH)
    except Exception as exc:  # noqa: BLE001 - missing file is the normal start
        if "not found" in str(exc).lower() or "no such file" in str(exc).lower():
            return []
        raise
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{TODOS_PATH} is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError(f"{TODOS_PATH} must contain a JSON list")
    items: list[dict] = []
    for entry in data:
        if isinstance(entry, str):
            items.append({"text": entry, "status": "pending", "note": ""})
        elif isinstance(entry, dict) and isinstance(entry.get("text"), str):
            status = entry.get("status", "pending")
            if status not in TODO_STATUSES:
                status = "pending"
            note = entry.get("note", "")
            items.append(
                {
                    "text": entry["text"],
                    "status": status,
                    "note": note if isinstance(note, str) else str(note),
                }
            )
    return items


def save_todos(sandbox: SandboxProvider, items: list[dict]) -> None:
    _resolve_sandbox(sandbox).write_file(
        TODOS_PATH, json.dumps(items, indent=2) + "\n"
    )


def _format_item(index: int, item: dict) -> str:
    line = f"{index}. [{item['status']}] {item['text']}"
    if item.get("note"):
        line += f" — {item['note']}"
    return line


def format_todos(items: list[dict]) -> str:
    if not items:
        return "todos: (empty)"
    lines = [f"todos ({TODOS_PATH}):"]
    for index, item in enumerate(items, 1):
        lines.append(_format_item(index, item))
    return "\n".join(lines)


def _todo_counts(items: list[dict]) -> str:
    done = sum(1 for item in items if item["status"] == "done")
    skipped = sum(1 for item in items if item["status"] == "skipped")
    open_count = len(items) - done - skipped
    counts = f"done={done} open={open_count} total={len(items)}"
    if skipped:
        counts += f" skipped={skipped}"
    return counts


def _format_todo_delta(items: list[dict], changed: list[int], action: str) -> str:
    lines = [f"todos: {action} — {_todo_counts(items)}"]
    for index in changed:
        lines.append(_format_item(index + 1, items[index]))
    lines.append(f'Full list: read_file("{TODOS_PATH}")')
    return "\n".join(lines)


def _locate(items: list[dict], index_or_text: int | str) -> int:
    """Resolve a 1-based index (0 also means the first) or matching text."""
    if isinstance(index_or_text, bool):
        raise ValueError("index_or_text must be an index or todo text")
    if isinstance(index_or_text, int):
        index = index_or_text
    else:
        text = str(index_or_text).strip()
        if text.isdigit():
            index = int(text)
        else:
            matches = [
                i
                for i, item in enumerate(items)
                if item["text"] == text
            ]
            if not matches:
                needles = [
                    i
                    for i, item in enumerate(items)
                    if text.lower() in item["text"].lower()
                ]
                matches = needles
            if not matches:
                raise ValueError(f"no todo matches {index_or_text!r}")
            if len(matches) > 1:
                raise ValueError(
                    f"{index_or_text!r} matches several todos; use an index"
                )
            return matches[0]
    if index == 0:
        resolved = 0
    else:
        resolved = index - 1
    if not 0 <= resolved < len(items):
        raise ValueError(f"todo index {index} is out of range")
    return resolved


def todo_tools(sandbox: SandboxProvider) -> list[BaseTool]:
    """Build the todos_write / todos_update tools bound to *sandbox*."""

    def todos_write(items: list[str]) -> str:
        """Replace the run's todo list with short imperative tasks.

        Each item starts pending. The updated list is persisted to
        scratch/todos.json; the result is only a compact summary.
        """
        try:
            cleaned = [
                str(item).strip() for item in items if str(item).strip()
            ]
            todos = [
                {"text": text, "status": "pending", "note": ""}
                for text in cleaned
            ]
            save_todos(sandbox, todos)
        except Exception as exc:  # noqa: BLE001 - surface failures to the model
            return f"error: {exc}"
        return (
            f"todos: replaced list — {_todo_counts(todos)}\n"
            "All items reset to pending.\n"
            f'Full list: read_file("{TODOS_PATH}")'
        )

    def todos_update(
        index_or_text: int | str,
        status: str,
        note: str = "",
    ) -> str:
        """Update one todo by 1-based index (0 means first) or by its text.

        status is pending, in_progress, done, or skipped. note records a skip
        reason or a result pointer. The result is a compact delta, not the list.
        """
        if status not in TODO_STATUSES:
            return (
                f"error: status must be one of {', '.join(TODO_STATUSES)}"
            )
        try:
            items = load_todos(sandbox)
            if not items:
                return "error: no todo list yet; call todos_write first"
            index = _locate(items, index_or_text)
            items[index]["status"] = status
            items[index]["note"] = str(note or "").strip()
            save_todos(sandbox, items)
        except Exception as exc:  # noqa: BLE001 - surface failures to the model
            return f"error: {exc}"
        return _format_todo_delta(items, [index], f"updated #{index + 1}")

    return [
        StructuredTool.from_function(
            todos_write,
            name="todos_write",
            description=(
                "Replace the run's todo list with short imperative tasks. "
                "Persists to scratch/todos.json and returns only a compact "
                "summary; read that file for the full list."
            ),
        ),
        StructuredTool.from_function(
            todos_update,
            name="todos_update",
            description=(
                "Update one todo by 1-based index (0 means first) or by text. "
                "status: pending, in_progress, done, or skipped; note carries a "
                "skip reason or result pointer. Returns a compact delta, not "
                "the full list; read scratch/todos.json for that."
            ),
        ),
    ]
