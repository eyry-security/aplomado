"""Large-output elision through agent-readable scratch buffers.

Tool results above :data:`BUFFER_THRESHOLD` are written in full to
``scratch/buffers/<buffer_id>.txt``. The agent receives a short notice with a
preview and a buffer id instead of the bulk output, then chooses how to pull
what it needs back with ``buffer_read``.
"""

from __future__ import annotations

import posixpath
import re
import threading
import time
from collections.abc import Callable
from pathlib import PurePosixPath

from langchain_core.tools import BaseTool, StructuredTool
from pinnace import Sandbox

BUFFER_THRESHOLD = 6_000
BUFFER_DIR = "scratch/buffers"
BUFFER_PREVIEW_CHARS = 300
BUFFER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SNIPPET_DEFAULT_LINES = 200
SEARCH_DEFAULT_CONTEXT = 2
TraceCallback = Callable[[dict], None]


class FullOutput(str):
    """A possibly-truncated visible string that still carries its full text.

    Scanner wrappers keep their display caps for direct callers, but the agent
    harness buffers the complete output instead of the capped preview.
    """

    def __new__(cls, visible: str, full: str | None = None) -> "FullOutput":
        obj = super().__new__(cls, visible)
        obj.full_output = visible if full is None else full
        return obj


def _line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _preview(text: str) -> str:
    preview = text[:BUFFER_PREVIEW_CHARS]
    if len(text) > BUFFER_PREVIEW_CHARS:
        preview += "\n…[preview truncated]"
    return preview


def _buffer_path(buffer_id: str) -> str:
    value = str(buffer_id).strip()
    if not value or not BUFFER_ID_RE.fullmatch(value) or value in {".", ".."}:
        raise ValueError(f"invalid buffer id {buffer_id!r}")
    return posixpath.join(BUFFER_DIR, f"{value}.txt")


def _scratch_path(path: str) -> str:
    value = str(path).strip()
    if not value or "\x00" in value:
        raise ValueError("path must be a non-empty scratch/ path")
    raw = PurePosixPath(value)
    if raw.is_absolute() or ".." in raw.parts:
        raise ValueError("path must stay inside scratch/")
    normalised = posixpath.normpath(value)
    if not normalised.startswith("scratch/") or normalised == "scratch":
        raise ValueError("path must name a file under scratch/")
    if normalised.startswith(f"{BUFFER_DIR}/"):
        raise ValueError("choose a scratch/ path outside the buffer directory")
    return normalised


def _as_int(value, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _slice_text(
    text: str,
    *,
    offset: int = 0,
    limit: int | None = None,
    unit: str = "lines",
    head: int = 0,
    tail: int = 0,
) -> str:
    """Return a head/tail slice or an offset/limit slice of *text*."""
    head = _as_int(head, "head")
    tail = _as_int(tail, "tail")
    offset = _as_int(offset, "offset")
    if head < 0 or tail < 0:
        raise ValueError("head and tail must be non-negative")
    if head and tail:
        raise ValueError("choose head or tail, not both")

    if head:
        return "".join(text.splitlines(keepends=True)[:head])
    if tail:
        return "".join(text.splitlines(keepends=True)[-tail:])

    if limit is not None:
        limit = _as_int(limit, "limit")
        if limit < 0:
            raise ValueError("limit must be non-negative")
    selected_unit = str(unit or "lines").strip().lower()
    if selected_unit in {"char", "chars", "character", "characters"}:
        start = offset if offset >= 0 else max(0, len(text) + offset)
        count = len(text) - start if limit is None else limit
        return text[start:start + max(0, count)]
    if selected_unit not in {"line", "lines"}:
        raise ValueError("unit must be 'lines' or 'chars'")

    lines = text.splitlines(keepends=True)
    start = offset if offset >= 0 else max(0, len(lines) + offset)
    count = len(lines) - start if limit is None else limit
    return "".join(lines[start:start + max(0, count)])


def _search_text(text: str, pattern: str, context: int = SEARCH_DEFAULT_CONTEXT) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty regular expression")
    try:
        expression = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid search pattern {pattern!r}: {exc}") from exc
    context = _as_int(context, "context")
    if context < 0:
        raise ValueError("context must be non-negative")
    context = min(context, 100)

    lines = text.splitlines()
    matches = [index for index, line in enumerate(lines) if expression.search(line)]
    if not matches:
        return f"no matches for {pattern!r}"

    match_set = set(matches)
    wanted: set[int] = set()
    for index in matches:
        wanted.update(
            range(max(0, index - context), min(len(lines), index + context + 1))
        )
    output = [f"[{len(matches)} matching lines]"]
    previous = -2
    for index in sorted(wanted):
        if index != previous + 1:
            output.append("--")
        marker = ":" if index in match_set else "-"
        output.append(f"{index + 1}{marker} {lines[index]}")
        previous = index
    return "\n".join(output)


class BufferStore:
    """Writes full tool output to buffers and serves agent-directed reads."""

    def __init__(
        self,
        sandbox: Sandbox,
        *,
        trace: TraceCallback | None = None,
        log: Callable[[str], None] | None = None,
        threshold: int = BUFFER_THRESHOLD,
        describe: Callable[[str, str], str] | None = None,
    ) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        self.sandbox = sandbox
        self.trace = trace
        self.log = log or (lambda *args: None)
        self.threshold = int(threshold)
        self.describe = describe
        self._lock = threading.Lock()
        self._counter = 0

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"buf-{self._counter}"

    def _emit(self, kind: str, **data) -> None:
        if self.trace is None:
            return
        event = {"type": f"buffer.{kind}", "timestamp": time.time()}
        event.update(data)
        try:
            self.trace(event)
        except Exception:  # noqa: BLE001 - tracing must never break a run
            pass

    def maybe_buffer(self, tool_name: str, output) -> str:
        """Return *output* unchanged when small, or store it and return a notice."""
        full = getattr(output, "full_output", None)
        text = full if isinstance(full, str) else str(output)
        if len(text) <= self.threshold:
            return str(output)
        return self.store(tool_name, text)

    def store(self, tool_name: str, text: str) -> str:
        """Write *text* to a new buffer and return the agent-facing notice."""
        buffer_id = self._next_id()
        path = _buffer_path(buffer_id)
        chars, lines = len(text), _line_count(text)
        try:
            self.sandbox.write_file(path, text)
        except Exception as exc:  # noqa: BLE001 - the agent sees the failure
            self._emit(
                "failed",
                buffer_id=buffer_id,
                tool=tool_name,
                size=chars,
                chars=chars,
                lines=lines,
                path=path,
                error=str(exc),
            )
            return (
                f"error: {tool_name} returned {chars:,} chars / {lines:,} lines "
                f"but the full output could not be buffered at {path}: {exc}"
            )

        self._emit(
            "created",
            buffer_id=buffer_id,
            tool=tool_name,
            size=chars,
            chars=chars,
            lines=lines,
            path=path,
        )
        self.log(
            f"[pinnace] buffered {tool_name} output "
            f"({chars:,} chars / {lines:,} lines) as {buffer_id}"
        )
        return (
            f"[large output withheld: {tool_name} returned "
            f"{chars:,} chars / {lines:,} lines]\n\n"
            f"Preview:\n{_preview(text)}\n\n"
            f"Full output: {buffer_id} at {path}\n"
            "Retrieve only what you need with buffer_read(buffer_id, mode):\n"
            '  - mode="snippet": head=N or tail=N, or offset=N & limit=N '
            '(unit="lines" default, or unit="chars")\n'
            '  - mode="search": pattern="<regex>", context=N lines around matches\n'
            '  - mode="describe": question="<specific question>" for a sub-agent '
            "to read the buffer and return only the answer\n"
            '  - mode="save": path="scratch/<file>" to copy the buffer or a slice '
            "for later use\n"
            "Do not re-run the tool just to fetch the bulk output."
        )

    def read(self, buffer_id: str, mode: str = "snippet", **kwargs) -> str:
        """Serve one ``buffer_read`` mode, re-buffering oversized results."""
        selected = str(mode or "snippet").strip().lower()
        try:
            path = _buffer_path(buffer_id)
            text = self.sandbox.read_file(path)
        except Exception as exc:  # noqa: BLE001 - surface it to the model
            return f"error: can't read buffer {buffer_id!r}: {exc}"

        try:
            result = self._run_mode(selected, buffer_id, path, text, **kwargs)
        except (TypeError, ValueError) as exc:
            return f"error: {exc}"

        self._emit(
            "read",
            buffer_id=str(buffer_id),
            mode=selected,
            size=len(result),
            chars=len(result),
            path=path,
        )
        return self.maybe_buffer(f"buffer_read[{selected}]", result)

    def _run_mode(
        self,
        mode: str,
        buffer_id: str,
        buffer_path: str,
        text: str,
        **kwargs,
    ) -> str:
        if mode == "snippet":
            return _slice_text(
                text,
                offset=kwargs.get("offset", 0),
                limit=kwargs.get("limit"),
                unit=kwargs.get("unit", "lines"),
                head=kwargs.get("head", 0),
                tail=kwargs.get("tail", 0),
            )
        if mode == "search":
            return _search_text(
                text,
                kwargs.get("pattern", ""),
                kwargs.get("context", SEARCH_DEFAULT_CONTEXT),
            )
        if mode == "describe":
            question = kwargs.get("question", "")
            if not isinstance(question, str) or not question.strip():
                raise ValueError("describe requires a non-empty question")
            if self.describe is None:
                raise ValueError("describe is unavailable in this run")
            return self.describe(buffer_path, question.strip())
        if mode == "save":
            destination = _scratch_path(kwargs.get("path", ""))
            head = _as_int(kwargs.get("head", 0), "head")
            tail = _as_int(kwargs.get("tail", 0), "tail")
            offset = _as_int(kwargs.get("offset", 0), "offset")
            limit = kwargs.get("limit")
            if head or tail or offset or limit is not None:
                payload = _slice_text(
                    text,
                    offset=offset,
                    limit=limit,
                    unit=kwargs.get("unit", "lines"),
                    head=head,
                    tail=tail,
                )
            else:
                payload = text
            self.sandbox.write_file(destination, payload)
            self._emit(
                "saved",
                buffer_id=str(buffer_id),
                path=destination,
                source=buffer_path,
                size=len(payload),
                chars=len(payload),
            )
            return (
                f"saved buffer {buffer_id} ({len(payload):,} chars / "
                f"{_line_count(payload):,} lines) to {destination}"
            )
        raise ValueError(
            f"unknown buffer mode {mode!r}; choose snippet, describe, search, or save"
        )


def buffer_read_tool(store: BufferStore) -> BaseTool:
    """Build the agent-facing ``buffer_read`` tool."""

    def buffer_read(
        buffer_id: str,
        mode: str = "snippet",
        offset: int = 0,
        limit: int | None = None,
        unit: str = "lines",
        head: int = 0,
        tail: int = 0,
        pattern: str = "",
        context: int = SEARCH_DEFAULT_CONTEXT,
        question: str = "",
        path: str = "",
    ) -> str:
        """Read part of a buffered tool output instead of the raw bulk.

        Modes: snippet (offset/limit or head/tail; unit lines or chars),
        describe (a sub-agent answers question from the buffer), search (regex
        pattern with context lines), and save (copy the buffer or a slice to a
        scratch/ path). Oversized results are buffered again.
        """
        return store.read(
            buffer_id,
            mode,
            offset=offset,
            limit=limit,
            unit=unit,
            head=head,
            tail=tail,
            pattern=pattern,
            context=context,
            question=question,
            path=path,
        )

    return StructuredTool.from_function(
        buffer_read,
        name="buffer_read",
        description=(
            "Read a large tool output that arrived as a buffer notice. Choose "
            'mode="snippet" (offset/limit or head/tail), mode="search" '
            '(pattern + context), mode="describe" (question for a sub-agent), '
            'or mode="save" (path under scratch/). Do not re-run the tool to '
            "fetch bulk data."
        ),
    )
