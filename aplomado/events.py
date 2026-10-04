"""Scan event emission for downstream consumers (Quarterdeck).

When a scan finishes, Aplomado wraps the normalized findings envelope in an
event with metadata and writes it to a sink. Quarterdeck (or anything else)
can consume these events without importing Aplomado.

Event shape (``aplomado.scan.completed``):

    {
        "type": "aplomado.scan.completed",
        "id": "<uuid4>",
        "producer": "aplomado",
        "timestamp": "<ISO-8601 UTC>",
        "data": {
            "target": "...",
            "summary": "...",
            "scanned_at": "...",
            "findings": [...],
            // ok, error, metadata when present
            // unknown fields preserved as-is
        }
    }

Unknown fields in the findings envelope pass through into ``data`` unchanged —
if the model or future Aplomado versions add fields (confidence, remediation,
fingerprint, etc.), they're preserved.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Protocol


# -- Event builder ------------------------------------------------------------

def build_event(envelope: dict, ok: bool = True, error: str | None = None,
                metadata: dict | None = None) -> dict:
    """Wrap a normalized findings envelope in a scan-completed event.

    The envelope dict is placed under ``data`` as-is (unknown fields preserved).
    ``ok``, ``error``, and ``metadata`` are merged into ``data`` when provided.
    """
    data = dict(envelope)  # shallow copy — don't mutate the caller's dict
    data["ok"] = ok
    if error is not None:
        data["error"] = error
    if metadata:
        data["metadata"] = metadata

    return {
        "type": "aplomado.scan.completed",
        "id": str(uuid.uuid4()),
        "producer": "aplomado",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }


# -- Sinks --------------------------------------------------------------------

class EventSink(Protocol):
    """Where events go."""

    def emit(self, event: dict) -> None: ...
    def close(self) -> None: ...


class NullSink:
    """Discard events (no --event-sink configured)."""

    def emit(self, event: dict) -> None:
        return None

    def close(self) -> None:
        return None


class StdoutSink:
    """Write one JSONL line per event to stdout."""

    def emit(self, event: dict) -> None:
        print(json.dumps(event, separators=(",", ":"), ensure_ascii=False),
              flush=True)

    def close(self) -> None:
        return None


class FileSink:
    """Append one JSONL line per event to a file."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = open(path, "a", encoding="utf-8")

    def emit(self, event: dict) -> None:
        self._fh.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False))
        self._fh.write("\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def resolve_sink(path: str | None) -> EventSink:
    """Build the right sink from a CLI flag value.

    - None or "" -> NullSink (no event emission)
    - "-" -> StdoutSink
    - anything else -> FileSink at that path
    """
    if not path:
        return NullSink()
    if path == "-":
        return StdoutSink()
    return FileSink(path)
