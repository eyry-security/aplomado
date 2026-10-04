"""Tests for events.py — event shape, sinks, unknown-field preservation.

No API keys, no Docker, no Postgres.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from aplomado.events import (
    FileSink,
    NullSink,
    StdoutSink,
    build_event,
    resolve_sink,
)


# -- build_event: shape -------------------------------------------------------

def _sample_envelope():
    return {
        "target": "https://example.com",
        "summary": "One issue.",
        "scanned_at": "2026-10-04T12:00:00+00:00",
        "findings": [
            {
                "severity": "high",
                "title": "Exposed .git",
                "detail": ".git/HEAD accessible",
                "evidence": "HTTP 200",
            }
        ],
    }


def test_event_has_required_top_level_fields():
    event = build_event(_sample_envelope())
    assert event["type"] == "aplomado.scan.completed"
    assert event["producer"] == "aplomado"
    assert "id" in event
    assert "timestamp" in event
    assert "data" in event


def test_event_id_is_valid_uuid4():
    event = build_event(_sample_envelope())
    parsed = uuid.UUID(event["id"])
    assert parsed.version == 4


def test_event_ids_are_unique():
    e1 = build_event(_sample_envelope())
    e2 = build_event(_sample_envelope())
    assert e1["id"] != e2["id"]


def test_event_timestamp_is_valid_iso():
    event = build_event(_sample_envelope())
    ts = datetime.fromisoformat(event["timestamp"])
    assert ts.tzinfo is not None  # UTC


def test_event_timestamp_is_recent():
    before = datetime.now(timezone.utc)
    event = build_event(_sample_envelope())
    after = datetime.now(timezone.utc)
    ts = datetime.fromisoformat(event["timestamp"])
    assert before <= ts <= after


# -- build_event: data contains full envelope ----------------------------------

def test_data_contains_required_envelope_fields():
    event = build_event(_sample_envelope())
    data = event["data"]
    assert data["target"] == "https://example.com"
    assert data["summary"] == "One issue."
    assert data["scanned_at"] == "2026-10-04T12:00:00+00:00"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "Exposed .git"


def test_data_includes_ok_field():
    event = build_event(_sample_envelope(), ok=True)
    assert event["data"]["ok"] is True

    event = build_event(_sample_envelope(), ok=False, error="timed out")
    assert event["data"]["ok"] is False
    assert event["data"]["error"] == "timed out"


def test_data_includes_metadata_when_provided():
    event = build_event(_sample_envelope(), metadata={"turns": 5, "session": "s1"})
    assert event["data"]["metadata"] == {"turns": 5, "session": "s1"}


def test_data_no_error_key_when_none():
    event = build_event(_sample_envelope(), ok=True, error=None)
    assert "error" not in event["data"]


# -- unknown-field preservation ------------------------------------------------

def test_unknown_fields_in_envelope_preserved():
    envelope = _sample_envelope()
    envelope["confidence"] = "high"
    envelope["remediation"] = "Remove .git from webroot"
    envelope["fingerprint"] = "abc123"
    envelope["custom_field"] = {"nested": True}

    event = build_event(envelope)
    data = event["data"]
    assert data["confidence"] == "high"
    assert data["remediation"] == "Remove .git from webroot"
    assert data["fingerprint"] == "abc123"
    assert data["custom_field"] == {"nested": True}


def test_unknown_fields_in_findings_preserved():
    envelope = _sample_envelope()
    envelope["findings"][0]["confidence"] = "confirmed"
    envelope["findings"][0]["remediation"] = "block .git"
    envelope["findings"][0]["references"] = ["https://example.com/advisory"]

    event = build_event(envelope)
    finding = event["data"]["findings"][0]
    assert finding["confidence"] == "confirmed"
    assert finding["remediation"] == "block .git"
    assert finding["references"] == ["https://example.com/advisory"]


def test_build_event_does_not_mutate_input():
    envelope = _sample_envelope()
    original_keys = set(envelope.keys())
    build_event(envelope, ok=True, error="test", metadata={"x": 1})
    assert set(envelope.keys()) == original_keys
    assert "ok" not in envelope


# -- sinks ---------------------------------------------------------------------

def test_null_sink_does_not_raise():
    sink = NullSink()
    sink.emit(build_event(_sample_envelope()))
    sink.close()


def test_stdout_sink(capsys):
    sink = StdoutSink()
    event = build_event(_sample_envelope())
    sink.emit(event)
    sink.close()
    captured = capsys.readouterr().out.strip()
    parsed = json.loads(captured)
    assert parsed["type"] == "aplomado.scan.completed"
    assert parsed["data"]["target"] == "https://example.com"


def test_file_sink(tmp_path):
    path = str(tmp_path / "events.jsonl")
    sink = FileSink(path)
    e1 = build_event(_sample_envelope())
    e2 = build_event(_sample_envelope())
    sink.emit(e1)
    sink.emit(e2)
    sink.close()

    lines = (tmp_path / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        parsed = json.loads(line)
        assert parsed["type"] == "aplomado.scan.completed"
        assert "id" in parsed


def test_file_sink_appends(tmp_path):
    path = str(tmp_path / "events.jsonl")
    # Write one event, close, reopen, write another
    sink1 = FileSink(path)
    sink1.emit(build_event(_sample_envelope()))
    sink1.close()

    sink2 = FileSink(path)
    sink2.emit(build_event(_sample_envelope()))
    sink2.close()

    lines = (tmp_path / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2


# -- resolve_sink --------------------------------------------------------------

def test_resolve_sink_none_returns_null():
    assert isinstance(resolve_sink(None), NullSink)
    assert isinstance(resolve_sink(""), NullSink)


def test_resolve_sink_dash_returns_stdout():
    assert isinstance(resolve_sink("-"), StdoutSink)


def test_resolve_sink_path_returns_file(tmp_path):
    path = str(tmp_path / "out.jsonl")
    sink = resolve_sink(path)
    assert isinstance(sink, FileSink)
    sink.close()


# -- event is JSON-serializable ------------------------------------------------

def test_event_round_trips_through_json():
    envelope = _sample_envelope()
    envelope["extra"] = [1, None, True, "text"]
    event = build_event(envelope, ok=True, metadata={"k": "v"})
    text = json.dumps(event)
    restored = json.loads(text)
    assert restored["type"] == "aplomado.scan.completed"
    assert restored["data"]["extra"] == [1, None, True, "text"]
    assert restored["data"]["ok"] is True
