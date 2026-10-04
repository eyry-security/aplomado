"""Integration tests for the converged wiring: store in run_scan, CLI flags."""

import json
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage

from aplomado.cli import build_parser
from aplomado.scanner import run_scan
from aplomado.store import NullStore
from pinnace import LocalSandbox
from pinnace.session import SessionStore


def _tc(name, args, i):
    return {"name": name, "args": args, "id": f"call-{i}", "type": "tool_call"}


class FakeModel:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        return self.script[min(self.calls - 1, len(self.script) - 1)]


_FINISH_PAYLOAD = json.dumps({
    "target": "https://example.com",
    "summary": "One issue.",
    "findings": [{"severity": "high", "title": "test", "detail": "d", "evidence": "e"}],
})


# -- store wiring in run_scan -------------------------------------------------

def test_run_scan_calls_store_save(tmp_path):
    mock_store = MagicMock()
    env = run_scan(
        "https://example.com",
        model=FakeModel([
            AIMessage(content="", tool_calls=[_tc("finish", {"result": _FINISH_PAYLOAD}, 1)]),
        ]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        store=mock_store,
        log=lambda *a: None,
    )
    mock_store.save.assert_called_once()
    saved = mock_store.save.call_args[0][0]
    assert saved["target"] == "https://example.com"
    assert len(saved["findings"]) == 1


def test_run_scan_without_store_still_works(tmp_path):
    env = run_scan(
        "https://example.com",
        model=FakeModel([AIMessage(content="all clear")]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        store=None,
        log=lambda *a: None,
    )
    assert env["target"] == "https://example.com"
    assert env["findings"] == []


def test_run_scan_no_finish_still_calls_store(tmp_path):
    mock_store = MagicMock()
    env = run_scan(
        "https://example.com",
        model=FakeModel([AIMessage(content="nothing here")]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        store=mock_store,
        log=lambda *a: None,
    )
    mock_store.save.assert_called_once()
    saved = mock_store.save.call_args[0][0]
    assert saved["findings"] == []
    assert saved["summary"] == "nothing here"


# -- CLI flag tests ------------------------------------------------------------

def test_cli_parser_rutt_dsn_default():
    args = build_parser().parse_args(["scan", "--target", "https://example.com"])
    assert args.rutt_dsn is None


def test_cli_parser_rutt_dsn_explicit():
    args = build_parser().parse_args([
        "scan", "--target", "https://example.com",
        "--rutt-dsn", "postgresql:///mydb",
    ])
    assert args.rutt_dsn == "postgresql:///mydb"


def test_cli_parser_config_subcommand():
    args = build_parser().parse_args(["config"])
    assert args.cmd == "config"


# -- event sink wiring in run_scan ---------------------------------------------

def test_run_scan_emits_event_to_sink(tmp_path):
    mock_sink = MagicMock()
    run_scan(
        "https://example.com",
        model=FakeModel([
            AIMessage(content="", tool_calls=[_tc("finish", {"result": _FINISH_PAYLOAD}, 1)]),
        ]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        event_sink=mock_sink,
        log=lambda *a: None,
    )
    mock_sink.emit.assert_called_once()
    event = mock_sink.emit.call_args[0][0]
    assert event["type"] == "aplomado.scan.completed"
    assert event["producer"] == "aplomado"
    assert event["data"]["target"] == "https://example.com"
    assert event["data"]["ok"] is True
    assert len(event["data"]["findings"]) == 1


def test_run_scan_no_finish_emits_event_with_ok_false(tmp_path):
    mock_sink = MagicMock()
    run_scan(
        "https://example.com",
        model=FakeModel([
            AIMessage(content="", tool_calls=[_tc("shell", {"command": "echo x"}, i)])
            for i in range(5)
        ]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        event_sink=mock_sink,
        max_turns=2,
        log=lambda *a: None,
    )
    mock_sink.emit.assert_called_once()
    event = mock_sink.emit.call_args[0][0]
    assert event["data"]["ok"] is False
    assert "error" in event["data"]


def test_run_scan_without_sink_still_works(tmp_path):
    env = run_scan(
        "https://example.com",
        model=FakeModel([AIMessage(content="all clear")]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        event_sink=None,
        log=lambda *a: None,
    )
    assert env["target"] == "https://example.com"


# -- CLI event-sink flag -------------------------------------------------------

def test_cli_parser_event_sink_default():
    args = build_parser().parse_args(["scan", "--target", "https://example.com"])
    assert args.event_sink is None


def test_cli_parser_event_sink_explicit():
    args = build_parser().parse_args([
        "scan", "--target", "https://example.com",
        "--event-sink", "/tmp/events.jsonl",
    ])
    assert args.event_sink == "/tmp/events.jsonl"


def test_cli_parser_event_sink_stdout():
    args = build_parser().parse_args([
        "scan", "--target", "https://example.com",
        "--event-sink", "-",
    ])
    assert args.event_sink == "-"
