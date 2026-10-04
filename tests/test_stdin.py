"""Tests for stdin ingestion, deterministic finding IDs, and parse_stdin_record.

No API keys, no Docker, no Postgres.
"""

from __future__ import annotations

import io
import json
import sys
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from aplomado.cli import build_parser, _resolve_targets
from aplomado.findings import finding_id, normalize_findings
from aplomado.scanner import AplomadoError, parse_stdin_record, run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore


# --------------------------------------------------------------------------- #
# Deterministic finding IDs
# --------------------------------------------------------------------------- #

def test_finding_id_deterministic():
    """Same inputs always produce the same ID."""
    id1 = finding_id("https://example.com", "Exposed .git", "HTTP 200")
    id2 = finding_id("https://example.com", "Exposed .git", "HTTP 200")
    assert id1 == id2
    assert len(id1) == 64  # sha256 hex


def test_finding_id_differs_by_target():
    """Same title+evidence, different target → different IDs."""
    id_a = finding_id("https://a.example", "Exposed .git", "HTTP 200")
    id_b = finding_id("https://b.example", "Exposed .git", "HTTP 200")
    assert id_a != id_b


def test_finding_id_differs_by_title():
    id_a = finding_id("https://example.com", "Exposed .git", "HTTP 200")
    id_b = finding_id("https://example.com", "Missing HSTS", "HTTP 200")
    assert id_a != id_b


def test_finding_id_differs_by_evidence():
    id_a = finding_id("https://example.com", "Exposed .git", "HTTP 200")
    id_b = finding_id("https://example.com", "Exposed .git", "HTTP 403")
    assert id_a != id_b


def test_finding_id_empty_fields():
    """Empty strings are valid — the ID is still deterministic."""
    id1 = finding_id("", "", "")
    id2 = finding_id("", "", "")
    assert id1 == id2
    assert len(id1) == 64


def test_normalize_findings_stamps_ids():
    """normalize_findings adds a deterministic 'id' to each finding."""
    env = normalize_findings(
        {
            "findings": [
                {"severity": "high", "title": "A", "evidence": "e1"},
                {"severity": "low", "title": "B", "evidence": "e2"},
            ]
        },
        "example.com",
    )
    for f in env["findings"]:
        assert "id" in f
        assert len(f["id"]) == 64

    # IDs should be different for different findings
    assert env["findings"][0]["id"] != env["findings"][1]["id"]


def test_normalize_findings_ids_match_finding_id():
    """The IDs stamped by normalize_findings match what finding_id() produces."""
    env = normalize_findings(
        {"findings": [{"severity": "high", "title": "test", "evidence": "ev"}]},
        "example.com",
    )
    expected = finding_id("example.com", "test", "ev")
    assert env["findings"][0]["id"] == expected


def test_rescan_produces_same_ids():
    """Re-scanning the same target with the same findings → same IDs (dedup)."""
    payload = {
        "findings": [
            {"severity": "high", "title": "Exposed .git", "evidence": "HTTP 200 on /.git/HEAD"},
        ]
    }
    env1 = normalize_findings(payload, "example.com")
    env2 = normalize_findings(payload, "example.com")
    assert env1["findings"][0]["id"] == env2["findings"][0]["id"]


# --------------------------------------------------------------------------- #
# parse_stdin_record
# --------------------------------------------------------------------------- #

def test_parse_vedette_jsonl():
    record = json.dumps({
        "input": "www.eyry.io", "ok": True,
        "url": "https://www.eyry.io/", "host": "www.eyry.io",
        "status": 200, "server": "Vercel",
    })
    target, context = parse_stdin_record(record)
    assert target == "https://www.eyry.io/"
    assert context is not None
    assert "Vedette prober record" in context
    assert "Vercel" in context


def test_parse_bare_hostname():
    target, context = parse_stdin_record("example.com")
    assert target == "example.com"
    assert context is None


def test_parse_bare_url():
    target, context = parse_stdin_record("https://example.com/path")
    assert target == "https://example.com/path"
    assert context is None


def test_parse_jsonl_prefers_url_over_host():
    record = json.dumps({"url": "https://a.example/", "host": "a.example"})
    target, _ = parse_stdin_record(record)
    assert target == "https://a.example/"


def test_parse_jsonl_falls_back_to_host():
    record = json.dumps({"host": "bare.example"})
    target, _ = parse_stdin_record(record)
    assert target == "bare.example"


def test_parse_jsonl_falls_back_to_input():
    record = json.dumps({"input": "from-input.example"})
    target, _ = parse_stdin_record(record)
    assert target == "from-input.example"


def test_parse_empty_line_raises():
    with pytest.raises(AplomadoError, match="empty"):
        parse_stdin_record("")
    with pytest.raises(AplomadoError, match="empty"):
        parse_stdin_record("   ")


def test_parse_bad_json_raises():
    with pytest.raises(AplomadoError, match="invalid JSON"):
        parse_stdin_record("{bad json")


def test_parse_json_no_target_fields_raises():
    with pytest.raises(AplomadoError, match="no url, host, or input"):
        parse_stdin_record('{"status": 200}')


def test_parse_json_non_object_raises():
    with pytest.raises(AplomadoError, match="no url, host, or input"):
        parse_stdin_record('{"status": 200, "extra": true}')
    with pytest.raises(AplomadoError, match="expected a JSON object"):
        parse_stdin_record("[1, 2, 3]")


# --------------------------------------------------------------------------- #
# CLI: stdin ingestion via _resolve_targets
# --------------------------------------------------------------------------- #

def _make_args(**overrides):
    """Build a minimal args namespace matching build_parser() output."""
    defaults = {
        "target": None, "target_file": None, "scan_all": False,
        "model": None, "sandbox": "local", "unsafe_ok": True,
        "image": "python:3.12-slim", "no_net": False,
        "workdir": "./aplomado-work", "max_turns": 30,
        "session": None, "json": False, "rutt_dsn": None,
        "event_sink": None, "cmd": "scan",
    }
    defaults.update(overrides)
    import argparse
    return argparse.Namespace(**defaults)


def test_resolve_targets_explicit_target():
    args = _make_args(target="https://example.com")
    targets = _resolve_targets(args)
    assert targets == [("https://example.com", None)]


def test_resolve_targets_stdin_all_records_by_default():
    """Stdin scans every valid record without an opt-in flag."""
    lines = [
        json.dumps({"url": "https://first.example/", "status": 200}),
        json.dumps({"url": "https://second.example/", "status": 200}),
    ]
    args = _make_args(scan_all=False)
    with patch("sys.stdin", io.StringIO("\n".join(lines) + "\n")):
        with patch("sys.stdin.isatty", return_value=False):
            targets = _resolve_targets(args)
    assert len(targets) == 2
    assert [target for target, _ in targets] == [
        "https://first.example/", "https://second.example/"
    ]


def test_resolve_targets_stdin_all_records():
    """--all mode: every valid record is returned."""
    lines = [
        json.dumps({"url": "https://first.example/"}),
        json.dumps({"url": "https://second.example/"}),
        json.dumps({"url": "https://third.example/"}),
    ]
    args = _make_args(scan_all=True)
    with patch("sys.stdin", io.StringIO("\n".join(lines) + "\n")):
        with patch("sys.stdin.isatty", return_value=False):
            targets = _resolve_targets(args)
    assert len(targets) == 3
    assert [t for t, _ in targets] == [
        "https://first.example/",
        "https://second.example/",
        "https://third.example/",
    ]


def test_resolve_targets_stdin_skips_blank_and_bad_lines():
    lines = [
        "",
        "{bad json",
        json.dumps({"url": "https://good.example/"}),
        '{"status": 200}',  # no target fields
    ]
    args = _make_args(scan_all=True)
    with patch("sys.stdin", io.StringIO("\n".join(lines) + "\n")):
        with patch("sys.stdin.isatty", return_value=False):
            targets = _resolve_targets(args)
    assert len(targets) == 1
    assert targets[0][0] == "https://good.example/"


def test_resolve_targets_stdin_bare_hostnames():
    lines = ["example.com", "other.example"]
    args = _make_args(scan_all=True)
    with patch("sys.stdin", io.StringIO("\n".join(lines) + "\n")):
        with patch("sys.stdin.isatty", return_value=False):
            targets = _resolve_targets(args)
    assert len(targets) == 2
    assert targets[0] == ("example.com", None)
    assert targets[1] == ("other.example", None)


def test_resolve_targets_tty_raises():
    args = _make_args()
    with patch("sys.stdin") as mock_stdin:
        mock_stdin.isatty.return_value = True
        with pytest.raises(AplomadoError, match="no target given"):
            _resolve_targets(args)


def test_resolve_targets_empty_stdin_raises():
    args = _make_args(scan_all=True)
    with patch("sys.stdin", io.StringIO("")):
        with patch("sys.stdin.isatty", return_value=False):
            with pytest.raises(AplomadoError, match="no targets found"):
                _resolve_targets(args)


# --------------------------------------------------------------------------- #
# CLI parser: new flags
# --------------------------------------------------------------------------- #

def test_cli_parser_target_is_optional():
    """--target is no longer required; scan without it should parse."""
    args = build_parser().parse_args(["scan"])
    assert args.target is None
    assert args.scan_all is False


def test_cli_parser_all_flag_is_compatibility_noop():
    args = build_parser().parse_args(["scan", "--all"])
    assert args.scan_all is True


def test_cli_parser_target_still_works():
    args = build_parser().parse_args(["scan", "--target", "https://example.com"])
    assert args.target == "https://example.com"


# --------------------------------------------------------------------------- #
# Integration: run_scan with deterministic IDs in findings
# --------------------------------------------------------------------------- #

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


def test_run_scan_findings_have_deterministic_ids(tmp_path):
    payload = json.dumps({
        "target": "https://example.com",
        "summary": "Issues found.",
        "findings": [
            {"severity": "high", "title": "Exposed .git", "detail": "d", "evidence": "HTTP 200"},
            {"severity": "low", "title": "Missing HSTS", "detail": "d2", "evidence": "no header"},
        ],
    })
    env = run_scan(
        "https://example.com",
        model=FakeModel([
            AIMessage(content="", tool_calls=[_tc("finish", {"result": payload}, 1)]),
        ]),
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        log=lambda *a: None,
    )
    # Every finding has an ID
    for f in env["findings"]:
        assert "id" in f
        assert len(f["id"]) == 64

    # IDs match what finding_id() would produce
    f0 = env["findings"][0]
    assert f0["id"] == finding_id("https://example.com", f0["title"], f0["evidence"])

    # Two different findings have different IDs
    assert env["findings"][0]["id"] != env["findings"][1]["id"]


def test_run_scan_same_findings_same_ids_across_runs(tmp_path):
    """Two scans returning the same findings for the same target → same IDs."""
    payload = json.dumps({
        "findings": [{"severity": "high", "title": "test", "evidence": "ev"}],
    })
    script = [AIMessage(content="", tool_calls=[_tc("finish", {"result": payload}, 1)])]

    env1 = run_scan(
        "https://example.com",
        model=FakeModel(script),
        sandbox=LocalSandbox(str(tmp_path / "w1"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "s1"),
        log=lambda *a: None,
    )
    env2 = run_scan(
        "https://example.com",
        model=FakeModel(script),
        sandbox=LocalSandbox(str(tmp_path / "w2"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "s2"),
        log=lambda *a: None,
    )
    assert env1["findings"][0]["id"] == env2["findings"][0]["id"]


# --------------------------------------------------------------------------- #
# CLI streaming and stdout ownership
# --------------------------------------------------------------------------- #

def test_finding_id_uses_unambiguous_canonical_components():
    # These tuples collide under naive delimiter joining but not canonical JSON.
    assert finding_id("a\0b", "c", "d") != finding_id("a", "b\0c", "d")
    assert finding_id("täst.example", "Ünicode", "é") == finding_id(
        "täst.example", "Ünicode", "é"
    )


def test_normalize_overwrites_model_id_and_uses_caller_target():
    payload = {
        "target": "model.example",
        "findings": [{"id": "model-controlled", "title": "check", "evidence": "proof"}],
    }
    env = normalize_findings(payload, "caller.example")
    assert env["target"] == "caller.example"
    assert env["findings"][0]["id"] == finding_id(
        "caller.example", "check", "proof"
    )


def test_cmd_scan_streams_every_record_and_stdout_is_events_only(monkeypatch, capsys):
    from aplomado import cli
    from aplomado.events import build_event

    records = "\n".join([
        json.dumps({"url": "https://one.example/", "status": 200}),
        json.dumps({"url": "https://two.example/", "status": 201}),
    ]) + "\n"
    sandboxes = []
    calls = []

    class FakeResource:
        def __init__(self):
            self.closed = False
        def close(self):
            self.closed = True

    def make_sandbox(args):
        resource = FakeResource()
        sandboxes.append(resource)
        return resource

    def run_one(target, context, args, sandbox, store, sink, session_id=None):
        calls.append((target, context, session_id))
        envelope = normalize_findings(
            {"summary": "done", "findings": [{"title": "check", "evidence": target}]},
            target,
        )
        sink.emit(build_event(envelope))
        return envelope

    monkeypatch.setattr(cli, "_make_sandbox", make_sandbox)
    monkeypatch.setattr(cli, "_run_one", run_one)
    monkeypatch.setattr(sys, "stdin", io.StringIO(records))
    args = build_parser().parse_args([
        "scan", "--event-sink", "-", "--json", "--session", "batch",
    ])
    assert cli.cmd_scan(args) == 0
    output = capsys.readouterr().out.splitlines()
    assert len(output) == 2
    events = [json.loads(line) for line in output]
    assert all(event["type"] == "aplomado.scan.completed" for event in events)
    assert [event["data"]["target"] for event in events] == [
        "https://one.example/", "https://two.example/",
    ]
    assert [call[2] for call in calls] == ["batch-1", "batch-2"]
    assert len(sandboxes) == 2 and all(item.closed for item in sandboxes)


def test_cmd_scan_continues_after_record_failure(monkeypatch, capsys):
    from aplomado import cli
    from aplomado.events import build_event

    monkeypatch.setattr(sys, "stdin", io.StringIO("one.example\ntwo.example\n"))
    monkeypatch.setattr(cli, "_make_sandbox", lambda args: MagicMock())
    seen = []

    def run_one(target, context, args, sandbox, store, sink, session_id=None):
        seen.append(target)
        if target == "one.example":
            raise RuntimeError("provider failed")
        envelope = normalize_findings({"summary": "done", "findings": []}, target)
        sink.emit(build_event(envelope))
        return envelope

    monkeypatch.setattr(cli, "_run_one", run_one)
    args = build_parser().parse_args(["scan", "--event-sink", "-"])
    assert cli.cmd_scan(args) == 1
    assert seen == ["one.example", "two.example"]
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(events) == 2
    assert events[0]["data"]["ok"] is False
    assert events[0]["data"]["error"] == "provider failed"
    assert events[1]["data"]["target"] == "two.example"


def test_identical_findings_keep_id_but_events_remain_unique():
    from aplomado.events import build_event

    envelope = normalize_findings(
        {"findings": [{"title": "check", "evidence": "proof"}]}, "example.com"
    )
    first = build_event(envelope)
    second = build_event(envelope)
    assert first["data"]["findings"][0]["id"] == second["data"]["findings"][0]["id"]
    assert first["id"] != second["id"]
