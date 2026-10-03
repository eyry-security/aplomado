"""End-to-end scan with a scripted fake model — no API keys, no Docker.

The fake model replays AIMessages: first a shell call (proving the agent runs
tools against LocalSandbox), then finish() with findings JSON.
"""

import json

import pytest
from langchain_core.messages import AIMessage

from aplomado.cli import build_parser
from aplomado.findings import SEVERITIES
from aplomado.scanner import AplomadoError, build_prompt, load_target_file, run_scan
from pinnace import LocalSandbox
from pinnace.sandbox import SandboxError
from pinnace.session import SessionStore


def _tc(name, args, i):
    return {"name": name, "args": args, "id": f"call-{i}", "type": "tool_call"}


class FakeModel:
    """Replays a script of AIMessages, one per invoke."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        return self.script[min(self.calls - 1, len(self.script) - 1)]


_FINISH_PAYLOAD = json.dumps(
    {
        "target": "https://example.com",
        "summary": "One issue worth fixing.",
        "findings": [
            {
                "severity": "HIGH",  # gets coerced down to "high"
                "title": "Server header leaks version",
                "detail": "nginx/1.25.3 exposed in Server",
                "evidence": "Server: nginx/1.25.3",
            }
        ],
    }
)


def _scripted_agent(tmp_path, script, **kw):
    kw.setdefault("sandbox", LocalSandbox(str(tmp_path / "work"), unsafe_ok=True))
    kw.setdefault("session_store", SessionStore(tmp_path / "sessions"))
    kw.setdefault("log", lambda *a: None)
    kw.setdefault("model", FakeModel(script))
    return run_scan("https://example.com", **kw)


def test_scan_shell_then_finish(tmp_path):
    env = _scripted_agent(
        tmp_path,
        [
            AIMessage(content="", tool_calls=[_tc("shell", {"command": "echo recon-ok"}, 1)]),
            AIMessage(content="", tool_calls=[_tc("finish", {"result": _FINISH_PAYLOAD}, 2)]),
        ],
    )
    assert env["target"] == "https://example.com"
    assert env["summary"] == "One issue worth fixing."
    (f,) = env["findings"]
    assert f["severity"] == "high"  # coerced
    assert f["title"] == "Server header leaks version"
    assert f["evidence"] == "Server: nginx/1.25.3"


def test_scan_without_finish_keeps_final_text(tmp_path):
    env = _scripted_agent(
        tmp_path, [AIMessage(content="nothing interesting here")]
    )
    assert env["target"] == "https://example.com"
    assert env["summary"] == "nothing interesting here"
    assert env["findings"] == []
    assert env["scanned_at"]


def test_scan_garbage_finish_payload_does_not_crash(tmp_path):
    env = _scripted_agent(
        tmp_path,
        [AIMessage(content="", tool_calls=[_tc("finish", {"result": "not json at all"}, 1)])],
    )
    assert env["findings"] == []
    assert env["summary"] == "not json at all"


def test_scan_weird_severity_in_finish_is_coerced(tmp_path):
    payload = json.dumps({"findings": [{"severity": "eh?", "title": "t"}]})
    env = _scripted_agent(
        tmp_path,
        [AIMessage(content="", tool_calls=[_tc("finish", {"result": payload}, 1)])],
    )
    assert env["findings"][0]["severity"] == "info"


def test_scan_uses_prober_context_in_prompt(tmp_path):
    seen = {}

    class SpyModel(FakeModel):
        def invoke(self, messages):
            seen["prompt"] = messages[-1].content
            return super().invoke(messages)

    _scripted_agent(
        tmp_path,
        [AIMessage(content="done")],
        model=SpyModel([AIMessage(content="done")]),
        target_context="Target context (one Vedette prober record):\n{...}",
    )
    assert "TARGET: https://example.com" in seen["prompt"]
    assert "Vedette prober record" in seen["prompt"]


def test_max_turns_limits_scan(tmp_path):
    script = [
        AIMessage(content="", tool_calls=[_tc("shell", {"command": "echo x"}, i)])
        for i in range(10)
    ]
    env = _scripted_agent(tmp_path, script, max_turns=2)
    assert env["summary"] == "scan ended without calling finish()"


def test_load_target_file_first_record(tmp_path):
    p = tmp_path / "vedette.jsonl"
    p.write_text(
        json.dumps(
            {
                "input": "www.eyry.io",
                "ok": True,
                "url": "https://www.eyry.io/",
                "host": "www.eyry.io",
                "status": 200,
                "server": "Vercel",
            }
        )
        + "\n"
        + json.dumps({"input": "other.example", "ok": False})
        + "\n"
    )
    label, context = load_target_file(str(p))
    assert label == "https://www.eyry.io/"
    assert "Vercel" in context
    assert "other.example" not in context  # first record only


def test_load_target_file_label_fallbacks(tmp_path):
    p = tmp_path / "v.jsonl"
    p.write_text('{"host": "bare.example"}\n')
    label, _ = load_target_file(str(p))
    assert label == "bare.example"


def test_load_target_file_errors(tmp_path):
    with pytest.raises(AplomadoError):
        load_target_file(str(tmp_path / "missing.jsonl"))
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\n")
    with pytest.raises(AplomadoError):
        load_target_file(str(empty))
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n")
    with pytest.raises(AplomadoError):
        load_target_file(str(bad))


def test_build_prompt():
    prompt = build_prompt("https://example.com")
    assert "TARGET: https://example.com" in prompt
    assert "finish()" in prompt
    prompt = build_prompt("https://example.com", "CTX")
    assert "CTX" in prompt


def test_local_sandbox_requires_unsafe_ok():
    with pytest.raises(SandboxError):
        LocalSandbox("/tmp/x")


def test_cli_parser_defaults():
    args = build_parser().parse_args(["scan", "--target", "https://example.com"])
    assert args.target == "https://example.com"
    assert args.sandbox == "docker"
    assert args.image == "python:3.12-slim"
    assert args.max_turns == 30
    assert args.model is None
    assert args.json is False
    assert args.unsafe_ok is False


def test_cli_parser_all_flags():
    args = build_parser().parse_args(
        [
            "scan", "--target", "https://example.com",
            "--target-file", "vedette.jsonl",
            "--model", "anthropic:claude-sonnet-4-5",
            "--sandbox", "local", "--unsafe-ok",
            "--max-turns", "10", "--session", "s1", "--json",
        ]
    )
    assert args.target_file == "vedette.jsonl"
    assert args.model == "anthropic:claude-sonnet-4-5"
    assert args.sandbox == "local"
    assert args.unsafe_ok is True
    assert args.max_turns == 10
    assert args.session == "s1"
    assert args.json is True


def test_all_finding_severities_valid(tmp_path):
    env = _scripted_agent(
        tmp_path,
        [AIMessage(content="", tool_calls=[_tc("finish", {"result": _FINISH_PAYLOAD}, 1)])],
    )
    assert all(f["severity"] in SEVERITIES for f in env["findings"])
