"""Pipeline v2 / S2: active-hunter schema, tool belt, and token leash."""

import json

from langchain_core.messages import AIMessage

from aplomado.agent import AplomadoAgent
from aplomado.findings import Finding, normalize_findings
from aplomado.prompts import BUGHUNTER_SYSTEM_PROMPT, SYSTEM_PROMPT
from aplomado.scanner import _bughunter_tools, run_scan
from aplomado.fuzz import ffuf_tool
from pinnace import LocalSandbox
from pinnace.session import SessionStore

from test_fuzz import StubSandbox


def _tc(name, args, i):
    return {"name": name, "args": args, "id": f"call-{i}", "type": "tool_call"}


class BudgetModel:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        return self.script[min(self.calls - 1, len(self.script) - 1)]


def _usage(inp, out):
    return {"input_tokens": inp, "output_tokens": out,
            "total_tokens": inp + out}


def test_agent_toolbelt_includes_fuzz_curl_crawl_js_auth():
    sandbox = StubSandbox()
    names = {tool.name for tool in [ffuf_tool(sandbox)] + _bughunter_tools(sandbox)}
    assert {"ffuf", "curl", "katana", "hakrawler", "js_recon",
            "discover_params", "nuclei", "dalfox", "sqli",
            "set_auth_session", "show_auth_status"} <= names


def test_finding_schema_coerces_and_drops_malformed():
    env = normalize_findings({"findings": [
        {"title": "SQLi in id", "severity": "HIGH", "vuln_class": "SQL injection",
         "repro": "1. inject\n2. observe", "evidence": "500"},
        {"severity": "high"},  # no title -> dropped
        42,                    # not a finding -> dropped
    ]}, "https://a.example")
    assert len(env["findings"]) == 1
    assert env["findings_dropped"] == 2
    f = env["findings"][0]
    assert isinstance(Finding.model_validate(f), Finding)
    assert f["severity"] == "high"
    assert f["vuln_class"] == "sqli"
    assert f["repro"] == ["1. inject", "2. observe"]


def test_prompts_use_active_hunting_posture():
    for prompt in (SYSTEM_PROMPT, BUGHUNTER_SYSTEM_PROMPT):
        text = prompt.lower()
        assert "fuzz every input" in text
        assert "decompile" in text
        assert "sourcemap" in text
        assert "vuln_class" in text


def test_token_budget_wraps_up_and_keeps_partial_findings(tmp_path):
    payload = json.dumps({"summary": "partial", "findings": [
        {"title": "Verified SQLi", "severity": "high", "vuln_class": "sqli",
         "evidence": "HTTP 500"}]})
    model = BudgetModel([
        AIMessage(content="", usage_metadata=_usage(600_000, 100_000),
                  tool_calls=[_tc("shell", {"command": "echo still-running"}, 1)]),
        AIMessage(content="", usage_metadata=_usage(1_000, 20_000),
                  tool_calls=[_tc("finish", {"result": payload}, 2)]),
    ])
    logs = []
    env = run_scan(
        "https://a.example", model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        token_budget=500_000, log=logs.append,
    )
    assert env["findings"][0]["title"] == "Verified SQLi"
    assert env["token_budget"]["exhausted"] is True
    assert env["token_budget"]["used"] >= 500_000
    assert any("token budget reached" in line for line in logs)
    assert AplomadoAgent is not None
