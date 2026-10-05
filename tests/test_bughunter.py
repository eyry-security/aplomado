"""Tests for the bughunter toolset (aplomado.crawl / nuclei / xss / sqli /
params / jsrecon / auth) and the bughunter-v1 prompt pack.

Everything runs against stub sandboxes — no Docker, no network, no API keys.
"""

import json

import pytest
from langchain_core.tools import BaseTool

from aplomado.auth import CookieJar, auth_tools
from aplomado.crawl import crawl_tools, hakrawler_tool, katana_tool
from aplomado.nuclei import nuclei_tool
from aplomado.params import param_discovery_tool
from aplomado.prompts import get_prompt_pack
from aplomado.sqli import sqli_tool
from aplomado.xss import dalfox_tool
from aplomado.jsrecon import js_recon_tool
from pinnace.sandbox import ExecResult


class StubSandbox:
    """Minimal in-memory Sandbox: scripted exec responses, recorded commands."""

    def __init__(self):
        self.commands = []
        self.files = {}
        self.exec_scripts = {}  # command prefix -> ExecResult

    def exec(self, cmd, timeout=120.0):
        self.commands.append(cmd)
        for prefix, result in self.exec_scripts.items():
            if cmd.startswith(prefix):
                return result
        return ExecResult("", "", 0)

    def read_file(self, path):
        return self.files[path]

    def write_file(self, path, content):
        self.files[path] = content

    def close(self):
        pass


# ---------------------------------------------------------------------------
# crawl.py


def test_katana_tool_parses_jsonl_to_urls():
    sb = StubSandbox()
    sb.exec_scripts["test -x ./katana"] = ExecResult("", "", 0)
    sb.exec_scripts["./katana"] = ExecResult(
        '{"request":{"endpoint":"https://example.com/a"}}\n'
        '{"request":{"endpoint":"https://example.com/b"}}\n'
        '{"request":{"endpoint":"https://example.com/a"}}\n',
        "",
        0,
    )
    tool = katana_tool(sb)
    assert isinstance(tool, BaseTool)
    out = tool.invoke({"url": "https://example.com", "depth": 2})
    assert "[3 unique URLs]" not in out
    assert "[2 unique URLs]" in out
    assert "https://example.com/a" in out
    assert any(c.startswith("./katana") and "-d 2" in c for c in sb.commands)


def test_katana_depth_clamped():
    sb = StubSandbox()
    sb.exec_scripts["test -x ./katana"] = ExecResult("", "", 0)
    sb.exec_scripts["./katana"] = ExecResult("", "", 0)
    tool = katana_tool(sb)
    tool.invoke({"url": "https://example.com", "depth": 99})
    assert any("-d 5" in c for c in sb.commands)


def test_katana_injects_cookies():
    sb = StubSandbox()
    sb.exec_scripts["test -x ./katana"] = ExecResult("", "", 0)
    sb.exec_scripts["./katana"] = ExecResult("", "", 0)
    jar = CookieJar()
    jar.set_cookies("session=abc123")
    tool = katana_tool(sb, jar)
    tool.invoke({"url": "https://example.com"})
    assert any("Cookie: session=abc123" in c for c in sb.commands)


def test_hakrawler_tool_merges_plain_output():
    sb = StubSandbox()
    sb.exec_scripts["test -x ./hakrawler"] = ExecResult("", "", 0)
    sb.exec_scripts["echo "] = ExecResult(
        "https://example.com/x\nhttps://example.com/y\n", "", 0
    )
    tool = hakrawler_tool(sb)
    out = tool.invoke({"url": "https://example.com"})
    assert "[2 unique URLs]" in out
    assert any("hakrawler" in c and "-depth 2" in c for c in sb.commands)


def test_crawl_tools_returns_both():
    tools = crawl_tools(StubSandbox())
    assert [t.name for t in tools] == ["katana", "hakrawler"]


# ---------------------------------------------------------------------------
# nuclei.py


def test_nuclei_uses_curated_scope():
    sb = StubSandbox()
    sb.exec_scripts["test -x ./nuclei"] = ExecResult("", "", 0)
    sb.exec_scripts["./nuclei -u"] = ExecResult(
        '{"template-id":"cve-2024-1"}\n', "", 0
    )
    tool = nuclei_tool(sb)
    out = tool.invoke({"target": "https://example.com"})
    cmd = next(c for c in sb.commands if c.startswith("./nuclei -u"))
    assert "-t cves/" in cmd
    assert "-t exposures/" in cmd
    assert "-t misconfiguration/" in cmd
    assert "-t takeovers/" in cmd
    assert "-severity critical,high" in cmd
    assert "-exclude-tags dos,fuzz" in cmd
    assert "-rate-limit 50" in cmd
    assert "[1 findings]" in out


def test_nuclei_updates_templates_on_first_use():
    sb = StubSandbox()
    sb.exec_scripts["test -x ./nuclei"] = ExecResult("", "", 1)  # missing
    sb.exec_scripts["python3 -c"] = ExecResult("", "", 0)
    sb.exec_scripts["./nuclei -update-templates"] = ExecResult("", "", 0)
    sb.exec_scripts["./nuclei -u"] = ExecResult("", "", 0)
    tool = nuclei_tool(sb)
    tool.invoke({"target": "https://example.com"})
    assert any("-update-templates" in c for c in sb.commands)


# ---------------------------------------------------------------------------
# xss.py


def test_dalfox_pipe_mode():
    sb = StubSandbox()
    sb.exec_scripts["test -x ./dalfox"] = ExecResult("", "", 0)
    sb.exec_scripts["echo "] = ExecResult(
        '{"vulnerable": true}\n', "", 0
    )
    tool = dalfox_tool(sb)
    out = tool.invoke({"url": "https://example.com/search?q=test"})
    assert "vulnerable" in out
    assert any("dalfox pipe" in c for c in sb.commands)


# ---------------------------------------------------------------------------
# sqli.py — staged escalation


def test_sqli_no_indicator_no_sqlmap():
    sb = StubSandbox()
    # Baseline + all probes return identical bodies, no error strings.
    sb.exec_scripts["curl -sk"] = ExecResult("same body", "", 0)
    tool = sqli_tool(sb)
    out = tool.invoke({"url": "https://example.com/item", "param": "id"})
    assert "no indicator" in out
    assert "sqlmap NOT run" in out
    assert not any("sqlmap.py" in c for c in sb.commands)


def test_sqli_error_indicator_escalates():
    sb = StubSandbox()

    def fake_exec(cmd, timeout=120.0):
        sb.commands.append(cmd)
        if "id='" in cmd:
            return ExecResult("You have an error in your SQL syntax", "", 0)
        if "sqlmap" in cmd and "test -x" in cmd:
            return ExecResult("", "", 0)
        if "sqlmap.py" in cmd:
            return ExecResult("sqlmap identified DBMS: MySQL", "", 0)
        return ExecResult("same body", "", 0)

    sb.exec = fake_exec
    tool = sqli_tool(sb)
    out = tool.invoke({"url": "https://example.com/item", "param": "id"})
    assert "SQL error string disclosed" in out
    assert "escalating to targeted sqlmap" in out
    assert any("sqlmap.py" in c and "-p" in c for c in sb.commands)
    # Proof limited: --banner, no --dump
    assert not any("--dump" in c for c in sb.commands)


# ---------------------------------------------------------------------------
# params.py


def test_discover_params_reports_live_ones():
    sb = StubSandbox()

    def fake_exec(cmd, timeout=120.0):
        sb.commands.append(cmd)
        if "debug=x" in cmd:
            return ExecResult("200 5000", "", 0)
        return ExecResult("200 1000", "", 0)

    sb.exec = fake_exec
    tool = param_discovery_tool(sb)
    out = tool.invoke({"url": "https://example.com/page"})
    assert "debug" in out
    assert "baseline: 200 1000 bytes" in out


def test_discover_params_baseline_failure():
    sb = StubSandbox()
    sb.exec_scripts["curl -sk"] = ExecResult("", "", 7)
    # fake a failing baseline via status 0
    sb.exec = lambda cmd, timeout=120.0: ExecResult("", "", 0) if False else ExecResult("garbage", "", 0)
    tool = param_discovery_tool(sb)
    out = tool.invoke({"url": "https://example.com/page"})
    assert "baseline" in out.lower() or "error" in out.lower()


# ---------------------------------------------------------------------------
# jsrecon.py


def test_js_recon_extracts_endpoints_and_secrets():
    sb = StubSandbox()
    page = (
        '<html><script src="/static/app.js"></script>'
        '<script src="https://cdn.example.com/lib.js"></script></html>'
    )
    js = (
        'fetch("/api/v1/users"); const k="AKIAIOSFODNN7EXAMPLE"; '
        'var ep = "/admin/panel";'
    )

    def fake_exec(cmd, timeout=120.0):
        sb.commands.append(cmd)
        if "cdn.example.com" in cmd:
            return ExecResult("", "", 0)
        if "/static/app.js" in cmd:
            return ExecResult(js, "", 0)
        return ExecResult(page, "", 0)

    sb.exec = fake_exec
    tool = js_recon_tool(sb)
    out = tool.invoke({"url": "https://example.com/"})
    assert "/api/v1/users" in out
    assert "/admin/panel" in out
    assert "aws_access_key" in out
    assert "verify a key is live" in out


# ---------------------------------------------------------------------------
# auth.py


def test_cookie_jar_status_never_echoes_secrets():
    jar = CookieJar()
    jar.set_cookies("session=supersecret123")
    jar.set_auth_header("Bearer token456")
    assert jar.configured()
    status = jar.status()
    assert "supersecret123" not in status
    assert "token456" not in status
    assert "cookies: set" in status


def test_cookie_jar_header_format():
    jar = CookieJar()
    assert jar.cookie_header() == ""
    jar.set_cookies("a=b; c=d")
    assert jar.cookie_header() == "Cookie: a=b; c=d"


def test_auth_tools_roundtrip():
    jar = CookieJar()
    tools = auth_tools(jar)
    assert [t.name for t in tools] == ["set_auth_session", "show_auth_status"]
    out = tools[0].invoke({"cookies": "s=1", "authorization": ""})
    assert "stored" in out
    assert "s=1" not in out
    status = tools[1].invoke({})
    assert "cookies: set" in status
    assert "s=1" not in status


def test_auth_tool_rejects_empty():
    jar = CookieJar()
    tools = auth_tools(jar)
    out = tools[0].invoke({"cookies": "", "authorization": ""})
    assert "error" in out


# ---------------------------------------------------------------------------
# bughunter-v1 prompt pack


def test_bughunter_pack_registered():
    pack = get_prompt_pack("bughunter-v1")
    assert pack.name == "bughunter"
    assert pack.version == 1
    assert pack.identifier == "bughunter-v1"


def test_bughunter_pack_encodes_doctrine():
    pack = get_prompt_pack("bughunter-v1")
    sp = pack.system_prompt
    assert "TREAD LIGHTLY" in sp
    assert "STAGED ESCALATION" in sp
    assert "katana" in sp
    assert "nuclei" in sp
    assert "dalfox" in sp
    assert "set_auth_session" in sp
    assert "curl" in sp.lower()


def test_bughunter_run_template_renders():
    pack = get_prompt_pack("bughunter-v1")
    rendered = pack.render("https://example.com")
    assert "https://example.com" in rendered
    assert "funnel" in rendered.lower()


def test_default_pack_still_recon_v1():
    from aplomado.prompts import DEFAULT_PROMPT_PACK_ID

    assert DEFAULT_PROMPT_PACK_ID == "recon-v1"
    pack = get_prompt_pack()
    assert pack.identifier == "recon-v1"
