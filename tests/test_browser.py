"""Tests for the authenticated screenshot and DevTools-MCP browser tools."""

import json

from langchain_core.messages import AIMessage

from aplomado.auth import COOKIE_JAR_PATH, CookieJar, format_cookie_jar
from aplomado.browser import (
    BROWSER_TIMEOUT_SECONDS,
    DEVTOOLS_TOOL_NAMES,
    BrowserSession,
    browser_auth_tool,
    browser_tools,
    capture_screenshot,
    is_login_url,
    screenshot_path,
    screenshot_tool,
)
from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.sandbox import ExecResult


class StubSandbox:
    def __init__(self):
        self.files = {}
        self.commands = []

    def exec(self, cmd, timeout=120.0):
        self.commands.append((cmd, timeout))
        return ExecResult("", "", 0)

    def read_file(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write_file(self, path, content):
        self.files[path] = content

    def close(self):
        pass


def _netscape_cookie(**overrides):
    cookie = {
        "name": "session",
        "value": "abc123",
        "domain": "example.com",
        "path": "/",
        "secure": True,
        "http_only": True,
        "expires": 0,
    }
    cookie.update(overrides)
    return format_cookie_jar([cookie])


def test_screenshot_sets_jar_cookies_before_navigation():
    sandbox = StubSandbox()
    sandbox.files[COOKIE_JAR_PATH] = _netscape_cookie()
    seen = {}

    def runner(payload, timeout):
        seen.update(payload)
        return {
            "ok": True,
            "path": payload["output_path"],
            "title": "Dashboard",
            "final_url": "https://example.com/app",
            "cookies": [
                {
                    "name": "session",
                    "value": "rotated",
                    "domain": "example.com",
                    "path": "/",
                }
            ],
        }

    jar = CookieJar(sandbox)
    result = screenshot_tool(sandbox, jar, runner=runner).invoke(
        {"url": "https://example.com/app"}
    )

    assert seen["action"] == "screenshot"
    assert seen["url"] == "https://example.com/app"
    assert seen["full_page"] is True
    assert seen["output_path"].startswith("scratch/shots/")
    # The jar's cookie is in the payload before the page is loaded.
    assert any(c["name"] == "session" and c["value"] == "abc123" for c in seen["cookies"])
    assert "screenshot: scratch/shots/" in result
    assert "title: Dashboard" in result
    assert "final_url: https://example.com/app" in result
    # Browser-side rotation lands back in the canonical jar.
    saved = sandbox.files[COOKIE_JAR_PATH]
    assert "rotated" in saved
    assert "abc123" not in result
    assert "rotated" not in result


def test_screenshot_reports_login_redirect_plainly():
    sandbox = StubSandbox()

    def runner(payload, timeout):
        return {
            "ok": True,
            "path": payload["output_path"],
            "title": "Sign in",
            "final_url": "https://example.com/login?next=/app",
        }

    result = screenshot_tool(sandbox, runner=runner).invoke(
        {"url": "https://example.com/app", "full_page": False}
    )
    assert "auth likely expired" in result
    assert "login" in result
    assert is_login_url("https://example.com/login", "", "Sign in")
    assert not is_login_url("https://example.com/logout", "", "Signed out")
    assert not is_login_url("https://example.com/authors", "", "Authors")


def test_capture_screenshot_full_page_flag_and_stable_path():
    sandbox = StubSandbox()
    seen = {}

    def runner(payload, timeout):
        seen.update(payload)
        return {
            "ok": True,
            "path": payload["output_path"],
            "title": "T",
            "final_url": payload["url"],
        }

    result = capture_screenshot(
        sandbox, "https://example.com/x", full_page=False, runner=runner
    )
    assert seen["full_page"] is False
    assert result["path"] == screenshot_path("https://example.com/x", False)
    assert result["path"].startswith("scratch/shots/")


def test_browser_auth_loads_canonical_jar():
    sandbox = StubSandbox()
    sandbox.files[COOKIE_JAR_PATH] = _netscape_cookie(name="sid", value="xyz")
    seen = {}

    def runner(payload, timeout):
        seen.update(payload)
        return {"ok": True, "cookies": []}

    out = browser_auth_tool(sandbox, runner=runner).invoke(
        {"url": "https://example.com/private"}
    )
    assert seen["action"] == "auth"
    assert seen["cookies"][0]["name"] == "sid"
    assert seen["cookies"][0]["value"] == "xyz"
    assert "loaded 1 cookie" in out
    assert "xyz" not in out


def test_browser_tools_expose_devtools_surface_and_auth():
    sandbox = StubSandbox()
    tools = browser_tools(sandbox)
    names = [tool.name for tool in tools]
    assert names[0] == "browser_auth"
    for expected in DEVTOOLS_TOOL_NAMES:
        assert expected in names
    navigate = next(tool for tool in tools if tool.name == "navigate_page")
    assert "timeout_seconds" in navigate.args
    assert navigate.args["timeout_seconds"]["default"] == BROWSER_TIMEOUT_SECONDS


def test_browser_action_timeout_is_clamped():
    sandbox = StubSandbox()
    seen = {}

    def runner(payload, timeout):
        seen["payload"] = payload
        seen["timeout"] = timeout
        return {"ok": True, "result": {"content": [{"type": "text", "text": "ok"}]}}

    session = BrowserSession(sandbox, runner=runner)
    assert session.call("list_pages", {}, timeout_seconds=99_999) == "ok"
    assert seen["timeout"] == 1200.0
    assert seen["payload"]["timeout_ms"] == 1_200_000


def test_browser_action_rejects_nonpositive_timeout():
    sandbox = StubSandbox()
    tool = next(
        t for t in browser_tools(sandbox, runner=lambda payload, timeout: {"ok": True})
        if t.name == "list_pages"
    )
    out = tool.invoke({"timeout_seconds": 0})
    assert out.startswith("error:")
    assert "positive" in out


def test_run_scan_registers_browser_tools(tmp_path):
    class RecordingModel:
        def __init__(self):
            self.bound = []
            self.calls = 0

        def bind_tools(self, tools):
            self.bound = list(tools)
            return self

        def invoke(self, messages):
            self.calls += 1
            return AIMessage(content="done")

    model = RecordingModel()
    run_scan(
        "https://example.com",
        model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        log=lambda *a: None,
    )
    names = {tool.name for tool in model.bound}
    assert "screenshot" in names
    assert "browser_auth" in names
    assert set(DEVTOOLS_TOOL_NAMES) <= names


def test_mcp_browser_payload_passes_tool_and_arguments():
    sandbox = StubSandbox()
    seen = {}

    def runner(payload, timeout):
        seen.update(payload)
        return {
            "ok": True,
            "result": {"content": [{"type": "text", "text": "console line"}]},
        }

    session = BrowserSession(sandbox, runner=runner)
    out = session.call(
        "evaluate_script",
        {"function": "() => document.title"},
        timeout_seconds=30,
    )
    assert out == "console line"
    assert seen["action"] == "mcp"
    assert seen["tool"] == "evaluate_script"
    assert seen["arguments"] == {"function": "() => document.title"}
    assert seen["timeout_ms"] == 30_000


def test_navigate_page_auto_auths_with_jar():
    sandbox = StubSandbox()
    sandbox.files[COOKIE_JAR_PATH] = _netscape_cookie(name="sid", value="secret")
    seen = {}

    def runner(payload, timeout):
        seen.update(payload)
        return {"ok": True, "result": {"content": []}}

    tools = browser_tools(sandbox, runner=runner)
    navigate = next(tool for tool in tools if tool.name == "navigate_page")
    navigate.invoke({"url": "https://example.com/app"})
    assert seen["url"] == "https://example.com/app"
    assert any(c["name"] == "sid" for c in seen["cookies"])


def test_jar_file_round_trips_through_browser(tmp_path):
    sandbox = StubSandbox()
    sandbox.files[COOKIE_JAR_PATH] = _netscape_cookie(
        name="token", value="one", domain=".example.com"
    )
    jar = CookieJar(sandbox)
    assert any(c["name"] == "token" for c in jar.browser_cookies("https://app.example.com/"))
    assert jar.browser_cookies("https://other.test/") == []
    jar.save_browser_cookies(
        [
            {
                "name": "token",
                "value": "two",
                "domain": ".example.com",
                "path": "/",
            }
        ]
    )
    assert "two" in sandbox.files[COOKIE_JAR_PATH]
    assert "Netscape HTTP Cookie File" in sandbox.files[COOKIE_JAR_PATH]


def test_mcp_server_registration_config():
    from aplomado.mcp import (
        CHROME_DEVTOOLS_MCP_SERVER,
        chrome_devtools_mcp_config,
        mcp_server_registry,
    )

    config = chrome_devtools_mcp_config(browser_url="http://127.0.0.1:9222")
    assert config["name"] == CHROME_DEVTOOLS_MCP_SERVER
    assert config["command"] == "chrome-devtools-mcp"
    assert "--headless" in config["args"]
    assert "--browserUrl" in config["args"]
    assert "http://127.0.0.1:9222" in config["args"]
    registry = mcp_server_registry()
    assert registry[CHROME_DEVTOOLS_MCP_SERVER]["command"] == "chrome-devtools-mcp"
    assert "--headless" in registry[CHROME_DEVTOOLS_MCP_SERVER]["args"]


def test_prompt_packs_steer_browser_use_and_evidence():
    from aplomado.prompts import get_prompt_pack

    for pack_id in ("recon-v1", "bughunter-v1"):
        prompt = get_prompt_pack(pack_id).system_prompt
        assert "screenshot(" in prompt
        assert "browser_auth(" in prompt
        assert "navigate_page" in prompt
        assert "evaluate_script" in prompt
        assert "BROWSER PURPOSE" in prompt
        assert "not a replacement" in prompt
        assert "buffer rule" in prompt
