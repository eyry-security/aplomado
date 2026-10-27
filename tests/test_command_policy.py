"""Tests for Aplomado's command execution safety; no container or network needed."""

import json

import pytest
from langchain_core.messages import AIMessage, ToolMessage

from aplomado.command_policy import (
    COMMAND_MAX_BYTES,
    COMMAND_TIMEOUT_SECONDS,
    DEFAULT_SHELL_TIMEOUT_SECONDS,
    MAX_SHELL_TIMEOUT_SECONDS,
    CommandPolicyError,
    CommandPolicySandbox,
    harden_commands,
    resolve_shell_timeout,
    shell_tool,
    validate_command,
)
from aplomado.scanner import run_scan
from aplomado.write_policy import WritePolicySandbox
from pinnace import (
    DockerSandbox,
    ExecResult,
    LocalSandbox,
    PinnaceError,
    Sandbox,
    SandboxError,
)
from pinnace.session import SessionStore


@pytest.mark.parametrize(
    "command",
    [
        # The documented recon commands from before the allowlist was removed.
        "curl -sSI https://example.com",
        "curl -H 'From: scanner@example.com' https://example.com",
        "curl -HX-Auth:abc https://example.com",
        "curl -dname=value https://example.com",
        "curl -AChrome https://example.com",
        "curl -s https://example.com | grep -i server | head -1",
        "dig +short A example.com",
        "openssl s_client -connect example.com:443",
        "command -v curl",
        "printf '%s\\n' recon-ok",
        # Binaries that used to be outside the allowlist.
        "pwd",
        "mkdir -p scratch/out && cp scratch/a scratch/out/a",
        "cd scratch && pwd",
        "rm -rf ./scratch/out",
        "sudo reboot",
        "bash -c 'echo bypass'",
        "/bin/curl https://example.com",
        "env curl https://example.com",
        "find . -exec rm {} ;",
        # Shell composition, redirects, subshells, and substitution.
        "echo ok; rm -rf /",
        "echo ok && rm -rf /",
        "echo ok || rm -rf /",
        "echo ok > output.txt",
        "cat < input.txt >> output.txt",
        "echo $(uname)",
        "echo `uname`",
        "(cd scratch && ls -la)",
        "echo ok\nrm -rf /",
        "curl https://example.com &",
        # curl options that used to be blocked, including the cookie-jar flow.
        "curl -o result.txt https://example.com",
        "curl --output=result.txt https://example.com",
        "curl -O https://example.com/file",
        "curl -so result.txt https://example.com",
        "curl --config settings https://example.com",
        "curl file:///etc/passwd",
        "curl --url=file:///etc/passwd",
        "curl --data-binary @secret.txt https://example.com",
        "curl --data=@secret.txt https://example.com",
        "curl -F artifact=@secret.txt https://example.com",
        "curl --form=artifact=@secret.txt https://example.com",
        "curl -H @headers.txt https://example.com",
        "curl --header=@headers.txt https://example.com",
        "curl -sH @headers.txt https://example.com",
        "curl -c cookies.txt -b cookies.txt https://example.com",
        "curl --cookie-jar cookies.txt --cookie cookies.txt https://example.com",
        "curl -D headers.txt https://example.com",
        "curl --dump-header headers.txt https://example.com",
        # Per-command special cases that only policed the allowlist.
        "openssl genpkey -algorithm RSA",
        "openssl x509 -in cert.pem -out copied.pem",
        "openssl s_client -connect example.com:443 -keylogfile keys.txt",
        "command curl",
        "command -v ../../bin/sh",
        "date --set=tomorrow",
        "date -s tomorrow",
        "sort -o changed.txt input.txt",
        "sort --compress-program=/bin/sh input.txt",
    ],
)
def test_accepts_full_shell_commands(command):
    validate_command(command)


def test_rejects_only_empty_and_oversize_commands():
    for command in ["", "   "]:
        with pytest.raises(CommandPolicyError):
            validate_command(command)
    with pytest.raises(CommandPolicyError, match="limit"):
        validate_command("echo " + "x" * COMMAND_MAX_BYTES)
    validate_command("echo " + "x" * (COMMAND_MAX_BYTES - len("echo ")))


def test_execution_ceilings_match_the_budget():
    assert COMMAND_MAX_BYTES == 16_384
    assert COMMAND_TIMEOUT_SECONDS == 1200.0
    assert MAX_SHELL_TIMEOUT_SECONDS == COMMAND_TIMEOUT_SECONDS
    assert DEFAULT_SHELL_TIMEOUT_SECONDS == 120.0


def test_shell_timeout_default_is_unchanged():
    base = SpyDockerSandbox()
    output = shell_tool(base).invoke({"command": "echo default"})

    assert base.calls == [("echo default", 120.0)]
    assert "echo default" in output


def test_shell_timeout_accepts_explicit_value():
    base = SpyDockerSandbox()
    shell_tool(base).invoke(
        {"command": "nuclei -u https://example.com", "timeout_seconds": 900}
    )

    assert base.calls == [("nuclei -u https://example.com", 900.0)]


def test_shell_timeout_above_ceiling_is_clamped():
    base = SpyDockerSandbox()
    shell_tool(base).invoke({"command": "sleep 1", "timeout_seconds": 5000})

    assert base.calls == [("sleep 1", 1200.0)]
    assert resolve_shell_timeout(5000) == 1200.0


def test_shell_timeout_rejects_nonpositive_without_executing():
    base = SpyDockerSandbox()
    output = shell_tool(base).invoke({"command": "echo no", "timeout_seconds": 0})

    assert output.startswith("error:")
    assert base.calls == []


def test_command_policy_caps_huge_timeouts_at_1200():
    base = SpyDockerSandbox()
    policy = CommandPolicySandbox(base)

    policy.exec("nuclei -u https://example.com", timeout=5000)

    assert base.calls == [("nuclei -u https://example.com", 1200.0)]


class SpyDockerSandbox(DockerSandbox):
    """Container-isolated stand-in that records commands instead of running them."""

    def __init__(self):
        self.calls = []
        self.closed = False

    def exec(self, cmd, timeout=120.0):
        self.calls.append((cmd, timeout))
        return ExecResult("ok", "", 0)

    def read_file(self, path):
        return f"read:{path}"

    def write_file(self, path, content):
        self.calls.append(("write", path, content))

    def close(self):
        self.closed = True


class SpySandbox(Sandbox):
    """Non-isolated stand-in used to prove commands are refused."""

    def __init__(self):
        self.calls = []

    def exec(self, cmd, timeout=120.0):
        self.calls.append((cmd, timeout))
        return ExecResult("ok", "", 0)

    def read_file(self, path):
        return f"read:{path}"

    def write_file(self, path, content):
        self.calls.append(("write", path, content))

    def close(self):
        pass


def test_proxy_executes_composed_shell_and_caps_timeout():
    base = SpyDockerSandbox()
    policy = CommandPolicySandbox(base, timeout=5)

    command = "cd scratch && mkdir -p out; printf hi > out/x | cat; echo $(uname)"
    result = policy.exec(command, timeout=30)

    assert result.stdout == "ok"
    assert base.calls == [(command, 5.0)]


def test_proxy_allows_long_scanner_timeouts():
    base = SpyDockerSandbox()
    policy = CommandPolicySandbox(base)

    policy.exec("nuclei -u https://example.com", timeout=900)
    assert base.calls == [("nuclei -u https://example.com", 900.0)]


def test_proxy_refuses_non_isolated_sandbox_before_execution(tmp_path):
    spy = SpySandbox()
    local = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)

    for base in (spy, local):
        policy = CommandPolicySandbox(base)

        with pytest.raises(CommandPolicyError, match="isolated"):
            policy.exec("echo safe")

    assert spy.calls == []


def test_proxy_delegates_non_command_operations_and_close():
    base = SpyDockerSandbox()
    policy = CommandPolicySandbox(base)

    assert policy.read_file("notes.txt") == "read:notes.txt"
    policy.write_file("notes.txt", "hello")
    policy.close()

    assert base.calls == [("write", "notes.txt", "hello")]
    assert base.closed is True


def test_wrapped_docker_sandbox_is_recognized_as_isolated():
    wrapped = WritePolicySandbox(SpyDockerSandbox())
    policy = CommandPolicySandbox(wrapped)

    assert policy.exec("echo composed && echo shell").stdout == "ok"


def test_harden_commands_is_idempotent(tmp_path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    policy = harden_commands(base)
    assert harden_commands(policy) is policy


def test_default_sandbox_failure_keeps_actionable_hint(monkeypatch):
    def fail():
        raise SandboxError("container unavailable")

    monkeypatch.setattr("aplomado.command_policy.DockerSandbox", fail)
    with pytest.raises(PinnaceError, match="Pass sandbox= explicitly"):
        harden_commands()


def test_run_scan_sends_composed_command_to_isolated_executor(tmp_path):
    class EchoDockerSandbox(SpyDockerSandbox):
        def exec(self, cmd, timeout=120.0):
            self.calls.append((cmd, timeout))
            return ExecResult(f"ran:{cmd}", "", 0)

    command = "mkdir -p scratch/x && printf ok > scratch/x/out; cat scratch/x/out | tr a-z A-Z"

    class ProbeModel:
        def __init__(self):
            self.calls = 0
            self.shell_descriptions = []

        def bind_tools(self, tools):
            shells = [tool for tool in tools if tool.name == "shell"]
            assert len(shells) == 1
            self.shell_descriptions.append(shells[0].description)
            return self

        def invoke(self, messages):
            self.calls += 1
            if self.calls == 1:
                return AIMessage(
                    content="",
                    tool_calls=[{
                        "name": "shell",
                        "args": {"command": command},
                        "id": "shell-1",
                        "type": "tool_call",
                    }],
                )
            tool_messages = [
                message for message in messages if isinstance(message, ToolMessage)
            ]
            assert tool_messages[-1].content.startswith(f"$ {command}")
            assert "ran:" in tool_messages[-1].content
            return AIMessage(
                content="",
                tool_calls=[{
                    "name": "finish",
                    "args": {"result": json.dumps({"summary": "ran shell", "findings": []})},
                    "id": "finish-1",
                    "type": "tool_call",
                }],
            )

    model = ProbeModel()
    base = EchoDockerSandbox()
    result = run_scan(
        "https://example.com",
        model=model,
        sandbox=base,
        session_store=SessionStore(tmp_path / "sessions"),
    )

    assert result["summary"] == "ran shell"
    assert base.calls[0][0] == command
    description = model.shell_descriptions[-1]
    assert "full bash shell" in description
    assert "isolated container" in description
    assert "workdir persists" in description
    assert "scratch/" in description
