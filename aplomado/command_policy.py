"""Execution safety for Aplomado's sandbox shell tool.

The Docker sandbox is the security boundary. This module does not police which
binaries or shell syntax the model may use: commands run through a real shell
inside the isolated container, so operators, pipes, redirects, subshells, and
command substitution all work. It only enforces the execution-safety limits
(an isolated backing sandbox, a command-size ceiling, and a timeout ceiling).
"""

from __future__ import annotations

from langchain_core.tools import BaseTool, StructuredTool
from pinnace import DockerSandbox, ExecResult, PinnaceError, Sandbox, SandboxError
from pinnace.tool_policy import ToolPolicyError, check_shell
from pinnace.tools import _format_exec

COMMAND_MAX_BYTES = 16_384
# Ceiling for any single sandbox command. The model-facing shell tool keeps its
# own 120s default but may request more per call; long-running internal scanners
# (nuclei/dalfox/sqlmap) pass explicit timeouts up to the same ceiling.
COMMAND_TIMEOUT_SECONDS = 1200.0
DEFAULT_SHELL_TIMEOUT_SECONDS = 120.0
MAX_SHELL_TIMEOUT_SECONDS = COMMAND_TIMEOUT_SECONDS

SHELL_TOOL_DESCRIPTION = (
    "Run commands in a full bash shell inside an isolated container. Shell "
    "operators (&&, ||, ;, pipes, redirects, subshells) and command substitution "
    "work, and any binary present in the image may be run. The workdir persists "
    "between calls; files written under scratch/ persist for the run. Returns "
    "stdout, stderr, and exit code. timeout_seconds defaults to 120 and may be "
    "raised up to 1200 for long-running commands."
)


class CommandPolicyError(SandboxError):
    """Raised when a shell command is rejected before execution."""


def _is_container_isolated(sandbox: Sandbox) -> bool:
    """True when the sandbox chain bottoms out in a DockerSandbox.

    WritePolicySandbox/CommandPolicySandbox wrap the real sandbox, so a
    direct isinstance check would wrongly treat production Docker runs as
    unisolated.
    """
    current: object | None = sandbox
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, DockerSandbox):
            return True
        current = getattr(current, "_sandbox", None)
    return False


def validate_command(command: str) -> None:
    """Validate a command against Aplomado's execution-safety limits."""
    if not isinstance(command, str) or not command.strip():
        raise CommandPolicyError("command must be a non-empty string")
    size = len(command.encode("utf-8"))
    if size > COMMAND_MAX_BYTES:
        raise CommandPolicyError(
            f"command is {size} bytes; limit is {COMMAND_MAX_BYTES} bytes"
        )


def resolve_shell_timeout(timeout_seconds: float | None = None) -> float:
    """Return a valid per-command timeout, clamped to the 1200s ceiling."""
    if timeout_seconds is None:
        return DEFAULT_SHELL_TIMEOUT_SECONDS
    if isinstance(timeout_seconds, bool):
        raise CommandPolicyError("timeout_seconds must be a number")
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise CommandPolicyError("timeout_seconds must be a number") from exc
    if timeout <= 0:
        raise CommandPolicyError("timeout_seconds must be positive")
    return min(timeout, MAX_SHELL_TIMEOUT_SECONDS)


def shell_tool(sandbox: Sandbox) -> BaseTool:
    """Build the model-facing shell tool with a per-call timeout argument."""

    def shell(
        command: str,
        timeout_seconds: float = DEFAULT_SHELL_TIMEOUT_SECONDS,
    ) -> str:
        """Run a bash command in the isolated sandbox and return its output.

        timeout_seconds defaults to 120 and is capped at 1200 seconds.
        """
        try:
            check_shell(command)
            timeout = resolve_shell_timeout(timeout_seconds)
            result = sandbox.exec(command, timeout=timeout)
        except (ToolPolicyError, CommandPolicyError) as exc:
            return f"error: {exc}"
        except Exception as exc:  # noqa: BLE001 - model sees execution failures
            return f"error: {exc}"
        return _format_exec(command, result)

    return StructuredTool.from_function(
        shell,
        name="shell",
        description=SHELL_TOOL_DESCRIPTION,
    )


class CommandPolicySandbox(Sandbox):
    """Sandbox proxy that requires isolation and time-limits execution."""

    def __init__(
        self,
        sandbox: Sandbox,
        *,
        timeout: float = COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._sandbox = sandbox
        self.timeout = float(timeout)

    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
        if not _is_container_isolated(self._sandbox):
            raise CommandPolicyError(
                "commands may only run inside an isolated Docker sandbox"
            )
        validate_command(cmd)
        return self._sandbox.exec(cmd, timeout=min(float(timeout), self.timeout))

    def read_file(self, path: str) -> str:
        return self._sandbox.read_file(path)

    def write_file(self, path: str, content: str) -> None:
        self._sandbox.write_file(path, content)

    def close(self) -> None:
        self._sandbox.close()


def harden_commands(sandbox: Sandbox | None = None) -> CommandPolicySandbox:
    """Return an idempotently execution-restricted sandbox.

    With no supplied sandbox, Aplomado's normal container sandbox is created
    first, so command execution stays inside that isolation boundary.
    """
    if isinstance(sandbox, CommandPolicySandbox):
        return sandbox
    if sandbox is None:
        try:
            backing = DockerSandbox()
        except SandboxError as exc:
            raise PinnaceError(
                f"{exc} Pass sandbox= explicitly (e.g. LocalSandbox for dev)."
            ) from exc
    else:
        backing = sandbox
    return CommandPolicySandbox(backing)
