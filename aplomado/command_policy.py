"""Execution safety for Aplomado's sandbox shell tool.

The Docker sandbox is the security boundary. This module does not police which
binaries or shell syntax the model may use: commands run through a real shell
inside the isolated container, so operators, pipes, redirects, subshells, and
command substitution all work. It only enforces the execution-safety limits
(an isolated backing sandbox, a command-size ceiling, and a timeout ceiling).
"""

from __future__ import annotations

from pinnace import DockerSandbox, ExecResult, PinnaceError, Sandbox, SandboxError

COMMAND_MAX_BYTES = 16_384
# Ceiling for any single sandbox command. The model-facing shell tool keeps its
# own 120s default; long-running internal scanners (nuclei/dalfox/sqlmap) pass
# explicit timeouts up to 900s and must not be silently cut off at 60s.
COMMAND_TIMEOUT_SECONDS = 920.0

SHELL_TOOL_DESCRIPTION = (
    "Run commands in a full bash shell inside an isolated container. Shell "
    "operators (&&, ||, ;, pipes, redirects, subshells) and command substitution "
    "work, and any binary present in the image may be run. The workdir persists "
    "between calls; files written under scratch/ persist for the run. Returns "
    "stdout, stderr, and exit code."
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
