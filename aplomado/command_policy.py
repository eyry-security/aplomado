"""Command-execution restrictions for Aplomado's sandbox shell tool.

The sandbox remains the security boundary. This module adds a conservative,
model-visible policy in front of it so normal reconnaissance commands work
while destructive binaries, shell composition, host-control tools, and common
filesystem side channels are rejected before execution.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence

from pinnace import DockerSandbox, ExecResult, PinnaceError, Sandbox, SandboxError

COMMAND_MAX_BYTES = 16_384
COMMAND_TIMEOUT_SECONDS = 60.0

# Commands needed by the documented light-recon playbook. Shells, privilege
# tools, package managers, process control, and filesystem mutation utilities
# are intentionally absent.
COMMAND_ALLOWLIST = frozenset(
    {
        "base64",
        "cat",
        "command",
        "curl",
        "cut",
        "date",
        "dig",
        "echo",
        "ffuf",
        "getent",
        "test",
        "grep",
        "head",
        "host",
        "jq",
        "ls",
        "nslookup",
        "openssl",
        "printf",
        "sort",
        "tail",
        "tr",
        "uname",
        "uniq",
        "wc",
        "which",
    }
)

# General-purpose interpreters can bypass a command-name policy. They are only
# available when the backing sandbox is known to be container-isolated.
ISOLATED_COMMAND_ALLOWLIST = frozenset({"python", "python3"})

_ALLOWED_OPENSSL_COMMANDS = frozenset({"s_client", "version", "x509"})
_SHELL_PUNCTUATION = "|&;()<>"
_CURL_BLOCKED_OPTIONS = frozenset(
    {
        "--abstract-unix-socket",
        "--config",
        "--cookie-jar",
        "--dump-header",
        "--netrc",
        "--netrc-file",
        "--output",
        "--output-dir",
        "--remote-header-name",
        "--remote-name",
        "--stderr",
        "--trace",
        "--trace-ascii",
        "--unix-socket",
        "--upload-file",
        "-D",
        "-K",
        "-O",
        "-T",
        "-c",
        "-n",
        "-o",
    }
)
_CURL_BLOCKED_PREFIXES = tuple(
    option + "=" for option in _CURL_BLOCKED_OPTIONS if option.startswith("--")
)
_CURL_FILE_VALUE_OPTIONS = frozenset(
    {"--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--form", "--header", "-F", "-H", "-d"}
)
_CURL_LOCAL_SCHEMES = (
    "dict://",
    "file://",
    "ftp://",
    "gopher://",
    "imap://",
    "ldap://",
    "ldaps://",
    "pop3://",
    "scp://",
    "sftp://",
    "smtp://",
    "telnet://",
    "tftp://",
)


class CommandPolicyError(SandboxError):
    """Raised when a shell command is rejected before execution."""


def _tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=_SHELL_PUNCTUATION)
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError as exc:
        raise CommandPolicyError(f"invalid shell syntax: {exc}") from exc


def _split_pipeline(tokens: Sequence[str]) -> list[list[str]]:
    commands: list[list[str]] = [[]]
    for token in tokens:
        if token == "|":
            if not commands[-1]:
                raise CommandPolicyError("empty pipeline command")
            commands.append([])
            continue
        if token and all(char in _SHELL_PUNCTUATION for char in token):
            raise CommandPolicyError(
                f"shell control operator {token!r} is not allowed; use one pipeline"
            )
        commands[-1].append(token)
    if not commands[-1]:
        raise CommandPolicyError("empty pipeline command")
    return commands


def _validate_command_lookup(arguments: Sequence[str]) -> None:
    if len(arguments) != 2 or arguments[0] != "-v":
        raise CommandPolicyError("command is limited to: command -v <tool>")
    requested = arguments[1]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", requested):
        raise CommandPolicyError(f"invalid tool lookup: {requested!r}")


def _validate_openssl(arguments: Sequence[str]) -> None:
    if not arguments or arguments[0].casefold() not in _ALLOWED_OPENSSL_COMMANDS:
        allowed = ", ".join(sorted(_ALLOWED_OPENSSL_COMMANDS))
        raise CommandPolicyError(f"openssl subcommand must be one of: {allowed}")

    # Keep certificate inspection available without letting openssl write files,
    # load executable providers/engines, or turn x509 into a signing utility.
    blocked = {
        "-cacreateserial",
        "-caserial",
        "-config",
        "-engine",
        "-keylogfile",
        "-out",
        "-provider",
        "-provider-path",
        "-sess_out",
        "-writerand",
    }
    if arguments[0].casefold() == "x509":
        blocked |= {"-ca", "-cakey", "-force_pubkey", "-new", "-req", "-signkey"}
    for argument in arguments[1:]:
        option = argument.partition("=")[0].casefold()
        if option in blocked:
            raise CommandPolicyError(f"openssl option is not allowed: {argument!r}")


def _validate_date(arguments: Sequence[str]) -> None:
    for argument in arguments:
        lowered = argument.casefold()
        if lowered == "-s" or lowered.startswith("-s") or lowered.startswith("--set"):
            raise CommandPolicyError(f"date clock-setting option is not allowed: {argument!r}")


def _validate_sort(arguments: Sequence[str]) -> None:
    for argument in arguments:
        lowered = argument.casefold()
        if (
            lowered == "-o"
            or lowered.startswith("-o")
            or lowered == "--output"
            or lowered.startswith("--output=")
            or lowered == "--compress-program"
            or lowered.startswith("--compress-program=")
        ):
            raise CommandPolicyError(f"sort option is not allowed: {argument!r}")


def _curl_value_reads_file(option: str, value: str) -> bool:
    if option in {"--header", "-H"}:
        return value.startswith("@")
    if option in {"--form", "-F"}:
        return value.startswith("@") or "=@" in value
    if option == "--data-urlencode":
        return value.startswith("@") or ("@" in value and "=" not in value)
    if option == "--url-query":
        return "@" in value
    if option in {"--cookie", "-b"}:
        return "=" not in value
    return value.startswith("@")


def _validate_curl(arguments: Sequence[str]) -> None:
    file_value_options = _CURL_FILE_VALUE_OPTIONS | {
        "--cookie",
        "--json",
        "--url-query",
        "-b",
    }
    blocked_long_options = {
        "--alt-svc",
        "--engine",
        "--etag-save",
        "--hsts",
        "--libcurl",
        "--proto-default",
        "--variable",
        "--write-out",
    }
    pending_file_value_option = ""
    for argument in arguments:
        if pending_file_value_option:
            if _curl_value_reads_file(pending_file_value_option, argument):
                raise CommandPolicyError("curl may not read request data from a file")
            pending_file_value_option = ""

        lowered = argument.casefold()
        long_option = lowered.partition("=")[0]
        if (
            argument in _CURL_BLOCKED_OPTIONS
            or lowered.startswith(_CURL_BLOCKED_PREFIXES)
            or long_option in blocked_long_options
        ):
            raise CommandPolicyError(f"curl filesystem option is not allowed: {argument!r}")
        if lowered.startswith(_CURL_LOCAL_SCHEMES) or any(
            f"={scheme}" in lowered for scheme in _CURL_LOCAL_SCHEMES
        ):
            raise CommandPolicyError(f"curl URL scheme is not allowed: {argument!r}")

        if argument.startswith("--"):
            option, separator, value = argument.partition("=")
            if option in file_value_options:
                if separator:
                    if _curl_value_reads_file(option, value):
                        raise CommandPolicyError("curl may not read request data from a file")
                else:
                    pending_file_value_option = option
            continue

        if argument.startswith("-"):
            flags = argument[1:]
            blocked_flags = frozenset("oOTKDEcnw")
            file_value_flags = frozenset("bdFH")
            value_flags = frozenset("ACemPQrtuUxXYyz")
            for index, flag in enumerate(flags):
                if flag in blocked_flags:
                    raise CommandPolicyError(
                        f"curl filesystem option is not allowed: {argument!r}"
                    )
                if flag in file_value_flags:
                    option = f"-{flag}"
                    inline_value = flags[index + 1 :]
                    if inline_value:
                        if _curl_value_reads_file(option, inline_value):
                            raise CommandPolicyError(
                                "curl may not read request data from a file"
                            )
                    else:
                        pending_file_value_option = option
                    break
                if flag in value_flags:
                    break


def validate_command(command: str, *, allow_interpreters: bool = False) -> None:
    """Validate one simple command or pipeline against Aplomado's policy."""
    if not isinstance(command, str) or not command.strip():
        raise CommandPolicyError("command must be a non-empty string")
    size = len(command.encode("utf-8"))
    if size > COMMAND_MAX_BYTES:
        raise CommandPolicyError(
            f"command is {size} bytes; limit is {COMMAND_MAX_BYTES} bytes"
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in command):
        raise CommandPolicyError("command contains a control character")
    if "$" in command or "`" in command:
        raise CommandPolicyError("shell expansion and command substitution are not allowed")

    commands = _split_pipeline(_tokens(command))
    allowed = COMMAND_ALLOWLIST
    if allow_interpreters:
        allowed = allowed | ISOLATED_COMMAND_ALLOWLIST

    for parts in commands:
        executable = parts[0]
        name = executable.casefold()
        # Allow ./ffuf (the bundled binary, run from workdir)
        if name == "./ffuf":
            name = "ffuf"
        if "/" in name or name not in allowed:
            raise CommandPolicyError(f"command is not allowed: {executable!r}")
        arguments = parts[1:]
        if name == "command":
            _validate_command_lookup(arguments)
        elif name == "curl":
            _validate_curl(arguments)
        elif name == "date":
            _validate_date(arguments)
        elif name == "openssl":
            _validate_openssl(arguments)
        elif name == "sort":
            _validate_sort(arguments)


class CommandPolicySandbox(Sandbox):
    """Sandbox proxy that validates and time-limits command execution."""

    def __init__(
        self,
        sandbox: Sandbox,
        *,
        allow_interpreters: bool | None = None,
        timeout: float = COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._sandbox = sandbox
        self.allow_interpreters = (
            isinstance(sandbox, DockerSandbox)
            if allow_interpreters is None
            else allow_interpreters
        )
        self.timeout = float(timeout)

    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
        validate_command(cmd, allow_interpreters=self.allow_interpreters)
        return self._sandbox.exec(cmd, timeout=min(float(timeout), self.timeout))

    def read_file(self, path: str) -> str:
        return self._sandbox.read_file(path)

    def write_file(self, path: str, content: str) -> None:
        self._sandbox.write_file(path, content)

    def close(self) -> None:
        self._sandbox.close()


def harden_commands(sandbox: Sandbox | None = None) -> CommandPolicySandbox:
    """Return an idempotently command-restricted sandbox.

    With no supplied sandbox, Aplomado's normal container sandbox is created
    first, so interpreter use stays inside that isolation boundary.
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
