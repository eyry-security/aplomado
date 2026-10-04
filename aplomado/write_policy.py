"""Write restrictions for Aplomado's sandbox file tool.

The command-execution tool is intentionally outside this module's scope.  This
wrapper constrains calls to ``Sandbox.write_file`` while transparently
forwarding reads and command execution to the underlying sandbox.
"""

from __future__ import annotations

import posixpath
import shlex
from pathlib import PurePosixPath

from pinnace import DockerSandbox, ExecResult, Sandbox, SandboxError

WRITE_ROOT = "scratch"
WRITE_MAX_BYTES = 1_000_000

_SENSITIVE_NAMES = frozenset(
    {
        ".git",
        ".gitconfig",
        ".gnupg",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".ssh",
        "authorized_keys",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
    }
)


def _normalise_root(root: str) -> str:
    if not isinstance(root, str) or not root or "\x00" in root:
        raise ValueError("write root must be a non-empty relative path")
    raw = PurePosixPath(root)
    if raw.is_absolute() or ".." in raw.parts:
        raise ValueError("write root must stay inside the sandbox workdir")
    normalised = posixpath.normpath(root)
    if normalised in {"", "."}:
        raise ValueError("write root must name a sandbox subdirectory")
    return normalised.rstrip("/")


class WritePolicySandbox(Sandbox):
    """Sandbox proxy that restricts ``write_file`` to a scratch subtree.

    Paths must be relative and live below ``root``. Sensitive credential and
    repository-control names are blocked, existing symlink components are
    rejected, and content is capped by UTF-8 byte size. Other sandbox methods
    are delegated unchanged.
    """

    def __init__(
        self,
        sandbox: Sandbox,
        *,
        root: str = WRITE_ROOT,
        max_bytes: int = WRITE_MAX_BYTES,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._sandbox = sandbox
        self.root = _normalise_root(root)
        self.max_bytes = max_bytes

    def exec(self, cmd: str, timeout: float = 120.0) -> ExecResult:
        return self._sandbox.exec(cmd, timeout=timeout)

    def read_file(self, path: str) -> str:
        return self._sandbox.read_file(path)

    def write_file(self, path: str, content: str) -> None:
        rel = self._validate_path(path)
        size = len(content.encode("utf-8"))
        if size > self.max_bytes:
            raise SandboxError(
                f"write is {size} bytes; limit is {self.max_bytes} bytes"
            )
        self._reject_symlink_path(rel)
        self._sandbox.write_file(rel, content)

    def close(self) -> None:
        self._sandbox.close()

    def _validate_path(self, path: str) -> str:
        if not isinstance(path, str) or not path or "\x00" in path:
            raise SandboxError("write path must be a non-empty relative path")
        raw = PurePosixPath(path)
        if raw.is_absolute() or ".." in raw.parts:
            raise SandboxError(f"write path escapes allowed root: {path!r}")
        rel = posixpath.normpath(path)
        prefix = self.root + "/"
        if not rel.startswith(prefix) or rel == self.root:
            raise SandboxError(
                f"writes are limited to {self.root}/ inside the sandbox workdir"
            )

        for component in PurePosixPath(rel).parts[1:]:
            name = component.casefold()
            if (
                name in _SENSITIVE_NAMES
                or name == ".env"
                or name.startswith(".env.")
            ):
                raise SandboxError(
                    f"refusing sensitive write path component: {component!r}"
                )
        return rel

    def _reject_symlink_path(self, rel: str) -> None:
        parts = PurePosixPath(rel).parts
        candidates = [
            posixpath.join(*parts[:index])
            for index in range(1, len(parts) + 1)
        ]
        checks = " || ".join(f"[ -L {shlex.quote(item)} ]" for item in candidates)
        result = self._sandbox.exec(checks)
        if result.exit_code == 0:
            raise SandboxError(f"refusing write through symlink path: {rel!r}")
        if result.exit_code != 1:
            raise SandboxError(f"could not validate write path: {rel!r}")


def harden_sandbox(sandbox: Sandbox | None = None) -> WritePolicySandbox:
    """Return an idempotently write-restricted sandbox.

    When no sandbox is supplied, create Aplomado's normal Docker sandbox first.
    """
    if isinstance(sandbox, WritePolicySandbox):
        return sandbox
    backing = sandbox if sandbox is not None else DockerSandbox()
    return WritePolicySandbox(backing)
