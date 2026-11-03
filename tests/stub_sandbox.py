"""Shared in-memory sandbox stub for tests."""

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
