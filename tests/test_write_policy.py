"""Tests for Aplomado's write_file policy; no Docker or network required."""

import json

import pytest
from langchain_core.messages import AIMessage

from aplomado.scanner import run_scan
from aplomado.write_policy import (
    WRITE_MAX_BYTES,
    WritePolicySandbox,
    harden_sandbox,
)
from pinnace import LocalSandbox, SandboxError, builtin_tools
from pinnace.session import SessionStore


def _write_tool(sandbox):
    return next(tool for tool in builtin_tools(sandbox) if tool.name == "write_file")


def test_allows_utf8_write_under_scratch(tmp_path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    tool = _write_tool(WritePolicySandbox(base))

    result = tool.invoke({"path": "scratch/notes/result.txt", "content": "héllo"})

    assert result == "wrote 5 chars to scratch/notes/result.txt"
    assert (tmp_path / "work/scratch/notes/result.txt").read_text() == "héllo"


@pytest.mark.parametrize(
    "path",
    ["notes.txt", "/tmp/notes.txt", "scratch/../../notes.txt", "../scratch/notes.txt"],
)
def test_rejects_writes_outside_scratch(tmp_path, path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    result = _write_tool(WritePolicySandbox(base)).invoke(
        {"path": path, "content": "blocked"}
    )

    assert result.startswith("error:")
    assert not (tmp_path / "work/notes.txt").exists()


@pytest.mark.parametrize(
    "path",
    [
        "scratch/.env",
        "scratch/config/.env.local",
        "scratch/.git/config",
        "scratch/home/.ssh/authorized_keys",
        "scratch/id_ed25519",
        "scratch/.netrc",
    ],
)
def test_rejects_sensitive_path_names(tmp_path, path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    result = _write_tool(WritePolicySandbox(base)).invoke(
        {"path": path, "content": "blocked"}
    )

    assert "sensitive write path" in result


def test_limit_uses_utf8_bytes_not_characters(tmp_path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    tool = _write_tool(WritePolicySandbox(base, max_bytes=3))

    result = tool.invoke({"path": "scratch/out.txt", "content": "éé"})

    assert "write is 4 bytes; limit is 3 bytes" in result
    assert not (tmp_path / "work/scratch/out.txt").exists()


def test_default_limit_accepts_exact_boundary(tmp_path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    policy = WritePolicySandbox(base)

    policy.write_file("scratch/boundary.bin", "x" * WRITE_MAX_BYTES)

    assert (tmp_path / "work/scratch/boundary.bin").stat().st_size == WRITE_MAX_BYTES


def test_rejects_existing_symlink_component(tmp_path):
    work = tmp_path / "work"
    outside = tmp_path / "outside"
    (work / "scratch").mkdir(parents=True)
    outside.mkdir()
    (work / "scratch/link").symlink_to(outside, target_is_directory=True)
    policy = WritePolicySandbox(LocalSandbox(str(work), unsafe_ok=True))

    with pytest.raises(SandboxError, match="symlink"):
        policy.write_file("scratch/link/escaped.txt", "blocked")

    assert not (outside / "escaped.txt").exists()


def test_reads_and_commands_are_delegated_unchanged(tmp_path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    base.write_file("existing.txt", "read me")
    policy = WritePolicySandbox(base)

    assert policy.read_file("existing.txt") == "read me"
    assert policy.exec("printf command-ok").stdout == "command-ok"


def test_harden_sandbox_is_idempotent(tmp_path):
    base = LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    policy = harden_sandbox(base)

    assert harden_sandbox(policy) is policy


def test_run_scan_enforces_policy_on_builtin_write_tool(tmp_path):
    class ProbeModel:
        def __init__(self):
            self.calls = 0

        def bind_tools(self, tools):
            assert len([tool for tool in tools if tool.name == "write_file"]) == 1
            return self

        def invoke(self, messages):
            self.calls += 1
            if self.calls == 1:
                return AIMessage(
                    content="",
                    tool_calls=[{
                        "name": "write_file",
                        "args": {"path": "outside.txt", "content": "blocked"},
                        "id": "write-1",
                        "type": "tool_call",
                    }],
                )
            assert "writes are limited to scratch/" in messages[-1].content
            return AIMessage(
                content="",
                tool_calls=[{
                    "name": "finish",
                    "args": {"result": json.dumps({"summary": "done", "findings": []})},
                    "id": "finish-1",
                    "type": "tool_call",
                }],
            )

    work = tmp_path / "work"
    result = run_scan(
        "https://example.com",
        model=ProbeModel(),
        sandbox=LocalSandbox(str(work), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
    )

    assert result["summary"] == "done"
    assert not (work / "outside.txt").exists()
