"""G3: harness-owned planning protocol and plan-aware coverage."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

from aplomado.partial import build_coverage_statement
from aplomado.prompts import (
    PLANNING_PROTOCOL,
    PromptPack,
    get_prompt_pack,
    load_prompt_pack,
)
from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore


class PromptSpyModel:
    def __init__(self):
        self.messages = None

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.messages = list(messages)
        return AIMessage(content="review complete")


def _scan(tmp_path, pack):
    model = PromptSpyModel()
    run_scan(
        "example.test",
        target_context="ports: 443",
        prompt_pack=pack,
        model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
    )
    return model


@pytest.mark.parametrize("pack_id", ["recon-v1", "bughunter-v1"])
def test_planning_protocol_is_in_builtin_rendered_run_prompts(tmp_path, pack_id):
    pack = get_prompt_pack(pack_id)
    model = _scan(tmp_path, pack)

    assert PLANNING_PROTOCOL not in pack.system_prompt
    assert PLANNING_PROTOCOL not in model.messages[0].content
    assert PLANNING_PROTOCOL in model.messages[-1].content
    assert "TARGET: example.test" in model.messages[-1].content


def test_planning_protocol_is_in_the_pro_pack_run_prompt(tmp_path):
    pack = PromptPack(
        name="pro-ai-scan",
        version=1,
        system_prompt="PRO SYSTEM PROMPT",
        run_prompt_template="PRO RUN {target}\n{target_context_block}",
    )
    model = _scan(tmp_path, pack)

    assert model.messages[0].content.startswith("PRO SYSTEM PROMPT")
    assert PLANNING_PROTOCOL not in model.messages[0].content
    assert model.messages[-1].content.startswith(
        "PRO RUN example.test\nports: 443\n\n"
    )
    assert PLANNING_PROTOCOL in model.messages[-1].content


def test_planning_protocol_survives_system_and_run_overrides(tmp_path):
    system_file = tmp_path / "system.txt"
    run_file = tmp_path / "run.txt"
    system_file.write_text("OVERRIDDEN SYSTEM\n", encoding="utf-8")
    run_file.write_text("OVERRIDDEN RUN {target}\n", encoding="utf-8")
    pack = load_prompt_pack(
        "recon-v1",
        system_prompt_file=str(system_file),
        run_prompt_file=str(run_file),
    )

    model = _scan(tmp_path, pack)

    assert model.messages[0].content.startswith("OVERRIDDEN SYSTEM\n")
    assert PLANNING_PROTOCOL not in model.messages[0].content
    assert model.messages[-1].content.startswith(
        "OVERRIDDEN RUN example.test\n\n" + PLANNING_PROTOCOL
    )


def test_planning_protocol_names_planning_and_recovery_actions():
    expected = [
        "Phase 0",
        "todos_write",
        "todos_add",
        "todos_update(in_progress)",
        "scratch/todos.json",
        "memory_summary()",
        "compaction event",
        "sub-agent returns",
        "three consecutive tool errors",
        "repeat a command",
    ]
    for phrase in expected:
        assert phrase in PLANNING_PROTOCOL


def test_coverage_statement_names_planned_but_unreached_items():
    todos = [
        {"text": "recon the target", "status": "done", "note": "scratch/recon.txt"},
        {"text": "test XSS", "status": "skipped", "note": "no reflected params"},
        {"text": "test SQL injection", "status": "pending", "note": ""},
        {"text": "test auth bypass", "status": "pending", "note": ""},
    ]

    coverage = build_coverage_statement(
        target="example.test",
        messages=[],
        todos=todos,
        usage_records=[],
    )

    assert "done=1 open=2 total=4 skipped=1" in coverage
    assert "test SQL injection" in coverage
    assert "test auth bypass" in coverage
