"""G4: skills framework — registry, access, unlocks, pre-load, byte prefix."""

from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage

import aplomado.scanner as scanner_mod
from aplomado.agent import AplomadoAgent
from aplomado.prompts import SYSTEM_PROMPT, PromptPack
from aplomado.scanner import run_scan
from aplomado import skills as skills_mod
from aplomado.skills import (
    Skill,
    SkillError,
    SkillRuntime,
    WEB_SCANNER_DOCTRINE,
    get_skill,
    resolve_primary_skill,
)
from pinnace import LocalSandbox
from pinnace.session import SessionStore

FINISH = json.dumps({
    "target": "https://example.test",
    "summary": "done",
    "findings": [],
})


def _tc(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


class ScriptModel:
    def __init__(self, script):
        self.script = list(script)
        self.requests = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.requests.append(list(messages))
        return self.script.pop(0)


def _run(tmp_path, model, **kwargs):
    kwargs.setdefault(
        "sandbox", LocalSandbox(str(tmp_path / "work"), unsafe_ok=True)
    )
    kwargs.setdefault("session_store", SessionStore(tmp_path / "sessions"))
    kwargs.setdefault("log", lambda *args: None)
    return run_scan("https://example.test", model=model, **kwargs)


def _install_fixture(monkeypatch, skill):
    monkeypatch.setitem(skills_mod._SKILLS, skill.name, skill)


def _fixture_chain(monkeypatch):
    primary = Skill(
        name="g4-primary",
        version=1,
        description="fixture primary",
        doctrine="FIXTURE PRIMARY DOCTRINE",
        planning_template=("fixture plan",),
        can_access=("g4-a",),
    )
    middle = Skill(
        name="g4-a",
        version=1,
        description="fixture middle",
        doctrine="FIXTURE MIDDLE DOCTRINE",
        planning_template=("middle plan",),
        can_access=("g4-b",),
    )
    outer = Skill(
        name="g4-b",
        version=1,
        description="fixture outer",
        doctrine="FIXTURE OUTER DOCTRINE",
        planning_template=("outer plan",),
    )
    for skill in (primary, middle, outer):
        _install_fixture(monkeypatch, skill)
    return primary


def test_unknown_skill_lists_available_choices():
    with pytest.raises(SkillError, match="web-scanner"):
        get_skill("missing-skill")
    assert get_skill("web-scanner-v1").id == "web-scanner"


def test_pack_names_map_to_primary_skills_by_identity():
    assert resolve_primary_skill(prompt_pack=PromptPack(
        name="recon", version=1, system_prompt="s",
        run_prompt_template="{target}",
    )).id == "web-scanner"
    assert resolve_primary_skill(prompt_pack=PromptPack(
        name="bughunter", version=1, system_prompt="s",
        run_prompt_template="{target}",
    )).id == "bug-hunter"
    assert resolve_primary_skill(
        primary_skill="bug-hunter",
        prompt_pack=PromptPack(
            name="recon", version=1, system_prompt="s",
            run_prompt_template="{target}",
        ),
    ).id == "bug-hunter"


def test_access_is_enforced_and_transitive_at_load_time(monkeypatch):
    primary = _fixture_chain(monkeypatch)
    runtime = SkillRuntime(primary)

    assert "g4-a" in runtime.catalog()
    assert "g4-b" not in runtime.catalog()

    assert "error:" in runtime.load("g4-b")
    assert "g4-a" in runtime.load("g4-b")
    assert "error:" in runtime.load("g4-b")

    loaded = runtime.load("g4-a")
    assert "g4-a" in loaded
    assert "middle plan" in loaded
    assert "todos_add" in loaded
    assert "g4-b" in runtime.catalog()

    assert "outer plan" in runtime.load("g4-b")
    assert runtime.loaded == ["g4-a", "g4-b"]


def test_double_load_is_a_noop(monkeypatch):
    primary = _fixture_chain(monkeypatch)
    runtime = SkillRuntime(primary)
    assert "skill loaded: g4-a" in runtime.load("g4-a")
    assert runtime.load("g4-a") == "already loaded"
    assert runtime.loaded == ["g4-a"]


def test_unlock_mechanism_starts_unbound_then_grants(monkeypatch, tmp_path):
    primary = Skill(
        name="g4-unlock-primary",
        version=1,
        description="fixture primary with a gated skill",
        doctrine="FIXTURE UNLOCK PRIMARY",
        planning_template=("fixture plan",),
        can_access=("g4-unlock",),
    )
    gated = Skill(
        name="g4-unlock",
        version=1,
        description="fixture secondary unlocking an existing tool",
        doctrine="FIXTURE UNLOCK DOCTRINE",
        planning_template=("gated plan",),
        tool_unlocks=("dalfox",),
    )
    _install_fixture(monkeypatch, primary)
    _install_fixture(monkeypatch, gated)

    captured = {}

    class CapturingAgent(AplomadoAgent):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured["agent"] = self
            captured["initial"] = set(self._tools_by_name)

    monkeypatch.setattr(scanner_mod, "PinnaceAgent", CapturingAgent)
    model = ScriptModel([
        AIMessage(content="", tool_calls=[
            _tc("dalfox", {"url": "https://example.test/?q=x"}, 1),
        ]),
        AIMessage(content="", tool_calls=[
            _tc("load_skill", {"skill_id": "g4-unlock"}, 2),
        ]),
        AIMessage(content="", tool_calls=[
            _tc("dalfox", {"url": "https://example.test/?q=x"}, 3),
        ]),
        AIMessage(content="", tool_calls=[
            _tc("finish", {"result": FINISH}, 4),
        ]),
    ])

    envelope = _run(
        tmp_path, model, primary_skill="g4-unlock-primary",
        log=lambda *args: None,
    )

    assert "dalfox" not in captured["initial"]
    assert "dalfox" in captured["agent"]._tools_by_name
    results = {
        message.tool_call_id: message.content
        for message in model.requests[-1]
        if isinstance(message, ToolMessage)
    }
    assert results["call-1"] == "error: unknown tool 'dalfox'"
    assert results["call-3"] != "error: unknown tool 'dalfox'"
    assert envelope["skills"]["primary"] == "g4-unlock-primary"
    assert envelope["skills"]["loaded"] == ["g4-unlock"]


def test_unlock_can_gate_a_pinnace_builtin(monkeypatch, tmp_path):
    primary = Skill(
        name="g4-builtin-primary",
        version=1,
        description="fixture primary gating a builtin",
        doctrine="FIXTURE BUILTIN PRIMARY",
        planning_template=("fixture plan",),
        can_access=("g4-builtin",),
    )
    gated = Skill(
        name="g4-builtin",
        version=1,
        description="fixture secondary gating a builtin tool",
        doctrine="FIXTURE BUILTIN DOCTRINE",
        planning_template=("builtin plan",),
        tool_unlocks=("read_file",),
    )
    _install_fixture(monkeypatch, primary)
    _install_fixture(monkeypatch, gated)

    captured = {}

    class CapturingAgent(AplomadoAgent):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured["agent"] = self
            captured["initial"] = set(self._tools_by_name)

    monkeypatch.setattr(scanner_mod, "PinnaceAgent", CapturingAgent)
    model = ScriptModel([
        AIMessage(content="", tool_calls=[
            _tc("read_file", {"path": "scratch/none.txt"}, 1),
        ]),
        AIMessage(content="", tool_calls=[
            _tc("load_skill", {"skill_id": "g4-builtin"}, 2),
        ]),
        AIMessage(content="", tool_calls=[
            _tc("finish", {"result": FINISH}, 3),
        ]),
    ])

    _run(tmp_path, model, primary_skill="g4-builtin-primary")

    assert "read_file" not in captured["initial"]
    assert "read_file" in captured["agent"]._tools_by_name
    results = {
        message.tool_call_id: message.content
        for message in model.requests[-1]
        if isinstance(message, ToolMessage)
    }
    assert results["call-1"] == "error: unknown tool 'read_file'"


def test_preload_matches_context_before_turn_one(tmp_path):
    logs = []
    model = ScriptModel([
        AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 1)]),
    ])
    envelope = _run(
        tmp_path, model,
        target_context="probe: scheme=https port=443 login form detected",
        log=logs.append,
    )

    assert envelope["skills"] == {
        "primary": "web-scanner",
        "loaded": ["auth-access-control"],
    }
    assert any(
        "[skill] loaded auth-access-control (turn 0)" in line for line in logs
    )
    first_request = model.requests[0]
    assert any(
        isinstance(message, SystemMessage)
        and "SKILL LOADED: auth-access-control" in str(message.content)
        for message in first_request
    )


def test_nonmatching_context_preloads_nothing(tmp_path):
    model = ScriptModel([
        AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 1)]),
    ])
    envelope = _run(
        tmp_path, model,
        target_context="probe: scheme=https port=443 status=200",
        log=lambda *args: None,
    )

    assert envelope["skills"] == {"primary": "web-scanner", "loaded": []}


def test_pro_system_prompt_is_byte_prefix_with_doctrine_appended(tmp_path):
    base = "OPERATOR SYSTEM PROMPT\nwith details\n"
    pack = PromptPack(
        name="pro-ai-scan",
        version=1,
        system_prompt=base,
        run_prompt_template="PRO RUN {target}\n{target_context_block}",
    )
    model = ScriptModel([
        AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 1)]),
    ])
    _run(tmp_path, model, prompt_pack=pack, log=lambda *args: None)

    effective = model.requests[0][0].content
    assert effective.startswith(base)
    assert effective[len(base):].strip() == WEB_SCANNER_DOCTRINE.strip()


def test_builtin_system_prompt_is_byte_prefix_with_doctrine_appended(tmp_path):
    model = ScriptModel([
        AIMessage(content="", tool_calls=[_tc("finish", {"result": FINISH}, 1)]),
    ])
    _run(tmp_path, model, log=lambda *args: None)

    effective = model.requests[0][0].content
    assert effective.startswith(SYSTEM_PROMPT)
    assert effective[len(SYSTEM_PROMPT):].strip() == (
        WEB_SCANNER_DOCTRINE.strip()
    )
