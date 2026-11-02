"""G2: session-only graph memory for one scan."""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage, ToolMessage
from pinnace import LocalSandbox
from pinnace.session import SessionStore

from aplomado.agent import COMPACTION_SUMMARY_PROMPT
from aplomado.memory import (
    MAX_EDGES,
    MAX_NODES,
    MEMORY_PATH,
    MemoryStore,
    TurnCounter,
    memory_tools,
    node_id_for,
)
from aplomado.prompts import BUGHUNTER_SYSTEM_PROMPT, SYSTEM_PROMPT
from aplomado.scanner import run_scan
from aplomado.subagents import SUBAGENT_TASK_MARKER


def _tc(name, args, number):
    return {
        "name": name,
        "args": args,
        "id": f"call-{number}",
        "type": "tool_call",
    }


def _finish(summary="done"):
    payload = json.dumps({
        "target": "https://example.com",
        "summary": summary,
        "findings": [],
    })
    return AIMessage(
        content="",
        tool_calls=[_tc("finish", {"result": payload}, 99)],
    )


class ScriptedModel:
    def __init__(self, parent_script, child_script=None):
        self.parent_script = list(parent_script)
        self.child_script = list(child_script or [])
        self.parent_calls = 0
        self.child_calls = 0
        self.requests = []

    def bind_tools(self, tools):
        return self

    def _is_child(self, messages):
        for message in messages:
            content = getattr(message, "content", "")
            if isinstance(content, str) and SUBAGENT_TASK_MARKER in content:
                return True
        return False

    def invoke(self, messages):
        is_child = self._is_child(messages)
        self.requests.append((is_child, list(messages)))
        if is_child:
            self.child_calls += 1
            index = min(self.child_calls - 1, len(self.child_script) - 1)
            return self.child_script[index]
        self.parent_calls += 1
        index = min(self.parent_calls - 1, len(self.parent_script) - 1)
        return self.parent_script[index]


def _sandbox(tmp_path, name="work"):
    return LocalSandbox(str(tmp_path / name), unsafe_ok=True)


def _tools(tmp_path, turn_counter=None):
    sandbox = _sandbox(tmp_path)
    return sandbox, {
        tool.name: tool
        for tool in memory_tools(lambda: sandbox, turn_counter)
    }


def _graph(tmp_path, name="work"):
    return json.loads((tmp_path / name / MEMORY_PATH).read_text())


def _tool_contents(model, name):
    return [
        message.content
        for child, messages in model.requests
        if not child
        for message in messages
        if isinstance(message, ToolMessage) and message.name == name
    ]


def test_deterministic_id_upsert_merges_props_without_duplicates(tmp_path):
    current = {"turn": 1}
    sandbox, tools = _tools(tmp_path, lambda: current["turn"])

    first = tools["memory_remember"].invoke({
        "kind": "endpoint",
        "key": "GET /Login",
        "label": "GET /login",
        "props": {"status": 200, "auth": "none"},
    })
    current["turn"] = 2
    second = tools["memory_remember"].invoke({
        "kind": "endpoint",
        "key": "  get   /login  ",
        "label": "GET /login (updated)",
        "props": {"auth": "required"},
        "confidence": "confirmed",
        "status": "confirmed",
    })

    assert node_id_for("endpoint", "GET /Login") == "endpoint:get /login"
    assert "added node endpoint:get /login" in first
    assert "updated node endpoint:get /login" in second
    graph = _graph(tmp_path)
    assert len(graph["nodes"]) == 1
    node = graph["nodes"][0]
    assert node["id"] == "endpoint:get /login"
    assert node["props"] == {"status": 200, "auth": "required"}
    assert node["label"] == "GET /login (updated)"
    assert node["confidence"] == "confirmed"
    assert node["status"] == "confirmed"
    assert node["created_turn"] == 1
    assert node["source_turn"] == 2
    assert node["updated_turn"] == 2


def test_edge_to_missing_node_and_unknown_enums_error(tmp_path):
    _, tools = _tools(tmp_path)
    tools["memory_remember"].invoke({
        "kind": "host",
        "key": "example.com",
        "label": "example.com",
    })

    missing = tools["memory_relate"].invoke({
        "source_id": "host:example.com",
        "relation": "calls",
        "target_id": "endpoint:get:/missing",
    })
    assert missing.startswith("error:")
    assert "missing node" in missing

    kind_error = tools["memory_remember"].invoke({
        "kind": "made_up",
        "key": "x",
        "label": "x",
    })
    assert kind_error.startswith("error:")
    assert "unknown node kind" in kind_error

    relation_error = tools["memory_relate"].invoke({
        "source_id": "host:example.com",
        "relation": "made_up",
        "target_id": "host:example.com",
    })
    assert relation_error.startswith("error:")
    assert "unknown relation" in relation_error

    assert len(_graph(tmp_path)["nodes"]) == 1
    assert _graph(tmp_path)["edges"] == []


def test_recall_walks_one_and_two_hops(tmp_path):
    _, tools = _tools(tmp_path)
    tools["memory_remember"].invoke({
        "kind": "host",
        "key": "example.com",
        "label": "HOST-LABEL",
    })
    tools["memory_remember"].invoke({
        "kind": "endpoint",
        "key": "get:/api",
        "label": "ENDPOINT-LABEL",
        "props": {"status": 200},
    })
    tools["memory_remember"].invoke({
        "kind": "technology",
        "key": "express",
        "label": "TECH-LABEL",
    })
    tools["memory_relate"].invoke({
        "source_id": "host:example.com",
        "relation": "calls",
        "target_id": "endpoint:get:/api",
    })
    tools["memory_relate"].invoke({
        "source_id": "endpoint:get:/api",
        "relation": "uses_technology",
        "target_id": "technology:express",
    })

    one_hop = tools["memory_recall"].invoke({
        "node_id": "host:example.com",
        "depth": 1,
    })
    assert "host:example.com" in one_hop
    assert "endpoint:get:/api" in one_hop
    assert "TECH-LABEL" not in one_hop
    assert "host:example.com --calls--> endpoint:get:/api" in one_hop

    two_hops = tools["memory_recall"].invoke({
        "node_id": "host:example.com",
        "depth": 2,
    })
    assert "TECH-LABEL" in two_hops
    assert "endpoint:get:/api --uses_technology--> technology:express" in (
        two_hops
    )

    by_query = tools["memory_recall"].invoke({"query": "endpoint-label"})
    assert "endpoint:get:/api" in by_query
    assert "HOST-LABEL" not in by_query

    missing = tools["memory_recall"].invoke({"node_id": "host:missing"})
    assert missing.startswith("error:")


def test_caps_error_without_evicting_nodes_or_edges(tmp_path, monkeypatch):
    monkeypatch.setattr("aplomado.memory.MAX_NODES", 2)
    monkeypatch.setattr("aplomado.memory.MAX_EDGES", 1)
    _, tools = _tools(tmp_path)
    assert MAX_NODES == 500
    assert MAX_EDGES == 1500

    for key in ("one", "two"):
        output = tools["memory_remember"].invoke({
            "kind": "note",
            "key": key,
            "label": key,
        })
        assert "error:" not in output

    over_cap = tools["memory_remember"].invoke({
        "kind": "note",
        "key": "three",
        "label": "three",
    })
    assert over_cap.startswith("error:")
    assert "cap 2" in over_cap
    assert len(_graph(tmp_path)["nodes"]) == 2

    upsert = tools["memory_remember"].invoke({
        "kind": "note",
        "key": "one",
        "label": "one updated",
    })
    assert "updated node" in upsert
    assert len(_graph(tmp_path)["nodes"]) == 2

    tools["memory_relate"].invoke({
        "source_id": "note:one",
        "relation": "part_of",
        "target_id": "note:two",
    })
    edge_cap = tools["memory_relate"].invoke({
        "source_id": "note:two",
        "relation": "part_of",
        "target_id": "note:one",
    })
    assert edge_cap.startswith("error:")
    assert "cap 1" in edge_cap
    assert len(_graph(tmp_path)["edges"]) == 1


def test_credential_props_are_redacted_and_rule_is_in_prompt_and_tool(tmp_path):
    _, tools = _tools(tmp_path)
    output = tools["memory_remember"].invoke({
        "kind": "credential",
        "key": "alice",
        "label": "alice session",
        "props": {
            "username": "alice",
            "session": "cookie jar scratch/cookies.txt",
            "scope": "read-only profile",
            "password": "not-a-real-secret",
            "api_key": "not-a-real-key",
        },
    })

    assert "error:" not in output
    props = _graph(tmp_path)["nodes"][0]["props"]
    assert props["username"] == "alice"
    assert props["session"] == "cookie jar scratch/cookies.txt"
    assert props["scope"] == "read-only profile"
    assert props["password"] == "[redacted]"
    assert props["api_key"] == "[redacted]"

    description = tools["memory_remember"].description
    assert "Credential nodes" in description
    assert "references only" in description
    assert "never secret values" in description
    assert "redacted" in description

    for prompt in (SYSTEM_PROMPT, BUGHUNTER_SYSTEM_PROMPT):
        assert "Remember as you go" in prompt
        assert "memory_summary" in prompt
        assert "memory_recall" in prompt
        assert "never secret values" in prompt
        assert "SESSION MEMORY GRAPH" in prompt


def test_hypothesis_starts_inferred_and_confirmed_issue_needs_confidence(
    tmp_path,
):
    _, tools = _tools(tmp_path)

    bad_hypothesis = tools["memory_remember"].invoke({
        "kind": "hypothesis",
        "key": "idor on profile",
        "label": "IDOR on profile",
        "confidence": "observed",
    })
    assert bad_hypothesis.startswith("error:")
    assert "confidence=inferred" in bad_hypothesis

    hypothesis = tools["memory_remember"].invoke({
        "kind": "hypothesis",
        "key": "idor on profile",
        "label": "IDOR on profile",
        "confidence": "inferred",
    })
    assert "added node" in hypothesis

    bad_issue = tools["memory_remember"].invoke({
        "kind": "issue",
        "key": "profile idor",
        "label": "Profile IDOR",
        "status": "confirmed",
        "confidence": "observed",
    })
    assert bad_issue.startswith("error:")
    assert "confidence=confirmed" in bad_issue

    issue = tools["memory_remember"].invoke({
        "kind": "issue",
        "key": "profile idor",
        "label": "Profile IDOR",
        "status": "confirmed",
        "confidence": "confirmed",
    })
    assert "added node" in issue
    summary = tools["memory_summary"].invoke({})
    assert "issue:profile idor" in summary
    assert "confirmed issues:" in summary


def test_compaction_summary_does_not_restate_graph_facts():
    assert "session memory graph" in COMPACTION_SUMMARY_PROMPT
    assert "authoritative" in COMPACTION_SUMMARY_PROMPT
    assert "NOT restated" in COMPACTION_SUMMARY_PROMPT
    assert "intent, sequence, and open questions" in COMPACTION_SUMMARY_PROMPT


def test_two_sequential_scans_do_not_share_memory(tmp_path):
    first_sandbox = _sandbox(tmp_path, "scan-a")
    first = run_scan(
        "https://example.com",
        model=ScriptedModel([
            AIMessage(content="", tool_calls=[
                _tc("memory_remember", {
                    "kind": "endpoint",
                    "key": "get:/login",
                    "label": "GET /login",
                }, 1),
            ]),
            _finish("scan a done"),
        ]),
        sandbox=first_sandbox,
        session_store=SessionStore(tmp_path / "sessions-a"),
        log=lambda *args: None,
    )
    assert first["summary"] == "scan a done"
    assert (tmp_path / "scan-a" / MEMORY_PATH).exists()

    second_sandbox = _sandbox(tmp_path, "scan-b")
    second_model = ScriptedModel([
        AIMessage(content="", tool_calls=[
            _tc("memory_summary", {}, 2),
        ]),
        _finish("scan b done"),
    ])
    second = run_scan(
        "https://example.com",
        model=second_model,
        sandbox=second_sandbox,
        session_store=SessionStore(tmp_path / "sessions-b"),
        log=lambda *args: None,
    )

    assert second["summary"] == "scan b done"
    assert not (tmp_path / "scan-b" / MEMORY_PATH).exists()
    summaries = _tool_contents(second_model, "memory_summary")
    assert summaries and "nodes=0 edges=0" in summaries[-1]


def test_subagent_fact_is_recallable_by_the_parent(tmp_path):
    sandbox = _sandbox(tmp_path)
    parent_script = [
        AIMessage(content="", tool_calls=[
            _tc("delegate_task", {
                "task": "remember the login endpoint on example.com",
            }, 1),
        ]),
        AIMessage(content="", tool_calls=[
            _tc("memory_recall", {"query": "login"}, 2),
        ]),
        _finish("parent done"),
    ]
    child_script = [
        AIMessage(content="", tool_calls=[
            _tc("memory_remember", {
                "kind": "endpoint",
                "key": "get:/login",
                "label": "GET /login",
                "props": {"status": 200},
            }, 3),
        ]),
        _finish("child remembered it"),
    ]
    model = ScriptedModel(parent_script, child_script)

    envelope = run_scan(
        "https://example.com",
        model=model,
        sandbox=sandbox,
        session_store=SessionStore(tmp_path / "sessions"),
        log=lambda *args: None,
    )

    assert envelope["summary"] == "parent done"
    assert model.child_calls == 2
    recalls = _tool_contents(model, "memory_recall")
    assert recalls
    assert "endpoint:get:/login" in recalls[-1]
    assert "GET /login" in recalls[-1]
    graph = _graph(tmp_path)
    assert [node["id"] for node in graph["nodes"]] == [
        "endpoint:get:/login"
    ]
