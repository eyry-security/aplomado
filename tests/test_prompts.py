"""Tests for prompts.py — prompt content and build_prompt helper."""

from aplomado.prompts import SYSTEM_PROMPT, build_prompt


def test_system_prompt_has_key_sections():
    assert "SCOPE" in SYSTEM_PROMPT
    assert "YOUR TOOLS" in SYSTEM_PROMPT
    assert "RECON PLAYBOOK" in SYSTEM_PROMPT
    assert "FINISH FORMAT" in SYSTEM_PROMPT
    assert "finish()" in SYSTEM_PROMPT
    assert "severity" in SYSTEM_PROMPT


def test_system_prompt_mentions_all_tools():
    for tool in ("shell", "fetch_url", "read_file", "write_file", "finish"):
        assert tool in SYSTEM_PROMPT


def test_system_prompt_has_severity_levels():
    for level in ("critical", "high", "medium", "low", "info"):
        assert level in SYSTEM_PROMPT


def test_build_prompt_basic():
    prompt = build_prompt("https://example.com")
    assert "TARGET: https://example.com" in prompt
    assert "finish()" in prompt


def test_build_prompt_with_context():
    prompt = build_prompt("https://example.com", "some vedette context")
    assert "TARGET: https://example.com" in prompt
    assert "some vedette context" in prompt
    assert "finish()" in prompt


def test_build_prompt_pins_agent_to_the_assigned_host():
    target = "https://blog.example.com"
    prompt = build_prompt(target)
    assert "HOST DISCIPLINE" in prompt
    assert f"The assigned host — {target} — is the ONLY target" in prompt
    assert "are CONTEXT ONLY" in prompt
    assert "never test them and never file findings about them" in prompt
    assert "every finding's host is the assigned host" in prompt
    assert "do not follow the trail onto other hosts" in prompt
    discipline = prompt.split("HOST DISCIPLINE", 1)[1]
    assert target in discipline


def test_bughunter_build_prompt_pins_agent_to_the_assigned_host():
    from aplomado.prompts import get_prompt_pack

    target = "https://shop.example.com"
    prompt = build_prompt(target, prompt_pack=get_prompt_pack("bughunter-v1"))
    assert "HOST DISCIPLINE" in prompt
    assert f"The assigned host — {target} — is the ONLY target" in prompt
    assert "every finding's host is the assigned host" in prompt


def test_subagent_prompt_keeps_the_parent_host_in_scope():
    from aplomado.subagents import _child_prompt

    prompt = _child_prompt("check headers", "context")
    assert "host assigned to the parent target" in prompt
    assert "never test them or file findings about them" in prompt


def test_build_prompt_without_context_has_no_blank_block():
    prompt = build_prompt("https://example.com")
    # Should have exactly two parts: TARGET line and the investigate instruction
    assert prompt.count("\n\n") == 1


def test_finish_format_instructs_structured_findings():
    from aplomado.prompts import BUGHUNTER_SYSTEM_PROMPT

    for prompt in (SYSTEM_PROMPT, BUGHUNTER_SYSTEM_PROMPT):
        assert '"summary": "<plain-language what and where>"' in prompt
        assert '"reproduction_steps"' in prompt
        assert '"impact": "<attacker gain and the business consequence>"' in prompt
        assert '"kind": "request_response|tool_output|note"' in prompt
        assert "verbatim" in prompt
        assert "business terms" in prompt
        assert "follow cold" in prompt
