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


def test_build_prompt_without_context_has_no_blank_block():
    prompt = build_prompt("https://example.com")
    # Should have exactly two parts: TARGET line and the investigate instruction
    assert prompt.count("\n\n") == 1
