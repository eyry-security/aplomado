"""Prompt-pack controls work without model credentials, Docker, or network."""

from __future__ import annotations

import json

import pytest
from langchain_core.messages import AIMessage

from aplomado.cli import build_parser, main
from aplomado.prompts import (
    DEFAULT_PROMPT_PACK_ID,
    PromptError,
    PromptPack,
    available_prompt_packs,
    build_prompt,
    get_prompt_pack,
    load_prompt_pack,
)
from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore


def test_default_pack_is_named_versioned_and_discoverable():
    pack = get_prompt_pack()
    assert pack.identifier == DEFAULT_PROMPT_PACK_ID == "recon-v1"
    assert get_prompt_pack("default") is pack
    assert available_prompt_packs() == (pack,)


def test_unknown_pack_lists_available_ids():
    with pytest.raises(PromptError, match="recon-v1"):
        get_prompt_pack("missing-v9")


def test_custom_template_renders_documented_tokens_only():
    pack = PromptPack(
        name="focused",
        version=2,
        system_prompt="Use the focused review policy.",
        run_prompt_template=(
            'Review {target}.\n{target_context_block}Keep JSON braces: {"mode": "safe"}'
        ),
    )
    rendered = build_prompt("example.test", "status: 200", pack)
    assert rendered.startswith("Review example.test.\nstatus: 200\n\n")
    assert '{"mode": "safe"}' in rendered


def test_target_text_cannot_expand_context_token():
    pack = get_prompt_pack()
    rendered = pack.render("literal-{target_context_block}", "PRIVATE CONTEXT")
    assert "TARGET: literal-{target_context_block}" in rendered
    assert rendered.count("PRIVATE CONTEXT") == 1


def test_template_requires_target_token():
    with pytest.raises(PromptError, match=r"must contain \{target\}"):
        PromptPack(
            name="broken",
            version=1,
            system_prompt="system",
            run_prompt_template="No target token here",
        )


def test_file_overrides_are_loaded_and_identified(tmp_path):
    system_file = tmp_path / "system.txt"
    run_file = tmp_path / "run.txt"
    system_file.write_text("Custom system policy.\n", encoding="utf-8")
    run_file.write_text("Inspect {target}.\n{target_context_block}Finish.", encoding="utf-8")

    pack = load_prompt_pack(
        "recon-v1",
        system_prompt_file=str(system_file),
        run_prompt_file=str(run_file),
    )
    assert pack.identifier == "recon-v1+system+run"
    assert pack.system_prompt == "Custom system policy.\n"
    assert build_prompt("host.test", "context", pack) == (
        "Inspect host.test.\ncontext\n\nFinish."
    )


def test_missing_empty_and_invalid_override_files_fail_cleanly(tmp_path):
    with pytest.raises(PromptError, match="cannot read system prompt file"):
        load_prompt_pack(system_prompt_file=str(tmp_path / "missing.txt"))

    empty = tmp_path / "empty.txt"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(PromptError, match="is empty"):
        load_prompt_pack(system_prompt_file=str(empty))

    invalid = tmp_path / "invalid.txt"
    invalid.write_text("Inspect something else", encoding="utf-8")
    with pytest.raises(PromptError, match=r"must contain \{target\}"):
        load_prompt_pack(run_prompt_file=str(invalid))


class SpyModel:
    def __init__(self):
        self.messages = None

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.messages = list(messages)
        return AIMessage(content="review complete")


def test_run_scan_uses_custom_system_and_run_prompts(tmp_path):
    model = SpyModel()
    pack = PromptPack(
        name="focused",
        version=3,
        system_prompt="CUSTOM SYSTEM",
        run_prompt_template="CUSTOM RUN {target}\n{target_context_block}DONE",
    )
    run_scan(
        "example.test",
        target_context="CONTEXT",
        prompt_pack=pack,
        model=model,
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
    )
    assert model.messages[0].content == "CUSTOM SYSTEM"
    assert model.messages[-1].content == "CUSTOM RUN example.test\nCONTEXT\n\nDONE"


def test_scan_parser_exposes_prompt_controls():
    args = build_parser().parse_args(
        [
            "scan",
            "--target",
            "example.test",
            "--prompt-pack",
            "recon-v1",
            "--system-prompt-file",
            "system.txt",
            "--run-prompt-file",
            "run.txt",
        ]
    )
    assert args.prompt_pack == "recon-v1"
    assert args.system_prompt_file == "system.txt"
    assert args.run_prompt_file == "run.txt"


def test_prompts_command_lists_and_displays_full_pack(capsys):
    assert main(["prompts"]) == 0
    assert capsys.readouterr().out.strip() == "recon-v1 (default)"

    assert main(["prompts", "--pack", "recon-v1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["id"] == "recon-v1"
    assert "SCOPE" in payload["system_prompt"]
    assert "{target}" in payload["run_prompt_template"]


def test_scan_rejects_unknown_pack_before_starting_sandbox(capsys):
    assert main(
        ["scan", "--target", "example.test", "--prompt-pack", "unknown-v1"]
    ) == 2
    assert "unknown prompt pack" in capsys.readouterr().err
