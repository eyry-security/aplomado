"""Default model resolution and wiring, without credentials or network."""

from types import SimpleNamespace

from aplomado.cli import cmd_config
from aplomado.models import DEFAULT_MODEL, resolve_model
from aplomado.scanner import run_scan
from pinnace import LocalSandbox
from pinnace.session import SessionStore


def test_default_model_is_deepseek_flash(monkeypatch):
    monkeypatch.delenv("PINNACE_MODEL", raising=False)
    assert DEFAULT_MODEL == "deepseek:deepseek-flash"
    assert resolve_model() == "deepseek:deepseek-flash"


def test_explicit_and_environment_models_still_win(monkeypatch):
    monkeypatch.setenv("PINNACE_MODEL", "anthropic:claude-sonnet-4-5")
    assert resolve_model() == "anthropic:claude-sonnet-4-5"
    assert (
        resolve_model("deepseek:deepseek-v4-pro")
        == "deepseek:deepseek-v4-pro"
    )


def test_cli_config_reports_deepseek_default(monkeypatch, capsys):
    monkeypatch.delenv("PINNACE_MODEL", raising=False)
    assert cmd_config(None) == 0
    assert "deepseek:deepseek-flash" in capsys.readouterr().out


def test_run_scan_resolves_deepseek_default_without_network(tmp_path, monkeypatch):
    monkeypatch.delenv("PINNACE_MODEL", raising=False)
    captured = {}

    class StubAgent:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run(self, prompt):
            return SimpleNamespace(
                finished=False,
                structured=None,
                final="ready",
            )

    monkeypatch.setattr("aplomado.scanner.PinnaceAgent", StubAgent)
    envelope = run_scan(
        "example.com",
        sandbox=LocalSandbox(str(tmp_path / "work"), unsafe_ok=True),
        session_store=SessionStore(tmp_path / "sessions"),
        log=lambda *args: None,
    )

    assert captured["model"] == "deepseek:deepseek-flash"
    assert envelope["summary"] == "ready"
