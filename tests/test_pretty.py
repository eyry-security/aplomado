"""Tests for pretty terminal output."""

import io
import sys

import pytest

from aplomado.pretty import color, colorize_log, severity_tag


@pytest.fixture()
def no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.fixture()
def force_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)


def test_color_plain_when_no_color(no_color):
    assert color("hi", "red") == "hi"


def test_color_plain_when_piped(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    assert color("hi", "red") == "hi"


def test_color_wraps_when_tty(force_color):
    out = color("hi", "red")
    assert out.startswith("\033[31m") and out.endswith("\033[0m")
    assert "hi" in out


def test_severity_tag_colors(force_color):
    assert "\033[31m" in severity_tag("critical")  # red
    assert "\033[31m" in severity_tag("high")  # red
    assert "\033[33m" in severity_tag("medium")  # yellow
    assert "[CRITICAL]" in severity_tag("critical")


def test_severity_tag_plain(no_color):
    assert severity_tag("high") == "[HIGH]"


def test_colorize_log_highlights_pinnace(force_color):
    out = colorize_log("[pinnace] turn 1, calling model…")
    assert "\033[" in out  # some color applied
    assert "[pinnace]" in out


def test_colorize_log_plain_without_marker(no_color):
    assert colorize_log("just a message") == "just a message"


def test_colorize_log_tool_highlight(force_color):
    out = colorize_log("[pinnace] tool: shell({'command': 'x'})")
    assert "\033[33m" in out  # yellow for tool:
