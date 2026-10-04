"""Tests for store.py — no Postgres, no Docker, no API keys."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from aplomado.store import NullStore, RuttStore, resolve_store


# -- NullStore ----------------------------------------------------------------

def test_null_store_save_is_noop():
    store = NullStore()
    store.save({"target": "example.com", "findings": []})  # should not raise
    store.close()


# -- resolve_store ------------------------------------------------------------

def test_resolve_store_returns_null_when_no_dsn():
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("RUTT_DSN", None)
        os.environ.pop("DATABASE_URL", None)
        store = resolve_store(None)
    assert isinstance(store, NullStore)


def test_resolve_store_explicit_dsn():
    with patch("aplomado.store.RuttStore") as mock_cls:
        mock_cls.return_value = MagicMock()
        store = resolve_store("postgresql:///test")
        mock_cls.assert_called_once_with("postgresql:///test")


def test_resolve_store_env_rutt_dsn():
    with patch.dict(os.environ, {"RUTT_DSN": "postgresql:///from-env"}):
        with patch("aplomado.store.RuttStore") as mock_cls:
            mock_cls.return_value = MagicMock()
            store = resolve_store(None)
            mock_cls.assert_called_once_with("postgresql:///from-env")


def test_resolve_store_env_database_url_fallback():
    with patch.dict(os.environ, {"DATABASE_URL": "postgresql:///fallback"}, clear=False):
        env = os.environ.copy()
        env.pop("RUTT_DSN", None)
        with patch.dict(os.environ, env, clear=True):
            with patch("aplomado.store.RuttStore") as mock_cls:
                mock_cls.return_value = MagicMock()
                store = resolve_store(None)
                mock_cls.assert_called_once_with("postgresql:///fallback")


# -- RuttStore (mocked Rutt) --------------------------------------------------

def _mock_rutt_module():
    """Patch the rutt import inside RuttStore.__init__."""
    mock_rutt_instance = MagicMock()
    mock_rutt_cls = MagicMock(return_value=mock_rutt_instance)
    return mock_rutt_cls, mock_rutt_instance


def test_rutt_store_save_with_findings():
    mock_cls, mock_rutt = _mock_rutt_module()
    with patch.dict("sys.modules", {"rutt": MagicMock(Rutt=mock_cls)}):
        store = RuttStore("postgresql:///test")

    envelope = {
        "target": "example.com",
        "summary": "Found issues.",
        "scanned_at": "2026-10-04T00:00:00Z",
        "findings": [
            {
                "severity": "high",
                "title": "Exposed .git",
                "detail": ".git/HEAD accessible",
                "evidence": "HTTP 200 on /.git/HEAD",
            },
            {
                "severity": "low",
                "title": "Missing HSTS",
                "detail": "No Strict-Transport-Security header",
                "evidence": "",
            },
        ],
    }
    store.save(envelope)

    assert mock_rutt.add_finding.call_count == 2
    call1 = mock_rutt.add_finding.call_args_list[0]
    assert call1[0][0] == "Exposed .git"  # title positional
    assert call1[1]["host"] == "example.com"
    assert call1[1]["severity"] == "high"
    assert call1[1]["source"] == "aplomado"
    assert "evidence" in call1[1]["data"]

    # review() should NOT be called when findings exist
    mock_rutt.review.assert_not_called()


def test_rutt_store_save_no_findings_records_review():
    mock_cls, mock_rutt = _mock_rutt_module()
    with patch.dict("sys.modules", {"rutt": MagicMock(Rutt=mock_cls)}):
        store = RuttStore("postgresql:///test")

    envelope = {
        "target": "clean.example.com",
        "summary": "Nothing found.",
        "scanned_at": "2026-10-04T00:00:00Z",
        "findings": [],
    }
    store.save(envelope)

    mock_rutt.add_finding.assert_not_called()
    mock_rutt.review.assert_called_once_with(
        "clean.example.com",
        tool="aplomado",
        detail={"summary": "Nothing found."},
    )


def test_rutt_store_close():
    mock_cls, mock_rutt = _mock_rutt_module()
    with patch.dict("sys.modules", {"rutt": MagicMock(Rutt=mock_cls)}):
        store = RuttStore("postgresql:///test")
    store.close()
    mock_rutt.close.assert_called_once()


def test_rutt_store_import_error():
    """RuttStore raises RuntimeError when rutt is not installed."""
    with patch.dict("sys.modules", {"rutt": None}):
        with pytest.raises(RuntimeError, match="rutt is not installed"):
            RuttStore("postgresql:///test")
