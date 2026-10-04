"""Tests for Aplomado's installed wordlist pack."""

from __future__ import annotations

import json

import pytest

from aplomado import get_wordlist, list_wordlists, read_wordlist
from aplomado.cli import main


EXPECTED_NAMES = (
    "common-paths",
    "api-routes",
    "parameters",
    "virtual-hosts",
)


def test_catalog_is_stable_and_has_all_discovery_kinds():
    catalog = list_wordlists()

    assert tuple(item.name for item in catalog) == EXPECTED_NAMES
    assert {item.kind for item in catalog} == {"content", "parameter", "vhost"}
    assert all(item.description for item in catalog)


@pytest.mark.parametrize("name", EXPECTED_NAMES)
def test_bundled_lists_are_clean_unique_and_ready_for_tools(name):
    text = read_wordlist(name)
    entries = get_wordlist(name).entries()

    assert text.endswith("\n")
    assert len(entries) >= 50
    assert len(entries) == len(set(entries))
    assert all(entry == entry.strip() for entry in entries)
    assert all(not entry.startswith("#") for entry in entries)
    assert "\x00" not in text


def test_lookup_normalizes_logical_names_only():
    assert get_wordlist("  COMMON-PATHS ").name == "common-paths"

    with pytest.raises(ValueError, match="unknown wordlist"):
        get_wordlist("../common-paths.txt")
    with pytest.raises(ValueError, match="unknown wordlist"):
        get_wordlist("common-paths.txt")


def test_metadata_is_json_friendly_and_matches_content():
    item = get_wordlist("parameters")
    metadata = item.as_dict()

    assert metadata == {
        "name": "parameters",
        "kind": "parameter",
        "description": "Common query and form parameter names.",
        "entries": len(item.entries()),
    }
    json.dumps(metadata)


def test_cli_lists_catalog(capsys):
    assert main(["wordlists"]) == 0

    output = capsys.readouterr().out
    assert "common-paths" in output
    assert "virtual-hosts" in output
    assert "content" in output


def test_cli_lists_catalog_as_json(capsys):
    assert main(["wordlists", "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert [item["name"] for item in payload] == list(EXPECTED_NAMES)
    assert all(item["entries"] >= 50 for item in payload)


def test_cli_prints_raw_list_for_pipes(capsys):
    assert main(["wordlists", "common-paths"]) == 0

    output = capsys.readouterr().out
    assert output == read_wordlist("common-paths")
    assert "admin\n" in output


def test_cli_rejects_unknown_name_without_traceback(capsys):
    assert main(["wordlists", "missing"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unknown wordlist 'missing'" in captured.err
