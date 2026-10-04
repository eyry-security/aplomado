"""Findings normalization edge cases. No network, no Docker, no API keys."""

from datetime import datetime, timezone

from aplomado.findings import (
    SEVERITIES,
    coerce_severity,
    normalize_finding,
    normalize_findings,
)


def test_full_payload_round_trips():
    payload = {
        "target": "https://example.com",
        "summary": "Solid, one nit.",
        "scanned_at": "2026-10-03T16:00:00+00:00",
        "findings": [
            {
                "severity": "low",
                "title": "Server header leaks version",
                "detail": "nginx/1.25.3 exposed",
                "evidence": "Server: nginx/1.25.3",
            }
        ],
    }
    env = normalize_findings(payload, "https://example.com")
    assert env["target"] == payload["target"]
    assert env["summary"] == payload["summary"]
    assert env["scanned_at"] == payload["scanned_at"]
    assert len(env["findings"]) == 1
    f = env["findings"][0]
    assert f["severity"] == "low"
    assert f["title"] == "Server header leaks version"
    assert "id" in f  # deterministic finding ID


def test_defaults_filled():
    env = normalize_findings({}, "example.com")
    assert env["target"] == "example.com"
    assert env["summary"] == ""
    assert env["findings"] == []
    # scanned_at defaults to now, in ISO-8601
    datetime.fromisoformat(env["scanned_at"])


def test_target_argument_is_authoritative():
    env = normalize_findings({"target": "https://a.example"}, "https://b.example")
    assert env["target"] == "https://b.example"


def test_severity_coercion():
    for raw, want in [
        ("critical", "critical"), ("CRITICAL", "critical"), (" Critical ", "critical"),
        ("crit", "critical"), ("HIGH", "high"), ("med", "medium"),
        ("Moderate", "medium"), ("low", "low"), ("LOW", "low"),
        ("info", "info"), ("Informational", "info"), ("none", "info"),
        ("bogus", "info"), ("", "info"), (None, "info"), (5, "info"),
    ]:
        assert coerce_severity(raw) == want, raw


def test_severity_set_is_stable():
    assert SEVERITIES == ("critical", "high", "medium", "low", "info")


def test_finding_item_defaults_and_coercion():
    f = normalize_finding({"severity": "HIGH"})
    assert f["severity"] == "high"
    assert f["title"] == ""
    assert f["detail"] == ""
    assert f["evidence"] == ""
    f = normalize_finding({"severity": "nope", "title": 42, "detail": None})
    assert f["severity"] == "info"
    assert f["title"] == "42"
    assert f["detail"] == ""


def test_string_item_becomes_title():
    f = normalize_finding("robots.txt is world-readable")
    assert f["title"] == "robots.txt is world-readable"
    assert f["severity"] == "info"


def test_non_dict_items_skipped():
    assert normalize_finding(42) is None
    assert normalize_finding(None) is None
    assert normalize_finding(["x"]) is None
    env = normalize_findings({"findings": ["ok title", 42, None, {"title": "real"}]})
    assert [f["title"] for f in env["findings"]] == ["ok title", "real"]


def test_json_string_payload_parses():
    env = normalize_findings(
        '{"summary": "fine", "findings": [{"severity": "low", "title": "t"}]}',
        "example.com",
    )
    assert env["summary"] == "fine"
    assert env["findings"][0]["severity"] == "low"


def test_garbage_string_becomes_summary():
    env = normalize_findings("the model just rambled", "example.com")
    assert env["summary"] == "the model just rambled"
    assert env["findings"] == []
    assert env["target"] == "example.com"


def test_list_payload_is_bare_findings_array():
    env = normalize_findings([{"severity": "HIGH", "title": "t"}], "example.com")
    assert len(env["findings"]) == 1
    f = env["findings"][0]
    assert f["severity"] == "high"
    assert f["title"] == "t"
    assert f["detail"] == ""
    assert f["evidence"] == ""
    assert "id" in f


def test_single_finding_object_wrapped():
    env = normalize_findings(
        {"findings": {"severity": "low", "title": "t"}}, "example.com"
    )
    assert len(env["findings"]) == 1
    assert env["findings"][0]["title"] == "t"


def test_findings_not_a_list_or_dict_gives_empty():
    for raw in ["nope", 42, None]:
        env = normalize_findings({"findings": raw}, "example.com")
        assert env["findings"] == [], raw


def test_none_payload():
    env = normalize_findings(None, "example.com")
    assert env == {
        "target": "example.com",
        "summary": "",
        "scanned_at": env["scanned_at"],
        "findings": [],
    }


def test_scanned_at_validation():
    env = normalize_findings({"scanned_at": "not a date"}, "example.com")
    datetime.fromisoformat(env["scanned_at"])  # replaced with now
    env = normalize_findings({"scanned_at": "2026-10-03T16:00:00Z"}, "example.com")
    assert env["scanned_at"] == "2026-10-03T16:00:00Z"  # kept as given
    env = normalize_findings({}, "example.com", scanned_at="2026-01-01T00:00:00Z")
    assert env["scanned_at"] == "2026-01-01T00:00:00Z"  # explicit override wins


def test_never_crashes_on_weird_input():
    weird = [
        0, 3.14, True, b"bytes", object(),
        {"findings": [{"severity": {"nested": 1}}]},
        {"summary": ["not", "a", "string"]},
        {"target": None, "findings": [[["deep"]]]},
    ]
    for w in weird:
        env = normalize_findings(w, "example.com")
        assert {"target", "summary", "scanned_at", "findings"} <= set(env)
        assert all(s in SEVERITIES for s in (f["severity"] for f in env["findings"]))
        datetime.fromisoformat(env["scanned_at"])


def test_scanned_at_now_is_recent():
    before = datetime.now(timezone.utc)
    env = normalize_findings({}, "example.com")
    after = datetime.now(timezone.utc)
    ts = datetime.fromisoformat(env["scanned_at"])
    assert before <= ts <= after
