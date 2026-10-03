"""Findings schema and normalization.

This is the shared findings envelope that seeds the Eyry suite's schema
(vedette prober output in, aplomado findings out):

    {
        "target": str,       # what was scanned (host or URL)
        "summary": str,      # one-paragraph overall verdict
        "scanned_at": str,   # ISO-8601 timestamp of the scan
        "findings": [        # list of finding objects
            {
                "severity": "critical" | "high" | "medium" | "low" | "info",
                "title": str,    # one line, e.g. "Server header leaks version"
                "detail": str,   # what it is and why it matters
                "evidence": str, # the observed output backing it up
            }
        ],
    }

normalize_findings() turns whatever a model handed to finish() into a valid
envelope. It never raises: severities are coerced (unknown -> "info"),
missing fields get defaults, and garbage input becomes an envelope with no
findings and a summary saying what happened.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

SEVERITIES = ("critical", "high", "medium", "low", "info")

_SEVERITY_ALIASES = {
    "crit": "critical",
    "med": "medium",
    "moderate": "medium",
    "informational": "info",
    "none": "info",
}


def coerce_severity(value: object) -> str:
    """Map anything to a valid severity; unknown -> "info"."""
    s = str(value or "").strip().lower()
    if s in SEVERITIES:
        return s
    return _SEVERITY_ALIASES.get(s, "info")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _valid_iso(value: object) -> str | None:
    """Return the value if it parses as ISO-8601, else None."""
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    # datetime.fromisoformat only learned "Z" in 3.11; support 3.10 too.
    candidate = v[:-1] + "+00:00" if v.endswith(("Z", "z")) else v
    try:
        datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return v


def _as_str(value: object) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def normalize_finding(item: object) -> dict | None:
    """Coerce one finding into the schema; None when the item is unusable."""
    if isinstance(item, str):
        item = {"title": item}
    if not isinstance(item, dict):
        return None
    return {
        "severity": coerce_severity(item.get("severity")),
        "title": _as_str(item.get("title")),
        "detail": _as_str(item.get("detail")),
        "evidence": _as_str(item.get("evidence")),
    }


def normalize_findings(
    payload: object, target: str = "", *, scanned_at: str | None = None
) -> dict:
    """Build a valid findings envelope from arbitrary model output.

    Never raises: a dict goes through field-by-field, a list is treated as a
    bare findings array, a JSON string is parsed, a non-JSON string becomes
    the summary, and anything else yields an empty-findings envelope.
    """
    summary = ""
    raw_findings: list = []
    payload_target = ""

    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            summary = payload  # not JSON: keep the text as the summary
            payload = None

    if isinstance(payload, list):
        raw_findings = payload  # model skipped the envelope, gave the array
    elif isinstance(payload, dict):
        summary = _as_str(payload.get("summary", summary))
        payload_target = _as_str(payload.get("target"))
        raw = payload.get("findings", [])
        if isinstance(raw, dict):
            raw_findings = [raw]  # one bare finding object instead of an array
        elif isinstance(raw, (list, tuple)):
            raw_findings = list(raw)
        # anything else -> no findings
    elif payload is not None:
        summary = _as_str(payload)

    findings = [
        f for f in (normalize_finding(i) for i in raw_findings) if f is not None
    ]

    return {
        "target": payload_target or _as_str(target),
        "summary": summary,
        "scanned_at": scanned_at
        or _valid_iso(payload.get("scanned_at") if isinstance(payload, dict) else None)
        or _now_iso(),
        "findings": findings,
    }
