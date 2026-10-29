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
                "summary": str,  # plain-language what + where
                "reproduction_steps": [str],  # ordered, unnumbered steps
                "impact": str,   # attacker gain + business consequence
                "evidence": [    # verbatim proof excerpts
                    {"kind": "request_response|tool_output|note",
                     "label": str, "content": str}
                ],
            }
        ],
    }

normalize_findings() turns whatever a model handed to finish() into a valid
envelope. It never raises: severities are coerced (unknown -> "info"),
missing fields get defaults, and garbage input becomes an envelope with no
findings and a summary saying what happened.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .schema import (
    SEVERITIES,
    VULN_CLASSES,
    Finding,
    _as_evidence,
    _as_repro,
    coerce_severity,
    coerce_vuln_class,
    validate_finding as _validate_model_finding,
)


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


def _evidence_fingerprint(evidence: object) -> str:
    """Turn legacy or structured evidence into a stable identity string."""
    if isinstance(evidence, str):
        return evidence
    if isinstance(evidence, (list, tuple)):
        return json.dumps(
            evidence,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    return str(evidence)


def finding_id(target: str, title: str, evidence: object) -> str:
    """Return a stable SHA-256 ID for target, finding title, and evidence.

    Compact JSON gives unambiguous component boundaries even when text contains
    delimiters. Display-only and model-supplied IDs are intentionally ignored.
    Structured evidence is fingerprinted canonically so re-scans dedupe.
    """
    payload = json.dumps(
        [str(target), str(title), _evidence_fingerprint(evidence)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_finding(item: object) -> dict | None:
    """Coerce one finding into the schema; None when the item is unusable."""
    if isinstance(item, str):
        item = {"title": item}
    if not isinstance(item, dict):
        return None
    detail = _as_str(item.get("detail"))
    summary = item.get("summary")
    impact = item.get("impact")
    steps = (
        item.get("reproduction_steps")
        or item.get("reproduction")
        or item.get("repro")
        or item.get("steps")
        or []
    )
    result = {
        "severity": coerce_severity(item.get("severity")),
        "title": _as_str(item.get("title")),
        "detail": detail,
        "summary": (summary if isinstance(summary, str) else "") or detail,
        "reproduction_steps": _as_repro(steps),
        "impact": impact if isinstance(impact, str) else "",
        "evidence": _as_evidence(item.get("evidence")),
    }
    # Preserve unknown fields from the model (confidence, remediation, etc.)
    for key, value in item.items():
        if key not in result:
            result[key] = value
    return result


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

    # The agent's output is untrusted: every item must validate as a Finding
    # model before it is stored. Malformed items are dropped here.
    findings = []
    dropped = 0
    for item in raw_findings:
        f = _validate_model_finding(item)
        if f is None:
            dropped += 1
            continue
        # Fill endpoint context from the authoritative scan target when the
        # model omitted it. The target argument still wins below.
        if not f.get("host"):
            f["host"] = _as_str(target) or payload_target
        if not f.get("url"):
            f["url"] = _as_str(target) or payload_target
        if not f.get("endpoint"):
            f["endpoint"] = f.get("url") or _as_str(target) or payload_target
        findings.append(f)

    # The caller-owned scan target is authoritative. Model output must not
    # change finding identity or redirect downstream lifecycle records.
    resolved_target = _as_str(target) or payload_target

    # Stamp each finding with a deterministic ID.
    for f in findings:
        f["id"] = finding_id(resolved_target, f["title"], f.get("evidence", ""))

    envelope = {
        "target": resolved_target,
        "summary": summary,
        "scanned_at": scanned_at
        or _valid_iso(payload.get("scanned_at") if isinstance(payload, dict) else None)
        or _now_iso(),
        "findings": findings,
    }
    if dropped:
        envelope["findings_dropped"] = dropped
    return envelope
