"""Validated finding models shared by the scanner and downstream ingestion.

The agent's findings are untrusted model output. Everything that leaves the
scan loop passes through these Pydantic models first; malformed items are
rejected rather than written as raw dictionaries.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SEVERITIES = ("critical", "high", "medium", "low", "info")
VULN_CLASSES = ("sqli", "xss", "lfi", "rce", "auth-bypass", "other")

_SEVERITY_ALIASES = {
    "crit": "critical",
    "med": "medium",
    "moderate": "medium",
    "informational": "info",
    "none": "info",
}

_VULN_ALIASES = {
    "sql": "sqli",
    "sqlinjection": "sqli",
    "sql-injection": "sqli",
    "sql injection": "sqli",
    "cross-site-scripting": "xss",
    "cross site scripting": "xss",
    "local-file-inclusion": "lfi",
    "local file inclusion": "lfi",
    "path-traversal": "lfi",
    "remote-code-execution": "rce",
    "command-injection": "rce",
    "os-command-injection": "rce",
    "authbypass": "auth-bypass",
    "auth_bypass": "auth-bypass",
    "auth bypass": "auth-bypass",
    "authentication-bypass": "auth-bypass",
    "authentication bypass": "auth-bypass",
    "access-control": "auth-bypass",
    "idor": "auth-bypass",
}


def coerce_severity(value: object) -> str:
    """Map anything to a valid severity; unknown -> "info"."""
    s = str(value or "").strip().lower()
    if s in SEVERITIES:
        return s
    return _SEVERITY_ALIASES.get(s, "info")


def coerce_vuln_class(value: object) -> str:
    """Map anything to a valid vulnerability class; unknown -> "other"."""
    s = str(value or "").strip().lower()
    if s in VULN_CLASSES:
        return s
    return _VULN_ALIASES.get(s, "other")


def _as_str(value: object) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _as_repro(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        steps = [_as_str(step).strip() for step in value if _as_str(step).strip()]
    elif isinstance(value, str):
        steps = [line.strip() for line in value.splitlines() if line.strip()]
    else:
        steps = []
    return steps


class Finding(BaseModel):
    """One evidence-backed finding emitted by the AI scanner."""

    model_config = ConfigDict(extra="allow")

    title: str = ""
    severity: str = "info"
    host: str = ""
    url: str = ""
    endpoint: str = ""
    parameter: str = ""
    vuln_class: str = "other"
    summary: str = ""
    repro: list[str] = Field(default_factory=list)
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    detail: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, value: object) -> str:
        return coerce_severity(value)

    @field_validator("vuln_class", mode="before")
    @classmethod
    def _vuln_class(cls, value: object) -> str:
        return coerce_vuln_class(value)

    @field_validator("repro", mode="before")
    @classmethod
    def _repro(cls, value: object) -> list[str]:
        return _as_repro(value)

    @field_validator(
        "title",
        "host",
        "url",
        "endpoint",
        "parameter",
        "summary",
        "evidence",
        "impact",
        "remediation",
        "detail",
        mode="before",
    )
    @classmethod
    def _strings(cls, value: object) -> str:
        return _as_str(value)


def validate_finding(item: object, *, require_title: bool = True) -> dict | None:
    """Validate one model-supplied finding; None when it is unusable.

    Strings are accepted as a bare title for backwards compatibility with the
    older finish() shape. Non-dict/non-string items are dropped.
    """
    if isinstance(item, str):
        item = {"title": item}
    if not isinstance(item, dict) or not item:
        return None
    payload = dict(item)
    # Accept the common model aliases for the structured-output fields.
    if not payload.get("url"):
        payload["url"] = payload.get("endpoint") or payload.get("uri") or ""
    if not payload.get("endpoint"):
        payload["endpoint"] = payload.get("url") or ""
    if not payload.get("vuln_class"):
        payload["vuln_class"] = (
            payload.get("vulnClass")
            or payload.get("vulnerability_class")
            or payload.get("vuln_type")
            or ""
        )
    if not payload.get("repro"):
        payload["repro"] = (
            payload.get("reproduction") or payload.get("steps") or []
        )
    try:
        finding = Finding.model_validate(payload)
    except Exception:  # noqa: BLE001 - validation failure means drop
        return None
    if require_title and not finding.title.strip():
        return None
    return finding.model_dump()


class FindingEnvelope(BaseModel):
    """Top-level finish() payload validated before it is stored."""

    model_config = ConfigDict(extra="allow")

    target: str = ""
    summary: str = ""
    findings: list[Finding] = Field(default_factory=list)

    @field_validator("target", "summary", mode="before")
    @classmethod
    def _strings(cls, value: object) -> str:
        return _as_str(value)
