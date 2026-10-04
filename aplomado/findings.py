"""Stable input/output models for Aplomado scans."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
CONFIDENCES = frozenset({"low", "medium", "high", "confirmed"})


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    description: str
    evidence: str
    remediation: str = ""
    confidence: str = "medium"
    references: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Finding":
        severity = str(value.get("severity", "")).lower()
        confidence = str(value.get("confidence", "medium")).lower()
        if severity not in SEVERITIES:
            raise ValueError(f"invalid finding severity: {severity!r}")
        if confidence not in CONFIDENCES:
            raise ValueError(f"invalid finding confidence: {confidence!r}")
        required = {name: str(value.get(name, "")).strip()
                    for name in ("title", "description", "evidence")}
        missing = [name for name, item in required.items() if not item]
        if missing:
            raise ValueError(f"finding missing {', '.join(missing)}")
        refs = value.get("references") or []
        if not isinstance(refs, list):
            raise ValueError("finding references must be a list")
        return cls(
            **required,
            severity=severity,
            remediation=str(value.get("remediation", "")).strip(),
            confidence=confidence,
            references=tuple(str(ref) for ref in refs),
        )

    @property
    def fingerprint(self) -> str:
        value = f"{self.title.lower()}\0{self.evidence.lower()}".encode()
        return hashlib.sha256(value).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["references"] = list(self.references)
        value["fingerprint"] = self.fingerprint
        return value


@dataclass
class ScanResult:
    target: str
    ok: bool
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "ok": self.ok,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "error": self.error,
            "metadata": self.metadata,
        }


def parse_agent_result(target: str, text: str, max_findings: int) -> ScanResult:
    """Parse the strict JSON object requested from the agent."""
    raw = text.strip()
    if raw.startswith("```") and raw.endswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(lines[1:-1]).strip()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return ScanResult(target, False, error=f"agent returned invalid JSON: {exc.msg}",
                          metadata={"raw_response": text})
    if not isinstance(payload, dict):
        return ScanResult(target, False, error="agent result must be a JSON object")

    findings: list[Finding] = []
    seen: set[str] = set()
    rejected: list[str] = []
    values = payload.get("findings", [])
    if not isinstance(values, list):
        return ScanResult(target, False, error="agent findings must be a JSON array")
    for index, value in enumerate(values):
        if len(findings) >= max_findings:
            break
        try:
            if not isinstance(value, dict):
                raise ValueError("finding must be an object")
            finding = Finding.from_dict(value)
        except ValueError as exc:
            rejected.append(f"finding {index}: {exc}")
            continue
        if finding.fingerprint not in seen:
            findings.append(finding)
            seen.add(finding.fingerprint)

    metadata: dict[str, Any] = {}
    if rejected:
        metadata["rejected_findings"] = rejected
    if len(values) > max_findings:
        metadata["findings_truncated"] = len(values) - max_findings
    return ScanResult(target, True, str(payload.get("summary", "")).strip(),
                      findings=findings, metadata=metadata)
