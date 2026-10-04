"""Optional persistence of validated scan results to Rutt."""

from __future__ import annotations

from typing import Protocol

from .findings import ScanResult


class FindingStore(Protocol):
    def save(self, result: ScanResult) -> None: ...
    def close(self) -> None: ...


class NullStore:
    def save(self, result: ScanResult) -> None:
        return None

    def close(self) -> None:
        return None


class RuttStore:
    """Thin adapter over Rutt's public lifecycle API.

    Rutt is imported lazily so standalone scans do not require that sibling
    package. The caller must initialize Rutt's schema before scanning.
    """

    def __init__(self, dsn: str) -> None:
        try:
            from rutt import Rutt
        except ImportError as exc:
            raise RuntimeError("Rutt persistence requested but rutt is not installed") from exc
        self._rutt = Rutt(dsn)

    def save(self, result: ScanResult) -> None:
        for finding in result.findings:
            self._rutt.add_finding(
                finding.title,
                host=result.target,
                severity=finding.severity,
                source="aplomado",
                description=finding.description,
                data={
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "confidence": finding.confidence,
                    "references": list(finding.references),
                    "fingerprint": finding.fingerprint,
                },
            )
        if not result.findings:
            self._rutt.review(result.target, tool="aplomado", ok=result.ok,
                              detail={"summary": result.summary, "error": result.error})

    def close(self) -> None:
        self._rutt.close()
