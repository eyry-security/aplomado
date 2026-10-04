"""Optional persistence of scan results to Rutt.

When ``--rutt-dsn`` is given (or ``$RUTT_DSN`` / ``$DATABASE_URL`` is set),
Aplomado writes every scan's findings into Rutt's shared store so the rest
of the Eyry suite — ``rutt findings``, ``rutt host``, Quarterdeck — can see
what was found.  Without a DSN, results go to stdout only (NullStore).

The store works with the dict-based envelope that :func:`normalize_findings`
produces — no separate data model required.
"""

from __future__ import annotations

import os
from typing import Protocol


class FindingStore(Protocol):
    """Where scan results go after normalization."""

    def save(self, envelope: dict) -> None: ...
    def close(self) -> None: ...


class NullStore:
    """No-op store — used when no Rutt DSN is configured."""

    def save(self, envelope: dict) -> None:
        return None

    def close(self) -> None:
        return None


class RuttStore:
    """Thin adapter over Rutt's public lifecycle API.

    Rutt is imported lazily so standalone scans (no Postgres) still work.
    The caller must have run ``rutt init`` before scanning.
    """

    def __init__(self, dsn: str) -> None:
        try:
            from rutt import Rutt
        except ImportError as exc:
            raise RuntimeError(
                "Rutt persistence requested but rutt is not installed"
            ) from exc
        self._rutt = Rutt(dsn)

    def save(self, envelope: dict) -> None:
        """Persist one normalized findings envelope to Rutt.

        Each finding becomes a ``rutt.add_finding()`` call; if the scan
        produced no findings, we still record a review event so the host
        advances through the lifecycle (probed → reviewed).
        """
        target = envelope.get("target", "")
        findings = envelope.get("findings", [])

        for finding in findings:
            self._rutt.add_finding(
                finding.get("title", ""),
                host=target,
                severity=finding.get("severity", "info"),
                source="aplomado",
                description=finding.get("detail", ""),
                data={
                    "evidence": finding.get("evidence", ""),
                },
            )

        if not findings:
            self._rutt.review(
                target,
                tool="aplomado",
                detail={"summary": envelope.get("summary", "")},
            )

    def close(self) -> None:
        self._rutt.close()


def resolve_store(dsn: str | None = None) -> FindingStore:
    """Build the right store from a DSN (explicit, env var, or None)."""
    dsn = dsn or os.environ.get("RUTT_DSN") or os.environ.get("DATABASE_URL") or ""
    if dsn:
        return RuttStore(dsn)
    return NullStore()
