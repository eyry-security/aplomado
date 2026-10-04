"""Curated wordlists bundled with Aplomado.

The registry is intentionally explicit: callers select a known logical name
rather than passing a resource path.  This keeps resource lookup predictable
and prevents path traversal when names originate at a CLI or agent boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources


@dataclass(frozen=True, slots=True)
class Wordlist:
    """Metadata and content access for one bundled wordlist."""

    name: str
    filename: str
    kind: str
    description: str

    def read_text(self) -> str:
        """Return the list exactly as UTF-8 text, including its final newline."""
        return resources.files(__package__).joinpath(self.filename).read_text(
            encoding="utf-8"
        )

    def entries(self) -> tuple[str, ...]:
        """Return non-empty, non-comment entries in priority order."""
        return tuple(
            line
            for raw_line in self.read_text().splitlines()
            if (line := raw_line.strip()) and not line.startswith("#")
        )

    def as_dict(self) -> dict[str, object]:
        """Return JSON-friendly catalog metadata."""
        return {
            "name": self.name,
            "kind": self.kind,
            "description": self.description,
            "entries": len(self.entries()),
        }


_WORDLISTS = (
    Wordlist(
        name="common-paths",
        filename="common-paths.txt",
        kind="content",
        description="High-signal web files and directories.",
    ),
    Wordlist(
        name="api-routes",
        filename="api-routes.txt",
        kind="content",
        description="Common API resources, actions, and metadata routes.",
    ),
    Wordlist(
        name="parameters",
        filename="parameters.txt",
        kind="parameter",
        description="Common query and form parameter names.",
    ),
    Wordlist(
        name="virtual-hosts",
        filename="virtual-hosts.txt",
        kind="vhost",
        description="Common virtual-host and subdomain labels.",
    ),
)
_BY_NAME = {wordlist.name: wordlist for wordlist in _WORDLISTS}


def list_wordlists() -> tuple[Wordlist, ...]:
    """Return the immutable catalog in stable display order."""
    return _WORDLISTS


def get_wordlist(name: str) -> Wordlist:
    """Resolve a logical wordlist name.

    Only names in :func:`list_wordlists` are accepted; filenames and paths are
    deliberately not interpreted.
    """
    try:
        return _BY_NAME[name.strip().lower()]
    except (AttributeError, KeyError) as exc:
        available = ", ".join(_BY_NAME)
        raise ValueError(f"unknown wordlist {name!r}; choose from: {available}") from exc


def read_wordlist(name: str) -> str:
    """Return a bundled wordlist as ready-to-use UTF-8 text."""
    return get_wordlist(name).read_text()


__all__ = ["Wordlist", "get_wordlist", "list_wordlists", "read_wordlist"]
