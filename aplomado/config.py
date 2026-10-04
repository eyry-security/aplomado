"""Configuration for Aplomado scans."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class ScanConfig:
    """Resolved scanner settings.

    Explicit values take precedence over environment variables. Scanner tool
    execution is always sandboxed; network access is enabled only because the
    sandbox must reach the authorized target.
    """

    model: str = "gpt-4o"
    api_key: str = ""
    base_url: str = ""
    sandbox_image: str = "aplomado-sandbox:latest"
    sandbox_timeout: int = 180
    sandbox_mem_limit: str = "1g"
    sandbox_network: bool = True
    max_turns: int = 40
    max_findings: int = 50
    rutt_dsn: str = ""
    concurrency: int = 1

    def __post_init__(self) -> None:
        if self.max_turns < 1:
            raise ValueError("max_turns must be positive")
        if self.max_findings < 1:
            raise ValueError("max_findings must be positive")
        if self.sandbox_timeout < 1:
            raise ValueError("sandbox_timeout must be positive")

    @classmethod
    def resolve(
        cls,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        sandbox_image: str | None = None,
        max_turns: int | None = None,
        max_findings: int | None = None,
        rutt_dsn: str | None = None,
    ) -> "ScanConfig":
        return cls(
            model=model if model is not None else os.getenv("PINNACE_MODEL", "gpt-4o"),
            api_key=api_key if api_key is not None else os.getenv("OPENAI_API_KEY", ""),
            base_url=base_url if base_url is not None else os.getenv("OPENAI_BASE_URL", ""),
            sandbox_image=(sandbox_image if sandbox_image is not None else
                           os.getenv("APLOMADO_SANDBOX_IMAGE", "aplomado-sandbox:latest")),
            sandbox_timeout=int(os.getenv("APLOMADO_SANDBOX_TIMEOUT", "180")),
            sandbox_mem_limit=os.getenv("APLOMADO_SANDBOX_MEMORY", "1g"),
            max_turns=(max_turns if max_turns is not None else
                       int(os.getenv("APLOMADO_MAX_TURNS", "40"))),
            max_findings=(max_findings if max_findings is not None else
                          int(os.getenv("APLOMADO_MAX_FINDINGS", "50"))),
            rutt_dsn=(rutt_dsn if rutt_dsn is not None else
                      os.getenv("RUTT_DSN") or os.getenv("DATABASE_URL", "")),
        )

    def to_pinnace_kwargs(self) -> dict[str, object]:
        """Return arguments accepted by the current Pinnace ``AgentConfig``."""
        return {
            "model": self.model,
            "api_key": self.api_key,
            "base_url": self.base_url,
            "sandbox_image": self.sandbox_image,
            "sandbox_timeout": self.sandbox_timeout,
            "sandbox_mem_limit": self.sandbox_mem_limit,
            "sandbox_network": self.sandbox_network,
            "max_turns": self.max_turns,
        }
