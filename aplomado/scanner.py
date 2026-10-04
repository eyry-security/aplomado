"""Application service for one sandboxed Aplomado review."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .config import ScanConfig
from .findings import ScanResult, parse_agent_result
from .prompts import SYSTEM_PROMPT, scan_prompt
from .store import FindingStore, NullStore, RuttStore


def normalize_target(value: str) -> str:
    """Validate and normalize one hostname or HTTP(S) URL."""
    target = value.strip()
    if not target:
        raise ValueError("target is empty")
    candidate = target if "://" in target else f"https://{target}"
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("target must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("target must not contain credentials")
    if parsed.fragment:
        raise ValueError("target must not contain a URL fragment")
    host = parsed.hostname.lower()
    if "." not in host and host != "localhost" and ":" not in host:
        raise ValueError("target hostname is not fully qualified")
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if parsed.port:
        netloc += f":{parsed.port}"
    normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", parsed.query, ""))
    return normalized if "://" in target else netloc


class Scanner:
    def __init__(self, config: ScanConfig | None = None,
                 store: FindingStore | None = None) -> None:
        self.config = config or ScanConfig.resolve()
        self.store = store or (RuttStore(self.config.rutt_dsn)
                               if self.config.rutt_dsn else NullStore())

    def scan(self, target: str, context: dict[str, Any] | None = None,
             on_message: Any = None) -> ScanResult:
        normalized = normalize_target(target)
        from pinnace import Agent, AgentConfig

        agent = Agent(config=AgentConfig(**self.config.to_pinnace_kwargs()))
        try:
            response = agent.run_sandboxed(
                scan_prompt(normalized, context),
                system_prompt=SYSTEM_PROMPT,
                on_message=on_message,
            )
            result = parse_agent_result(normalized, response, self.config.max_findings)
        except Exception as exc:
            result = ScanResult(normalized, False,
                                error=f"{type(exc).__name__}: {exc}")
        try:
            self.store.save(result)
        except Exception as exc:
            result.ok = False
            result.error = f"persistence failed: {type(exc).__name__}: {exc}"
        return result

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "Scanner":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
