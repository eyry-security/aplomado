"""Opt-in model-thinking narration for Aplomado scans."""

from __future__ import annotations

from typing import Callable

from pinnace import AgentConfig, PinnaceError

COMPACT_MAX_CHARS = 240
VERBOSE_MAX_CHARS = 4000
THINKING_BUDGET_TOKENS = 4000
THINKING_MAX_TOKENS = 8000


def extract_thinking(response: object) -> str:
    """Return reasoning text carried by a model response, if any.

    Providers expose reasoning either as typed content blocks or response
    metadata. Redacted blocks are identified without exposing their payload.
    Duplicate copies across fields are emitted only once.
    """
    parts: list[str] = []
    content = getattr(response, "content", None)
    blocks = content if isinstance(content, list) else []
    for block in blocks:
        if isinstance(block, dict):
            block_type = block.get("type")
            text = block.get("thinking") or block.get("text")
        else:
            block_type = getattr(block, "type", None)
            text = getattr(block, "thinking", None) or getattr(block, "text", None)
        if block_type in {"thinking", "reasoning"} and isinstance(text, str) and text:
            parts.append(text)
        elif block_type == "redacted_thinking":
            parts.append("[redacted thinking]")

    for metadata_name in ("additional_kwargs", "response_metadata"):
        metadata = getattr(response, metadata_name, None)
        if not isinstance(metadata, dict):
            continue
        for key in ("reasoning", "reasoning_content", "thinking"):
            text = metadata.get(key)
            if isinstance(text, str) and text:
                parts.append(text)

    unique: list[str] = []
    for part in parts:
        stripped = part.strip()
        if stripped and stripped not in unique:
            unique.append(stripped)
    return "\n".join(unique)


def render_thinking(text: str, mode: str) -> str:
    """Render a collapsed preview or an expanded, bounded reasoning block."""
    if mode == "compact":
        rendered = " ".join(text.split())
        if len(rendered) > COMPACT_MAX_CHARS:
            rendered = rendered[:COMPACT_MAX_CHARS].rstrip() + "…"
        return f"thinking: {rendered}"
    if mode == "verbose":
        rendered = text.strip()
        if len(rendered) > VERBOSE_MAX_CHARS:
            rendered = rendered[:VERBOSE_MAX_CHARS].rstrip() + "…"
        indented = "\n".join(f"  {line}" for line in rendered.splitlines())
        return f"thinking (verbose):\n{indented}"
    raise ValueError(f"unknown thinking mode: {mode!r}")


def _make_model(model_ref: str):
    """Build a model with extended reasoning enabled where supported."""
    try:
        from langchain.chat_models import init_chat_model
    except ImportError as exc:
        raise PinnaceError(
            "thinking with a model reference needs the 'langchain' package "
            "and the selected provider integration"
        ) from exc

    provider, separator, name = model_ref.partition(":")
    if not separator or not name:
        raise PinnaceError(
            f"bad model ref {model_ref!r}: want 'provider:model'"
        )
    kwargs: dict = {}
    if provider == "anthropic":
        kwargs["thinking"] = {
            "type": "enabled",
            "budget_tokens": THINKING_BUDGET_TOKENS,
        }
        kwargs["max_tokens"] = THINKING_MAX_TOKENS
    return init_chat_model(name, model_provider=provider, **kwargs)


class ThinkingModel:
    """Transparent ``bind_tools``/``invoke`` proxy that narrates reasoning."""

    def __init__(self, model, mode: str, log: Callable[[str], None]) -> None:
        self._model = model
        self._mode = mode
        self._log = log

    def bind_tools(self, tools):
        return ThinkingModel(self._model.bind_tools(tools), self._mode, self._log)

    def invoke(self, *args, **kwargs):
        response = self._model.invoke(*args, **kwargs)
        thinking = extract_thinking(response)
        if thinking:
            self._log(render_thinking(thinking, self._mode))
        return response

    def __getattr__(self, name):
        return getattr(self._model, name)


def prepare_thinking_model(model, mode: str | None):
    """Resolve and build the concrete model when narration is enabled.

    The returned model is deliberately not proxied so Pinnace can still use
    concrete-type capability checks such as prompt-caching support. Callers
    wrap the agent's already-bound invocation layer with :class:`ThinkingModel`.
    """
    if mode is None:
        return model
    if mode not in {"compact", "verbose"}:
        raise ValueError(f"unknown thinking mode: {mode!r}")
    if model is None:
        model = AgentConfig.resolve().model
    if isinstance(model, str):
        model = _make_model(model)
    return model
