"""Tool-message pairing repair for provider requests.

OpenAI-compatible providers (DeepSeek included) require every assistant
``tool_calls`` entry to be answered by exactly one tool message before the next
non-tool message. Compaction boundaries and resumed transcripts can violate
that invariant, so every provider request passes through :func:`repair_tool_pairs`.
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage

SYNTHETIC_TOOL_RESULT_KEY = "aplomado_synthetic_tool_result"
PAIRING_ERROR_MARKERS = (
    "must be followed by tool messages",
    "insufficient tool messages",
    "tool_call_id",
    "role 'tool'",
    "role \"tool\"",
)


def _is_synthetic(tool_message: ToolMessage) -> bool:
    extra = getattr(tool_message, "additional_kwargs", None)
    return isinstance(extra, dict) and bool(extra.get(SYNTHETIC_TOOL_RESULT_KEY))


def _synthetic_tool_message(call: dict) -> ToolMessage:
    call_id = str(call.get("id", ""))
    name = str(call.get("name", ""))
    label = name or "unknown tool"
    return ToolMessage(
        content=(
            f"error: the result of {label} (tool_call_id={call_id or 'unset'}) "
            "was lost while assembling conversation history; no output is "
            "available for this call."
        ),
        tool_call_id=call_id,
        name=name,
        additional_kwargs={SYNTHETIC_TOOL_RESULT_KEY: True},
    )


def _copy_without_tool_calls(message: AIMessage) -> AIMessage:
    extra = dict(getattr(message, "additional_kwargs", None) or {})
    extra.pop("tool_calls", None)
    extra.pop("function_call", None)
    try:
        return message.model_copy(
            update={"tool_calls": [], "additional_kwargs": extra}
        )
    except Exception:  # noqa: BLE001 - very old langchain fallback
        return AIMessage(content=message.content)


def _copy_with_tool_calls(message: AIMessage, calls: list[dict]) -> AIMessage:
    extra = dict(getattr(message, "additional_kwargs", None) or {})
    extra.pop("tool_calls", None)
    extra.pop("function_call", None)
    try:
        return message.model_copy(
            update={"tool_calls": calls, "additional_kwargs": extra}
        )
    except Exception:  # noqa: BLE001 - very old langchain fallback
        return AIMessage(content=message.content, tool_calls=calls)


def repair_tool_pairs(
    messages: list[BaseMessage],
    *,
    aggressive: bool = False,
) -> list[BaseMessage]:
    """Return a history with valid assistant/tool message pairing.

    Normal mode inserts a synthetic tool message for every unanswered call so
    the model can see that the call happened but its result was lost. Aggressive
    mode instead drops unanswered calls (and any synthetic placeholders from an
    earlier pass), keeping only calls that have a real tool result. Orphan tool
    messages are always dropped.
    """
    repaired: list[BaseMessage] = []
    index = 0
    total = len(messages)

    while index < total:
        message = messages[index]
        if isinstance(message, ToolMessage):
            # Not consumed by a preceding assistant call: orphan.
            index += 1
            continue

        calls = list(getattr(message, "tool_calls", None) or [])
        if not isinstance(message, AIMessage) or not calls:
            repaired.append(message)
            index += 1
            continue

        follow_start = index + 1
        follow_end = follow_start
        while follow_end < total and isinstance(messages[follow_end], ToolMessage):
            follow_end += 1

        by_id: dict[str, ToolMessage] = {}
        for tool_message in messages[follow_start:follow_end]:
            call_id = str(getattr(tool_message, "tool_call_id", ""))
            by_id.setdefault(call_id, tool_message)

        if aggressive:
            kept_calls = [
                call
                for call in calls
                if by_id.get(str(call.get("id", ""))) is not None
                and not _is_synthetic(by_id[str(call.get("id", ""))])
            ]
            if kept_calls:
                repaired.append(_copy_with_tool_calls(message, kept_calls))
                for call in kept_calls:
                    repaired.append(by_id[str(call.get("id", ""))])
            else:
                repaired.append(_copy_without_tool_calls(message))
        else:
            repaired.append(message)
            for call in calls:
                call_id = str(call.get("id", ""))
                tool_message = by_id.get(call_id)
                repaired.append(
                    tool_message if tool_message is not None
                    else _synthetic_tool_message(call)
                )

        index = follow_end

    return repaired


def is_tool_pairing_error(exc: Exception) -> bool:
    """True when *exc* is the provider's tool-message pairing rejection."""
    text = str(exc)
    lower = text.lower()
    if "tool" not in lower:
        return False
    mentions_calls = "tool_calls" in lower or "tool calls" in lower
    mentions_id = "tool_call_id" in lower
    if not (mentions_calls or mentions_id):
        return False
    return any(marker in lower for marker in PAIRING_ERROR_MARKERS)
