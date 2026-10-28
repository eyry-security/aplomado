"""Protocol-safe agent loop for Aplomado scans.

Pinnace's loop stops a turn as soon as one tool call returns a ``finish()``
payload. When the model emitted several calls in that same assistant message,
the remaining calls never receive tool messages. Some providers (DeepSeek via
the OpenAI-compatible API) then reject the next request with "insufficient
tool messages following tool_calls message".

This subclass keeps Pinnace's turn loop, compaction, metering, and finish
semantics, but answers every call in the turn before honouring ``finish()``.
"""

from __future__ import annotations

import time

from langchain_core.load import dumpd
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from pinnace import AgentResult, PinnaceAgent
from pinnace.agent import THINKING_LOG_MAX_CHARS, extract_thinking
from pinnace.compaction import (
    SUMMARIZE_PROMPT,
    estimate_tokens,
    needs_compaction,
)
from pinnace.tools import parse_finish

from .command_policy import shell_tool
from .history import is_tool_pairing_error, repair_tool_pairs

PAIRING_RETRY_DELAYS = (0.25, 0.5, 1.0)


def _invoke_with_pairing_repair(model, messages, *, log=None, kind="request"):
    """Invoke *model* after repairing tool pairing, retrying pairing 400s."""
    working = repair_tool_pairs(messages)
    retries = 0
    while True:
        try:
            return model.invoke(working), working
        except Exception as exc:  # noqa: BLE001 - only retry pairing failures
            if (
                not is_tool_pairing_error(exc)
                or retries >= len(PAIRING_RETRY_DELAYS)
            ):
                raise
            delay = PAIRING_RETRY_DELAYS[retries]
            retries += 1
            # The first pass fills gaps with synthetic results; if the provider
            # still objects, drop unanswered calls instead of preserving them.
            working = repair_tool_pairs(working, aggressive=True)
            if log is not None:
                log(
                    "[pinnace] provider rejected tool-message pairing; "
                    f"repaired history and retrying {kind} "
                    f"({retries}/{len(PAIRING_RETRY_DELAYS)})"
                )
            time.sleep(delay)


def _safe_tail_start(messages: list[BaseMessage], desired: int) -> int:
    """Move a compaction cut so it never splits an assistant/tool group."""
    start = max(0, desired)
    index = 0
    total = len(messages)
    while index < total:
        calls = getattr(messages[index], "tool_calls", None) or []
        if calls and isinstance(messages[index], AIMessage):
            end = index + 1
            while end < total and isinstance(messages[end], ToolMessage):
                end += 1
            if index < start < end:
                start = index
            index = end
        else:
            index += 1
    return start


def _compact_messages(model, messages, keep_last, on_response=None, log=None):
    """Pinnace-style compaction with a tool-pair-safe tail boundary."""
    if len(messages) <= keep_last + 1:
        return messages
    head = messages[0] if isinstance(messages[0], SystemMessage) else None
    body_start = 1 if head else 0
    desired = len(messages) - keep_last if keep_last else len(messages)
    cut = _safe_tail_start(messages, max(body_start, desired))
    to_summarize = messages[body_start:cut]
    tail = messages[cut:]

    request = [SystemMessage(content=SUMMARIZE_PROMPT), *to_summarize]
    response, _ = _invoke_with_pairing_repair(
        model, request, log=log, kind="compaction request"
    )
    if on_response is not None:
        on_response(response)
    summary = response.content
    if not isinstance(summary, str):
        summary = str(summary)

    out: list[BaseMessage] = []
    if head:
        out.append(head)
    out.append(
        SystemMessage(
            content=(
                "Conversation so far (compacted — details summarized, tail "
                "kept verbatim):\n" + summary
            )
        )
    )
    out.extend(tail)
    return out


class AplomadoAgent(PinnaceAgent):
    """A PinnaceAgent whose tool-call turns are always fully answered."""

    def __init__(self, *args, buffer_store=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.buffer_store = buffer_store
        shell = self._tools_by_name.get("shell")
        if shell is not None:
            replacement = shell_tool(self.sandbox)
            self.tools = [
                replacement if tool.name == "shell" else tool
                for tool in self.tools
            ]
            self._tools_by_name["shell"] = replacement
            self.bound = self.model.bind_tools(self.tools)
            if self._cache_system:
                self._add_tools_cache_breakpoint()

    def run(self, prompt: str) -> AgentResult:
        messages: list[BaseMessage] = []
        if self.system_prompt:
            messages.append(self._system_message())
        if self.session_id:
            history = self.session_store.load(self.session_id)
            if history:
                # History already carries its own system prompt; don't double it.
                messages = [m for m in history if not isinstance(m, SystemMessage)]
                if self.system_prompt:
                    messages.insert(0, self._system_message())
                self._say(
                    f"[pinnace] resumed session {self.session_id!r} "
                    f"({len(history)} messages)"
                )
        if self._cache_system:
            self._say("[pinnace] prompt caching on (system prompt)")
        messages.append(HumanMessage(content=prompt))

        turns = 0
        compacted = 0
        structured = None
        final: str | None = None
        usage_records: list[dict] = []

        while turns < self.max_turns:
            turns += 1
            messages = repair_tool_pairs(messages)
            if needs_compaction(messages, self.compaction_tokens):
                before = estimate_tokens(messages)
                messages = _compact_messages(
                    self.model,
                    messages,
                    self.compaction_keep_last,
                    on_response=lambda response: self._record_usage(
                        response, "compaction", usage_records
                    ),
                    log=self._say,
                )
                compacted += 1
                messages = repair_tool_pairs(messages)
                self._say(
                    f"[pinnace] compacted context "
                    f"({before}→{estimate_tokens(messages)} est. tokens)"
                )

            self._say(f"[pinnace] turn {turns}/{self.max_turns}, calling model…")
            resp, messages = _invoke_with_pairing_repair(
                self.bound, messages, log=self._say, kind="agent request"
            )
            self._record_usage(resp, "agent_turn", usage_records)
            messages.append(resp)

            thinking = extract_thinking(resp)
            if thinking:
                if len(thinking) > THINKING_LOG_MAX_CHARS:
                    thinking = thinking[:THINKING_LOG_MAX_CHARS] + "…"
                self._say(f"[pinnace] thinking: {thinking}")

            calls = resp.tool_calls or []
            if not calls:
                final = (
                    resp.content
                    if isinstance(resp.content, str)
                    else str(resp.content)
                )
                self._say("[pinnace] no tool calls — done")
                break

            done = False
            for call in calls:
                name = call.get("name", "")
                call_id = call.get("id", "")
                args = call.get("args", {}) or {}
                tool = self._tools_by_name.get(name)
                self._say(f"[pinnace] tool: {name}({str(args)[:120]})")
                if tool is None:
                    out = f"error: unknown tool {name!r}"
                    self._say(f"[pinnace] tool-result: {name} -> {out}")
                else:
                    try:
                        result = tool.invoke(args)
                        out = str(result)
                        if self.buffer_store is not None and name != "finish":
                            out = self.buffer_store.maybe_buffer(name, result)
                        out_preview = out[:500].replace(chr(10), " ")
                        self._say(
                            f"[pinnace] tool-result: {name} -> {out_preview}"
                        )
                    except Exception as e:  # noqa: BLE001 - model sees failures
                        out = f"error: {e}"
                        self._say(f"[pinnace] tool-result: {name} -> error: {e}")
                messages.append(
                    ToolMessage(content=out, tool_call_id=call_id, name=name)
                )
                payload = parse_finish(out)
                if payload is not None and not done:
                    structured = payload
                    done = True
                    self._say("[pinnace] finish() called — done")
            if done:
                break
        else:
            self._say(f"[pinnace] hit max_turns={self.max_turns}")

        # A scan that exhausts its active-testing budget still deserves a
        # chance to emit the findings it already confirmed. Ask for a
        # finish()-only wrap-up turn instead of silently returning nothing.
        if structured is None and final is None:
            self._say("[pinnace] turn limit reached — requesting finish payload")
            messages.append(HumanMessage(content=(
                "TURN LIMIT REACHED. Do not run any more tests. Call finish() "
                "exactly once now with your findings JSON. Include every "
                "confirmed finding and the coverage ledger you have so far."
            )))
            for _ in range(2):
                try:
                    resp, messages = _invoke_with_pairing_repair(
                        self.bound,
                        messages,
                        log=self._say,
                        kind="wrap-up request",
                    )
                except Exception as e:  # noqa: BLE001 - keep the scan result
                    self._say(f"[pinnace] wrap-up model call failed: {e}")
                    break
                self._record_usage(resp, "wrapup_turn", usage_records)
                messages.append(resp)
                calls = resp.tool_calls or []
                if not calls:
                    final = (
                        resp.content
                        if isinstance(resp.content, str)
                        else str(resp.content)
                    )
                    break
                for call in calls:
                    name = call.get("name", "")
                    call_id = call.get("id", "")
                    args = call.get("args", {}) or {}
                    if name != "finish":
                        out = (
                            "error: turn limit reached; only finish() is "
                            "allowed"
                        )
                    else:
                        tool = self._tools_by_name.get(name)
                        try:
                            out = str(tool.invoke(args)) if tool else (
                                f"error: unknown tool {name!r}"
                            )
                        except Exception as e:  # noqa: BLE001
                            out = f"error: {e}"
                    messages.append(
                        ToolMessage(content=out, tool_call_id=call_id, name=name)
                    )
                    payload = parse_finish(out)
                    if payload is not None and structured is None:
                        structured = payload
                        self._say("[pinnace] finish() called — done")
                if structured is not None:
                    break

        messages = repair_tool_pairs(messages)
        if self.session_id:
            path = self.session_store.save(self.session_id, messages)
            self._say(f"[pinnace] session saved to {path}")

        return AgentResult(
            final=final,
            structured=structured,
            turns=turns,
            compacted=compacted,
            session_id=self.session_id,
            transcript=[dumpd(m) for m in messages],
            usage=usage_records,
        )
