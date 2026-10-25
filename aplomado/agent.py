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

from langchain_core.load import dumpd
from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from pinnace import AgentResult, PinnaceAgent
from pinnace.agent import THINKING_LOG_MAX_CHARS, extract_thinking
from pinnace.compaction import compact_messages, estimate_tokens, needs_compaction
from pinnace.tools import parse_finish


class AplomadoAgent(PinnaceAgent):
    """A PinnaceAgent whose tool-call turns are always fully answered."""

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
            if needs_compaction(messages, self.compaction_tokens):
                before = estimate_tokens(messages)
                messages = compact_messages(
                    self.model,
                    messages,
                    self.compaction_keep_last,
                    on_response=lambda response: self._record_usage(
                        response, "compaction", usage_records
                    ),
                )
                compacted += 1
                self._say(
                    f"[pinnace] compacted context "
                    f"({before}→{estimate_tokens(messages)} est. tokens)"
                )

            self._say(f"[pinnace] turn {turns}/{self.max_turns}, calling model…")
            resp = self.bound.invoke(messages)
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
                if tool is None:
                    out = f"error: unknown tool {name!r}"
                else:
                    self._say(f"[pinnace] tool: {name}({str(args)[:120]})")
                    try:
                        out = str(tool.invoke(args))
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
