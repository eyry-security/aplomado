"""Depth-1 sub-agents and output elision for Aplomado scans.

A parent scan can hand an isolated task (or a large output plus an extraction
question) to a child agent. The child shares the parent's model configuration
and sandbox/workdir, cannot delegate further, and reports only a concise
summary back into the parent's context. Child turns and tool calls are relayed
through the parent's log/trace stream with a stable sub-agent id.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable

from langchain_core.tools import BaseTool, StructuredTool
from pinnace import Sandbox

from .agent import AplomadoAgent
from .thinking import ThinkingModel

DEFAULT_SUBAGENT_TURNS = 30
MAX_SUBAGENT_TURNS = 60
MAX_ACTIVE_SUBAGENTS = 2
MAX_SUBAGENT_DEPTH = 1

ELIDE_SOURCE_PREFIX = "scratch/"
SUBAGENT_TASK_MARKER = "SUB-AGENT TASK"
SUMMARIZE_KEYS = ("summary", "answer", "result", "output")

TraceCallback = Callable[[dict], None]


def clamp_subagent_turns(max_turns: int | None) -> int:
    """Return a valid child turn budget (default 30, capped at 60)."""
    if max_turns is None:
        return DEFAULT_SUBAGENT_TURNS
    if isinstance(max_turns, bool):
        raise ValueError("max_turns must be an integer")
    try:
        turns = int(max_turns)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_turns must be an integer") from exc
    if turns < 1:
        raise ValueError("max_turns must be at least 1")
    return min(turns, MAX_SUBAGENT_TURNS)


def summarize_result(result) -> str:
    """Extract the child's summary text from an AgentResult."""
    structured = result.structured
    if isinstance(structured, dict):
        for key in SUMMARIZE_KEYS:
            value = structured.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        if structured:
            return json.dumps(structured, ensure_ascii=False)
    if isinstance(structured, str) and structured.strip():
        return structured.strip()
    if result.final is not None:
        text = result.final
        return text if isinstance(text, str) else str(text)
    return ""


def _child_prompt(task: str, context: str) -> str:
    context_block = context.strip() or "(none)"
    return (
        f"{SUBAGENT_TASK_MARKER}\n{task.strip()}\n\n"
        f"CONTEXT\n{context_block}\n\n"
        "You are a depth-1 sub-agent working for the parent scan. You cannot "
        "delegate further. Use the available tools, stay within scope, and "
        "then call finish() with a JSON object like "
        '{"summary": "<concise result>"} or reply with your concise summary. '
        "Return only what the parent needs; do not paste raw bulk output."
    )


class SubAgentRunner:
    """Runs depth-1 child agents against the parent's model and sandbox."""

    def __init__(
        self,
        *,
        model,
        sandbox: Sandbox,
        tools: list[BaseTool],
        system_prompt: str,
        log: Callable[[str], None] | None = None,
        trace: TraceCallback | None = None,
        thinking: str | None = None,
    ) -> None:
        self.model = model
        self.sandbox = sandbox
        self.tools = list(tools)
        self.system_prompt = system_prompt
        self.log = log or (lambda *args: None)
        self.trace = trace
        self.thinking = thinking
        self._lock = threading.Lock()
        self._counter = 0
        self._semaphore = threading.BoundedSemaphore(MAX_ACTIVE_SUBAGENTS)

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"sub-{self._counter}"

    def _emit(self, subagent_id: str, kind: str, **data) -> None:
        if self.trace is None:
            return
        event = {
            "type": f"subagent.{kind}",
            "subagent_id": subagent_id,
            "timestamp": time.time(),
        }
        event.update(data)
        try:
            self.trace(event)
        except Exception:  # noqa: BLE001 - tracing must never break a run
            pass

    def _relay_log(self, subagent_id: str, message: str) -> None:
        text = str(message)
        if text.startswith("[pinnace] "):
            body = text[len("[pinnace] "):]
        else:
            body = text
        tagged = f"[pinnace] [subagent {subagent_id}] {body}"
        self.log(tagged)
        self._emit(subagent_id, "log", text=body)

    def run(
        self,
        task: str,
        context: str = "",
        *,
        max_turns: int | None = DEFAULT_SUBAGENT_TURNS,
        label: str = "delegate",
        depth: int = 0,
    ) -> str:
        """Run one child agent and return its summary text."""
        if depth >= MAX_SUBAGENT_DEPTH:
            return "error: nested delegation is not allowed (depth 1)"
        if not isinstance(task, str) or not task.strip():
            return "error: task must be a non-empty string"
        try:
            budget = clamp_subagent_turns(max_turns)
        except ValueError as exc:
            return f"error: {exc}"

        subagent_id = self._next_id()
        self._emit(
            subagent_id,
            "started",
            label=label,
            task=task.strip(),
            max_turns=budget,
        )
        self._relay_log(
            subagent_id,
            f"[pinnace] sub-agent {subagent_id} started ({label}, "
            f"max {budget} turns): {task.strip()[:200]}",
        )

        try:
            with self._semaphore:
                agent = AplomadoAgent(
                    model=self.model,
                    sandbox=self.sandbox,
                    tools=self.tools,
                    system_prompt=self.system_prompt,
                    max_turns=budget,
                    log=lambda msg: self._relay_log(subagent_id, msg),
                )
                if self.thinking is not None:
                    agent.bound = ThinkingModel(
                        agent.bound,
                        self.thinking,
                        lambda msg: self._relay_log(subagent_id, msg),
                    )
                result = agent.run(_child_prompt(task, context))
        except Exception as exc:  # noqa: BLE001 - parent sees the failure
            summary = f"error: sub-agent {subagent_id} failed: {exc}"
            self._emit(subagent_id, "failed", error=str(exc))
            self._relay_log(subagent_id, f"[pinnace] {summary}")
            return summary

        summary = summarize_result(result)
        self._emit(
            subagent_id,
            "finished",
            turns=result.turns,
            summary=summary,
        )
        self._relay_log(
            subagent_id,
            f"[pinnace] sub-agent {subagent_id} finished "
            f"({result.turns} turns)",
        )
        if not summary:
            return f"(sub-agent {subagent_id} returned no summary)"
        return summary

    def elide(self, source: str, question: str) -> str:
        """Answer *question* from *source* without returning the raw source."""
        if not isinstance(question, str) or not question.strip():
            return "error: question must be a non-empty string"
        if not isinstance(source, str):
            return "error: source must be text or a scratch/ file path"

        text = source
        candidate = source.strip()
        if candidate.startswith(ELIDE_SOURCE_PREFIX) and "\n" not in candidate:
            try:
                text = self.sandbox.read_file(candidate)
            except Exception as exc:  # noqa: BLE001 - surface it to the model
                return f"error: can't read elide source {candidate!r}: {exc}"

        task = (
            "Extract an answer from the SOURCE below. Return ONLY the answer "
            "to the QUESTION; do not copy the raw source or unrelated bulk.\n\n"
            f"QUESTION\n{question.strip()}\n\nSOURCE\n{text}"
        )
        return self.run(task, label="elide")


def delegate_task_tool(runner: SubAgentRunner) -> BaseTool:
    """Build the parent-facing delegate_task tool."""

    def delegate_task(
        task: str,
        context: str = "",
        max_turns: int = DEFAULT_SUBAGENT_TURNS,
    ) -> str:
        """Delegate one focused task to a depth-1 sub-agent.

        The child shares this run's sandbox and workdir and returns only its
        summary. max_turns defaults to 30 and is capped at 60.
        """
        return runner.run(task, context, max_turns=max_turns)

    return StructuredTool.from_function(
        delegate_task,
        name="delegate_task",
        description=(
            "Delegate one focused task to a depth-1 sub-agent that shares "
            "your sandbox/workdir. Give it a clear task and any context; it "
            "returns a concise summary. max_turns defaults to 30, max 60. "
            "Sub-agents cannot delegate further."
        ),
    )


def elide_tool(runner: SubAgentRunner) -> BaseTool:
    """Build the parent-facing elide tool for large-output extraction."""

    def elide(source: str, question: str) -> str:
        """Answer a question from a large source without loading it raw.

        source is inline text or a path under scratch/. Only the extracted
        answer is returned to your context.
        """
        return runner.elide(source, question)

    return StructuredTool.from_function(
        elide,
        name="elide",
        description=(
            "Extract just the answer you need from a large output. Pass the "
            "inline text or a scratch/ file path plus a precise question; a "
            "sub-agent reads the bulk and returns only the answer."
        ),
    )


def subagent_tools(runner: SubAgentRunner) -> list[BaseTool]:
    return [delegate_task_tool(runner), elide_tool(runner)]
