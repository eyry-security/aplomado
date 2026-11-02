"""Session-only graph memory for one Aplomado scan.

The graph lives in ``scratch/memory.json`` inside the scan workdir, next to the
todo list. It is created empty for every scan, shared by the parent agent and
its sub-agents, and dies with the sandbox. Nothing here touches the Pro
database, the network, or a previous scan.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable

from langchain_core.tools import BaseTool, StructuredTool
from pinnace import Sandbox

MEMORY_PATH = "scratch/memory.json"
MEMORY_VERSION = 1

NODE_KINDS = (
    "host",
    "endpoint",
    "parameter",
    "credential",
    "technology",
    "auth_state",
    "hypothesis",
    "issue",
    "artifact",
    "note",
)
EDGE_RELATIONS = (
    "has_parameter",
    "uses_technology",
    "requires_auth",
    "authenticated_as",
    "leads_to",
    "calls",
    "redirects_to",
    "part_of",
    "evidence_for",
    "confirms",
    "contradicts",
)
CONFIDENCE_LEVELS = ("observed", "inferred", "confirmed")
_STATUS_RANK = {"open": 0, "confirmed": 1, "ruled_out": 1}
_CONFIDENCE_RANK = {"inferred": 1, "observed": 2, "confirmed": 3}
_SECRET_KEY = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer|cookie)",
    re.IGNORECASE,
)

MAX_NODES = 500
MAX_EDGES = 1500
MAX_PROP_CHARS = 500
MAX_RECALL_RESULTS = 200

SandboxProvider = Sandbox | Callable[[], Sandbox]


class TurnCounter:
    """Zero-argument turn source updated by the agent loop."""

    def __init__(self) -> None:
        self._turn = 0

    def __call__(self) -> int:
        return self._turn

    def set(self, turn: int) -> None:
        try:
            self._turn = max(0, int(turn))
        except (TypeError, ValueError):
            self._turn = 0


def _resolve_sandbox(provider: SandboxProvider) -> Sandbox:
    return provider() if callable(provider) else provider


def _is_missing(exc: Exception) -> bool:
    text = str(exc).lower()
    return "not found" in text or "no such file" in text


def _empty_graph() -> dict:
    return {"version": MEMORY_VERSION, "nodes": [], "edges": []}


def normalize_key(key: object) -> str:
    """Lowercase and collapse whitespace so repeated facts share an id."""
    return " ".join(str(key).strip().split()).lower()


def node_id_for(kind: str, key: object) -> str:
    return f"{kind}:{normalize_key(key)}"


def _truncate_value(value: object) -> object:
    if isinstance(value, str):
        return value[:MAX_PROP_CHARS]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = json.dumps(value, ensure_ascii=False, default=str)
    return text[:MAX_PROP_CHARS]


def _normalize_props(props: object, *, credential: bool = False) -> dict:
    if props is None:
        return {}
    if not isinstance(props, dict):
        raise ValueError("props must be a JSON object")
    normalized: dict = {}
    for raw_key, value in props.items():
        key = str(raw_key)
        if credential and _SECRET_KEY.search(key):
            normalized[key] = "[redacted]"
            continue
        normalized[key] = _truncate_value(value)
    return normalized


def _edge_id(src: str, relation: str, dst: str) -> str:
    digest = hashlib.sha1(
        f"{src}\0{relation}\0{dst}".encode("utf-8")
    ).hexdigest()
    return f"edge:{digest[:16]}"


class MemoryStore:
    """Load-mutate-save access to one scan's ``scratch/memory.json``.

    The lock is per store instance: parent and sub-agents run in one process
    and share this instance, so in-process serialization is sufficient.
    """

    def __init__(
        self,
        sandbox_provider: SandboxProvider,
        turn_counter: TurnCounter | None = None,
    ) -> None:
        self._sandbox = sandbox_provider
        self._turn_counter = turn_counter or (lambda: 0)
        self._lock = threading.Lock()

    def _current_turn(self) -> int:
        try:
            return max(0, int(self._turn_counter()))
        except Exception:  # noqa: BLE001 - turn stamps must never break a write
            return 0

    def _load(self) -> dict:
        try:
            raw = _resolve_sandbox(self._sandbox).read_file(MEMORY_PATH)
        except Exception as exc:  # noqa: BLE001 - missing file is the normal start
            if _is_missing(exc):
                return _empty_graph()
            raise
        if not raw.strip():
            return _empty_graph()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{MEMORY_PATH} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{MEMORY_PATH} must contain a JSON object")
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise ValueError(
                f"{MEMORY_PATH} must contain JSON lists for nodes and edges"
            )
        return {
            "version": data.get("version", MEMORY_VERSION),
            "nodes": nodes,
            "edges": edges,
        }

    def _save(self, graph: dict) -> None:
        _resolve_sandbox(self._sandbox).write_file(
            MEMORY_PATH,
            json.dumps(graph, indent=2, ensure_ascii=False) + "\n",
        )

    @staticmethod
    def _counts(graph: dict) -> str:
        return f"nodes={len(graph['nodes'])} edges={len(graph['edges'])}"

    def _find_node(self, graph: dict, node_id: str) -> dict | None:
        return next(
            (node for node in graph["nodes"] if node.get("id") == node_id),
            None,
        )

    def remember(
        self,
        kind: str,
        key: str,
        label: str,
        props: dict | None = None,
        confidence: str = "observed",
        status: str = "open",
    ) -> str:
        if kind not in NODE_KINDS:
            raise ValueError(
                f"unknown node kind {kind!r}; use one of {', '.join(NODE_KINDS)}"
            )
        if confidence not in CONFIDENCE_LEVELS:
            raise ValueError(
                "confidence must be one of "
                f"{', '.join(CONFIDENCE_LEVELS)}"
            )
        if not normalize_key(key):
            raise ValueError("key must be a non-empty string")
        if not isinstance(label, str) or not label.strip():
            raise ValueError("label must be a non-empty string")
        status_text = str(status or "open").strip() or "open"

        turn = self._current_turn()
        with self._lock:
            graph = self._load()
            node_id = node_id_for(kind, key)
            existing = self._find_node(graph, node_id)
            merged_props = _normalize_props(
                props, credential=kind == "credential"
            )

            if existing is None:
                if kind == "hypothesis" and confidence != "inferred":
                    raise ValueError(
                        "hypothesis nodes must start with confidence=inferred"
                    )
                if kind == "issue" and status_text == "confirmed" and (
                    confidence != "confirmed"
                ):
                    raise ValueError(
                        "issue nodes may be status=confirmed only with "
                        "confidence=confirmed"
                    )
                if len(graph["nodes"]) >= MAX_NODES:
                    raise ValueError(
                        f"node cap {MAX_NODES} reached; consolidate (merge or "
                        "upsert) existing nodes before adding more"
                    )
                node = {
                    "id": node_id,
                    "kind": kind,
                    "label": label.strip(),
                    "props": merged_props,
                    "confidence": confidence,
                    "status": status_text,
                    "source_turn": turn,
                    "created_turn": turn,
                    "updated_turn": turn,
                }
                graph["nodes"].append(node)
                action = "added"
            else:
                effective_confidence = max(
                    (existing.get("confidence", "inferred"), confidence),
                    key=lambda value: _CONFIDENCE_RANK.get(value, 0),
                )
                effective_status = status_text
                if (
                    _STATUS_RANK.get(existing.get("status", "open"), 0)
                    > _STATUS_RANK.get(status_text, 0)
                ):
                    effective_status = existing.get("status", status_text)
                if kind == "issue" and effective_status == "confirmed" and (
                    effective_confidence != "confirmed"
                ):
                    raise ValueError(
                        "issue nodes may be status=confirmed only with "
                        "confidence=confirmed"
                    )
                existing_props = existing.get("props")
                if not isinstance(existing_props, dict):
                    existing_props = {}
                existing_props.update(merged_props)
                existing["props"] = existing_props
                existing["label"] = label.strip()
                existing["confidence"] = effective_confidence
                existing["status"] = effective_status
                existing["source_turn"] = turn
                existing["updated_turn"] = turn
                action = "updated"
                node = existing

            self._save(graph)
        return (
            f"memory: {action} node {node['id']} — {self._counts(graph)}\n"
            f"- {node['id']} [{node['kind']}] {node['label']} "
            f"confidence={node['confidence']} status={node['status']} "
            f"props={json.dumps(node['props'], ensure_ascii=False, sort_keys=True)}\n"
            f'Full graph: read_file("{MEMORY_PATH}")'
        )

    def relate(
        self,
        source_id: str,
        relation: str,
        target_id: str,
        props: dict | None = None,
    ) -> str:
        if relation not in EDGE_RELATIONS:
            raise ValueError(
                f"unknown relation {relation!r}; use one of "
                f"{', '.join(EDGE_RELATIONS)}"
            )
        turn = self._current_turn()
        with self._lock:
            graph = self._load()
            missing = [
                value
                for value in (source_id, target_id)
                if self._find_node(graph, value) is None
            ]
            if missing:
                raise ValueError(
                    "edge endpoints must already exist; missing node "
                    + ", ".join(repr(value) for value in missing)
                )
            edge_id = _edge_id(source_id, relation, target_id)
            existing = next(
                (
                    edge
                    for edge in graph["edges"]
                    if edge.get("id") == edge_id
                ),
                None,
            )
            merged_props = _normalize_props(props)
            if existing is None:
                if len(graph["edges"]) >= MAX_EDGES:
                    raise ValueError(
                        f"edge cap {MAX_EDGES} reached; consolidate existing "
                        "edges before adding more"
                    )
                edge = {
                    "id": edge_id,
                    "src": source_id,
                    "rel": relation,
                    "dst": target_id,
                    "props": merged_props,
                    "created_turn": turn,
                }
                graph["edges"].append(edge)
                action = "added"
            else:
                existing_props = existing.get("props")
                if not isinstance(existing_props, dict):
                    existing_props = {}
                existing_props.update(merged_props)
                existing["props"] = existing_props
                edge = existing
                action = "confirmed"

            self._save(graph)
        return (
            f"memory: edge {action} {source_id} --{relation}--> {target_id} "
            f"({edge_id}) — {self._counts(graph)}"
        )

    def recall(
        self,
        query: str = "",
        kind: str | None = None,
        node_id: str | None = None,
        depth: int = 1,
        limit: int = 50,
    ) -> str:
        if kind is not None and kind not in NODE_KINDS:
            raise ValueError(
                f"unknown node kind {kind!r}; use one of {', '.join(NODE_KINDS)}"
            )
        try:
            depth_value = max(0, int(depth))
        except (TypeError, ValueError) as exc:
            raise ValueError("depth must be a non-negative integer") from exc
        try:
            limit_value = max(1, int(limit))
        except (TypeError, ValueError) as exc:
            raise ValueError("limit must be a positive integer") from exc
        limit_value = min(limit_value, MAX_RECALL_RESULTS)

        with self._lock:
            graph = self._load()
            nodes = {
                node.get("id"): node
                for node in graph["nodes"]
                if isinstance(node, dict) and node.get("id")
            }
            edges = [
                edge
                for edge in graph["edges"]
                if isinstance(edge, dict)
            ]

            if node_id is not None:
                if node_id not in nodes:
                    raise ValueError(f"no node with id {node_id!r}")
                selected_ids = self._walk(nodes, edges, {node_id}, depth_value)
            else:
                needle = str(query or "").strip().lower()
                selected_ids = set()
                for node_id_value, node in nodes.items():
                    if kind is not None and node.get("kind") != kind:
                        continue
                    if needle and not self._matches(node, needle):
                        continue
                    selected_ids.add(node_id_value)

            if kind is not None:
                selected_ids = {
                    value
                    for value in selected_ids
                    if nodes[value].get("kind") == kind
                }
            selected_ids = sorted(selected_ids)[:limit_value]
            selected = [nodes[value] for value in selected_ids]
            selected_set = set(selected_ids)
            shown_edges = [
                edge
                for edge in edges
                if edge.get("src") in selected_set
                and edge.get("dst") in selected_set
            ]

        lines = [
            f"memory recall: nodes={len(selected)}/{len(nodes)} "
            f"edges={len(shown_edges)}/{len(edges)} limit={limit_value}"
        ]
        for node in selected:
            lines.append(self._format_node(node))
        if shown_edges:
            lines.append("edges:")
            for edge in shown_edges:
                lines.append(self._format_edge(edge))
        if not selected:
            lines.append("(no matching nodes)")
        return "\n".join(lines)

    @staticmethod
    def _matches(node: dict, needle: str) -> bool:
        haystacks = [
            str(node.get("id", "")),
            str(node.get("label", "")),
            str(node.get("kind", "")),
        ]
        props = node.get("props")
        if isinstance(props, dict):
            haystacks.extend(str(value) for value in props.values())
        return any(needle in value.lower() for value in haystacks)

    @staticmethod
    def _walk(
        nodes: dict,
        edges: list[dict],
        seeds: set[str],
        depth: int,
    ) -> set[str]:
        selected = set(seeds)
        frontier = set(seeds)
        for _ in range(depth):
            neighbors: set[str] = set()
            for edge in edges:
                src = edge.get("src")
                dst = edge.get("dst")
                if src in frontier and dst in nodes:
                    neighbors.add(dst)
                if dst in frontier and src in nodes:
                    neighbors.add(src)
            frontier = neighbors - selected
            if not frontier:
                break
            selected.update(frontier)
        return selected

    @staticmethod
    def _format_node(node: dict) -> str:
        props = node.get("props")
        if not isinstance(props, dict):
            props = {}
        return (
            f"- {node.get('id')} [{node.get('kind')}] {node.get('label')} "
            f"confidence={node.get('confidence')} status={node.get('status')} "
            f"props={json.dumps(props, ensure_ascii=False, sort_keys=True)} "
            f"source_turn={node.get('source_turn')} "
            f"updated_turn={node.get('updated_turn')}"
        )

    @staticmethod
    def _format_edge(edge: dict) -> str:
        props = edge.get("props")
        if not isinstance(props, dict):
            props = {}
        return (
            f"- {edge.get('src')} --{edge.get('rel')}--> {edge.get('dst')} "
            f"props={json.dumps(props, ensure_ascii=False, sort_keys=True)}"
        )

    def summary(self) -> str:
        with self._lock:
            graph = self._load()
            nodes = [
                node for node in graph["nodes"] if isinstance(node, dict)
            ]
            kinds: dict[str, int] = {}
            statuses: dict[str, int] = {}
            for node in nodes:
                kind = str(node.get("kind", "unknown"))
                status = str(node.get("status", "unknown"))
                kinds[kind] = kinds.get(kind, 0) + 1
                statuses[status] = statuses.get(status, 0) + 1
            hypotheses = sorted(
                node.get("id", "")
                for node in nodes
                if node.get("kind") == "hypothesis"
                and node.get("status") == "open"
            )
            issues = sorted(
                node.get("id", "")
                for node in nodes
                if node.get("kind") == "issue"
                and node.get("status") == "confirmed"
            )

        lines = [
            f"memory: nodes={len(nodes)} edges={len(graph['edges'])}",
            "kinds: "
            + (
                ", ".join(f"{key}={kinds[key]}" for key in sorted(kinds))
                or "(none)"
            ),
            "status: "
            + (
                ", ".join(
                    f"{key}={statuses[key]}" for key in sorted(statuses)
                )
                or "(none)"
            ),
            "open hypotheses: "
            + (", ".join(hypotheses) if hypotheses else "(none)"),
            "confirmed issues: "
            + (", ".join(issues) if issues else "(none)"),
        ]
        return "\n".join(lines)


def memory_tools(
    sandbox_provider: SandboxProvider,
    turn_counter: TurnCounter | None = None,
) -> list[BaseTool]:
    """Build the four memory tools bound to one shared MemoryStore."""
    store = MemoryStore(sandbox_provider, turn_counter)

    def memory_remember(
        kind: str,
        key: str,
        label: str,
        props: dict | None = None,
        confidence: str = "observed",
        status: str = "open",
    ) -> str:
        """Remember one fact as a node in this scan's session memory graph.

        kind is a closed enum; id is kind + ':' + normalized key, so repeating
        the same fact upserts and merges props. confidence is observed,
        inferred, or confirmed. Credential nodes store references only
        (username, where the session is kept, scope of access), never secret
        values; secret-looking credential props are redacted.
        """
        try:
            return store.remember(
                kind, key, label, props, confidence, status
            )
        except Exception as exc:  # noqa: BLE001 - surface failures to the model
            return f"error: {exc}"

    def memory_relate(
        source_id: str,
        relation: str,
        target_id: str,
        props: dict | None = None,
    ) -> str:
        """Connect two existing nodes with a typed edge.

        relation is a closed enum. Both endpoints must already exist; an
        unknown endpoint or relation is an error. Repeating an edge merges its
        props instead of duplicating it.
        """
        try:
            return store.relate(source_id, relation, target_id, props)
        except Exception as exc:  # noqa: BLE001 - surface failures to the model
            return f"error: {exc}"

    def memory_recall(
        query: str = "",
        kind: str | None = None,
        node_id: str | None = None,
        depth: int = 1,
        limit: int = 50,
    ) -> str:
        """Return a compact text subgraph from this scan's memory graph.

        Matches query text (or filters by kind), or walks depth-hop neighbors
        from node_id. Results are capped by limit.
        """
        try:
            return store.recall(query, kind, node_id, depth, limit)
        except Exception as exc:  # noqa: BLE001 - surface failures to the model
            return f"error: {exc}"

    def memory_summary() -> str:
        """Summarize this scan's memory graph.

        Returns counts by kind and status, plus open hypotheses and confirmed
        issues.
        """
        try:
            return store.summary()
        except Exception as exc:  # noqa: BLE001 - surface failures to the model
            return f"error: {exc}"

    return [
        StructuredTool.from_function(
            memory_remember,
            name="memory_remember",
            description=(
                "Remember one fact in this scan's session memory graph "
                "(scratch/memory.json). kind: host, endpoint, parameter, "
                "credential, technology, auth_state, hypothesis, issue, "
                "artifact, or note. The id is kind + ':' + normalized key; "
                "repeating a fact upserts and merges props. confidence: "
                "observed, inferred, or confirmed. Credential nodes must store "
                "references only — username, where the session is kept, and "
                "scope of access — never secret values; secret-looking "
                "credential props are redacted. Returns the node id and graph "
                "counts."
            ),
        ),
        StructuredTool.from_function(
            memory_relate,
            name="memory_relate",
            description=(
                "Connect two existing memory nodes with a typed edge. "
                "relation: has_parameter, uses_technology, requires_auth, "
                "authenticated_as, leads_to, calls, redirects_to, part_of, "
                "evidence_for, confirms, or contradicts. Both nodes must "
                "already exist; missing nodes and unknown relations are "
                "errors. Repeating an edge merges props. Returns the edge and "
                "graph counts."
            ),
        ),
        StructuredTool.from_function(
            memory_recall,
            name="memory_recall",
            description=(
                "Return a compact text subgraph from session memory. Use query "
                "text or kind to find nodes, or node_id with depth to walk "
                "neighbors. Includes props and edges among the selected nodes. "
                "Results are capped by limit (default 50)."
            ),
        ),
        StructuredTool.from_function(
            memory_summary,
            name="memory_summary",
            description=(
                "Summarize session memory: counts by node kind and status, "
                "open hypotheses, and confirmed issues. Call this before a new "
                "test phase and after compaction instead of re-running "
                "discovery."
            ),
        ),
    ]
