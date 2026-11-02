"""Versioned skills, their access graph, and parent-only loading tools.

A skill is the registry-held unit that grows out of :class:`PromptPack`.  The
pack remains the rendering core for the system/run prompt pair; a skill adds
doctrine, planning seeds, optional reachability, and optional tool unlocks.

Shipped v1 secondaries deliberately declare no ``tool_unlocks`` so every tool
that is always-on today stays always-on.  The unlock plumbing is exercised by
tests with fixture skills.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Iterable

from langchain_core.tools import BaseTool, StructuredTool


class SkillError(ValueError):
    """A skill id or skill definition is invalid."""


@dataclass(frozen=True)
class Skill:
    """One immutable, versioned skill."""

    name: str
    version: int = 1
    description: str = ""
    doctrine: str = ""
    planning_template: tuple[str, ...] = ()
    tool_unlocks: tuple[str, ...] = ()
    can_access: tuple[str, ...] = ()
    triggers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise SkillError("skill name cannot be empty")
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise SkillError("skill version must be an integer")
        if self.version < 1:
            raise SkillError("skill version must be positive")
        if not isinstance(self.description, str) or not self.description.strip():
            raise SkillError("skill description cannot be empty")
        if not isinstance(self.doctrine, str) or not self.doctrine.strip():
            raise SkillError("skill doctrine cannot be empty")
        for field_name in (
            "planning_template",
            "tool_unlocks",
            "can_access",
            "triggers",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, tuple):
                object.__setattr__(self, field_name, tuple(value))

    @property
    def id(self) -> str:
        """The stable public id used in envelopes and tool calls."""
        return self.name

    @property
    def identifier(self) -> str:
        """Pack-parity identifier; skills address by name in v1."""
        return self.name


# ---------------------------------------------------------------------------
# Doctrine and planning templates
# ---------------------------------------------------------------------------

WEB_SCANNER_DOCTRINE = """\
PRIMARY SKILL: WEB-SCANNER
- PLAN FIRST: instantiate the web-scanner planning template with todos_write
  before spending test actions. The template is the seed; add target-specific
  items only after the first list exists.
- MEMORY HABITS: create memory nodes in the same turn a surface, input,
  technology, or auth state is discovered. Write a hypothesis node before a
  test, then update its status and link evidence when the result lands. Recall
  the graph before entering a new phase and after any compaction.
- CLASS ROUTING: the secondary skills reachable from this primary are loaded
  by you, mid-run, when their surface appears. Call skills_list to see the
  current reachable set, then load_skill:
  * form, query, JSON, or database-backed parameters -> injection-testing;
  * reflected input, script sinks, or DOM-heavy pages -> xss-testing;
  * login, session, role, admin, token, or object-identifier surface ->
    auth-access-control.
- Merge a loaded skill's planning items with todos_add. Never replace the
  todo list to install them, and never discard done/skipped state.
- A secondary doctrine adds procedure and verdict discipline only. It never
  relaxes this primary skill's scope, rate, or evidence rules.
"""

BUG_HUNTER_DOCTRINE = """\
PRIMARY SKILL: BUG-HUNTER
- PLAN FIRST: instantiate the bug-hunter planning template with todos_write
  before testing. Keep the funnel order in the list: map, JS/SPA decompile,
  known-vuln sweep, parameters, targeted injection, auth/access control,
  verification, finish.
- MEMORY HABITS: record endpoints, parameters, technologies, auth states, and
  hypotheses as memory nodes in the same turn they are discovered. Link
  evidence to every finding you intend to file, and recall the graph after
  compaction instead of re-running discovery.
- CLASS ROUTING: call skills_list to see the reachable secondary skills, then
  load_skill exactly when the matching surface appears:
  * inputs or database-backed parameters -> injection-testing;
  * reflected parameters, script-heavy pages, or DOM sinks -> xss-testing;
  * sessions, roles, admin routes, tokens, or object identifiers ->
    auth-access-control.
- Merge the returned planning items with todos_add so existing done/skipped
  state survives. Loading a skill is not a substitute for verification.
- Secondary doctrine adds procedure; the funnel's staged-escalation and
  evidence rules remain in force.
"""

INJECTION_DOCTRINE = """\
SKILL: INJECTION-TESTING
STAGED PROCEDURE
1. Enumerate the concrete inputs first: query parameters, form fields, JSON
   keys, path segments, headers, and cookies. Record each input as a memory
   parameter node before probing it.
2. Probe with low-noise indicator payloads before using any heavy tool:
   quote/marker pairing for SQL, arithmetic or boolean differences, path
   traversal markers for file access, and command/template markers where the
   technology suggests them.
3. Escalate only on an indicator. Use the routed tool for the class (the
   staged SQLi tool for database-backed parameters) and then reproduce the
   result manually with curl.
4. Cover every applicable class on every applicable input; a class is not
   clean because a couple of parameters were tried.
5. Never use destructive or data-writing payloads, dump entire databases, or
   chain heavy scans speculatively.
VERDICT DISCIPLINE
- An indicator is a lead, not a finding. Report only behavior you reproduced
  with the exact request and a verbatim response excerpt.
- State the input, the payload, the observed differential, and whether the
  result is confirmed or ruled out in memory.
- Record a hypothesis before the probe, and update it with confirmed or
  ruled_out plus the evidence link afterward.
"""

XSS_DOCTRINE = """\
SKILL: XSS-TESTING
STAGED PROCEDURE
1. Separate reflected inputs, stored inputs, and DOM sources/sinks. Record
   each candidate as a memory hypothesis or parameter node before probing.
2. Start with harmless marker payloads and locate exactly where the marker
   lands in the response or DOM. Check encoding, attribute context, and script
   context before escalating.
3. For DOM surfaces, trace source-to-sink flow in the recovered JavaScript;
   confirm with a rendered check rather than inferred reachability.
4. Escalate to an executing payload only where the context supports it, and
   verify execution in the browser when the sink is client-side.
5. Keep payloads non-destructive and rate-limited; never spray every input
   with an execution payload.
VERDICT DISCIPLINE
- Reflection is not execution. A confirmed finding needs a reproducible
  context and observable execution (or a demonstrated exploit path for DOM).
- Replay the exact request with curl for server-side reflections and keep the
  browser observation for client-side execution.
- Record the verdict and evidence link in memory; mark unreachable sink
  candidates ruled_out rather than leaving them ambiguous.
"""

AUTH_ACCESS_CONTROL_DOCTRINE = """\
SKILL: AUTH-ACCESS-CONTROL
STAGED PROCEDURE
1. Map the authentication surface: login/logout, session cookies, token
   issuance and refresh, role boundaries, and admin or privileged routes.
2. Record auth state as credential references only — never secret values.
   Note where each session is stored so later requests replay the same state.
3. Test forced browsing and missing server-side authorization: request
   privileged routes and objects directly with a low-privilege session.
4. Test object-level access control (IDOR/BOLA) by comparing responses for
   adjacent identifiers between sessions; report the differential, not an
   assumed exploit.
5. Check session handling: fixation, rotation on login/logout, scope and
   flags of cookies, and whether access survives a logout or role change.
VERDICT DISCIPLINE
- A missing UI link is not an authorization finding. The server must return
  privileged data or perform a privileged action without an adequate check.
- Replay both the authorized and unauthorized requests with curl and quote
  the status/body difference as evidence.
- Record the access hypothesis before testing and mark it confirmed or
  ruled_out with links to the request evidence afterward.
"""

WEB_SCANNER_PLAN = (
    "Map the assigned host's HTTP surface and record the inventory in memory",
    "Identify input, authentication, and admin/CMS surfaces worth testing",
    "Route each surface to the applicable secondary skill and run its tests",
    "Verify every candidate finding by replaying the exact request",
    "Record verdicts in memory and finish with evidence-backed findings",
)

BUG_HUNTER_PLAN = (
    "Map URLs, forms, and endpoints with the crawlers and merge the inventory",
    "Decompile the app's JavaScript and recover routes, APIs, and parameters",
    "Sweep known vulnerabilities and discover hidden parameters",
    "Run targeted injection and auth/access-control tests on candidate inputs",
    "Verify every candidate by replaying the exact request",
    "Record verdicts and finish with only evidence-backed findings",
)

INJECTION_PLAN = (
    "Enumerate all inputs (query, form, JSON, path, header, cookie)",
    "Probe each input with low-noise injection indicators",
    "Escalate only on an indicator using the routed class tool",
    "Verify the result by replaying the exact request",
    "Record the class verdict in memory",
)

XSS_PLAN = (
    "Identify reflected, stored, and DOM input candidates",
    "Locate marker placement and the surrounding encoding context",
    "Trace DOM source-to-sink flow where client-side code is involved",
    "Verify execution or reflection by replaying the exact request",
    "Record the verdict and evidence in memory",
)

AUTH_ACCESS_CONTROL_PLAN = (
    "Map login, session, token, role, and admin surfaces",
    "Record low-privilege and high-privilege auth states as references",
    "Test forced browsing and missing server-side authorization",
    "Test object-level access with adjacent identifiers",
    "Verify the differential by replaying both requests",
    "Record the access verdict in memory",
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

DEFAULT_PRIMARY_SKILL_ID = "web-scanner"
PACK_PRIMARY_SKILLS = {
    "recon": "web-scanner",
    "recon-v1": "web-scanner",
    "bughunter": "bug-hunter",
    "bughunter-v1": "bug-hunter",
}

_SKILLS: dict[str, Skill] = {}


def register_skill(skill: Skill) -> Skill:
    """Register (or replace) one skill by its public name."""
    if not isinstance(skill, Skill):
        raise SkillError("register_skill expects a Skill instance")
    _SKILLS[skill.name] = skill
    return skill


def unregister_skill(name: str) -> None:
    """Remove a skill; intended for fixture setup/teardown."""
    _SKILLS.pop(str(name), None)


def _register_shipped() -> None:
    register_skill(
        Skill(
            name="injection-testing",
            version=1,
            description=(
                "Staged injection procedure for SQLi, traversal/LFI, and "
                "command or template inputs."
            ),
            doctrine=INJECTION_DOCTRINE,
            planning_template=INJECTION_PLAN,
            triggers=(
                "injection",
                "sqli",
                "sql",
                "database",
                "mysql",
                "postgres",
                "sqlite",
                "lfi",
                "traversal",
            ),
        )
    )
    register_skill(
        Skill(
            name="xss-testing",
            version=1,
            description=(
                "Staged cross-site scripting procedure for reflected, stored, "
                "and DOM sinks."
            ),
            doctrine=XSS_DOCTRINE,
            planning_template=XSS_PLAN,
            triggers=(
                "xss",
                "cross-site",
                "cross site",
                "reflected",
                "dom sink",
                "innerhtml",
                "script injection",
            ),
        )
    )
    register_skill(
        Skill(
            name="auth-access-control",
            version=1,
            description=(
                "Session, authorization, and object-level access "
                "verification procedure."
            ),
            doctrine=AUTH_ACCESS_CONTROL_DOCTRINE,
            planning_template=AUTH_ACCESS_CONTROL_PLAN,
            triggers=(
                "login",
                "auth",
                "session",
                "admin",
                "idor",
                "access control",
                "jwt",
                "oauth",
                "cookie",
            ),
        )
    )
    register_skill(
        Skill(
            name="web-scanner",
            version=1,
            description=(
                "Primary web-surface scanner: plan, map inputs, and route to "
                "the matching test skills."
            ),
            doctrine=WEB_SCANNER_DOCTRINE,
            planning_template=WEB_SCANNER_PLAN,
            can_access=(
                "injection-testing",
                "xss-testing",
                "auth-access-control",
            ),
        )
    )
    register_skill(
        Skill(
            name="bug-hunter",
            version=1,
            description=(
                "Primary bug-hunter funnel: map, decompile JavaScript, and "
                "escalate only on indicators."
            ),
            doctrine=BUG_HUNTER_DOCTRINE,
            planning_template=BUG_HUNTER_PLAN,
            can_access=(
                "injection-testing",
                "xss-testing",
                "auth-access-control",
            ),
        )
    )


_register_shipped()


def available_skills() -> tuple[Skill, ...]:
    """Return built-in skills in stable registry order."""
    return tuple(_SKILLS.values())


def _versioned_name(identifier: str) -> tuple[str, int | None]:
    name, separator, suffix = identifier.rpartition("-v")
    if separator and suffix.isdigit():
        return name, int(suffix)
    return identifier, None


def get_skill(identifier: str | Skill | None = None) -> Skill:
    """Resolve a skill by id (or ``name-vN``); ``None`` yields the default."""
    if isinstance(identifier, Skill):
        return identifier
    requested = str(identifier or DEFAULT_PRIMARY_SKILL_ID).strip()
    skill = _SKILLS.get(requested)
    if skill is not None:
        return skill
    name, version = _versioned_name(requested)
    candidate = _SKILLS.get(name)
    if candidate is not None and (version is None or candidate.version == version):
        return candidate
    choices = ", ".join(_SKILLS)
    raise SkillError(
        f"unknown skill {identifier!r}; available: {choices}"
    )


def primary_skill_for_pack(pack) -> Skill:
    """Map a prompt pack (versioned id or bare name) to its primary skill."""
    identifier = getattr(pack, "identifier", None)
    name = getattr(pack, "name", None)
    for key in (identifier, name):
        if key and key in PACK_PRIMARY_SKILLS:
            return get_skill(PACK_PRIMARY_SKILLS[key])
    return get_skill(DEFAULT_PRIMARY_SKILL_ID)


def resolve_primary_skill(
    primary_skill: str | Skill | None = None,
    prompt_pack=None,
) -> Skill:
    """Select the run's primary skill.

    An explicit skill wins.  Otherwise the pack's identity selects its mapped
    primary; custom packs (including Pro's) default to ``web-scanner``.
    """
    if primary_skill is not None:
        return get_skill(primary_skill)
    if prompt_pack is not None:
        return primary_skill_for_pack(prompt_pack)
    return get_skill(DEFAULT_PRIMARY_SKILL_ID)


def reachable_skill_ids(primary: Skill) -> set[str]:
    """All skill ids statically reachable from *primary* through ``can_access``."""
    seen: set[str] = set()
    stack = list(primary.can_access)
    while stack:
        skill_id = stack.pop()
        if skill_id in seen:
            continue
        try:
            skill = get_skill(skill_id)
        except SkillError:
            continue
        seen.add(skill.name)
        stack.extend(skill.can_access)
    return seen


def declared_tool_unlocks(primary: Skill) -> set[str]:
    """Every tool named by the primary or a statically reachable skill."""
    names = set(primary.tool_unlocks)
    for skill_id in reachable_skill_ids(primary):
        names.update(get_skill(skill_id).tool_unlocks)
    return names


def primary_plan_block(skill: Skill) -> str:
    """Render the primary planning template for the run prompt."""
    if not skill.planning_template:
        return ""
    lines = [
        f"PRIMARY SKILL PLAN ({skill.name})",
        "Instantiate these as your Phase 0 todos with todos_write, adapted to "
        "the target:",
    ]
    lines.extend(f"- {item}" for item in skill.planning_template)
    return "\n".join(lines)


def _format_planning_result(skill: Skill, granted: Iterable[str]) -> str:
    lines = [
        f"skill loaded: {skill.id} (v{skill.version})",
        "Planning template — merge these items into the existing todo list "
        "with todos_add; do not replace the list:",
    ]
    lines.extend(f"- {item}" for item in skill.planning_template)
    granted_names = list(granted)
    if granted_names:
        lines.append("Unlocked tools: " + ", ".join(granted_names))
    lines.append("Doctrine appended for this and following turns.")
    return "\n".join(lines)


class SkillRuntime:
    """Per-run skill state: reachable set, load order, and injections."""

    def __init__(
        self,
        primary: Skill,
        *,
        log: Callable[[str], None] | None = None,
        turn_source: Callable[[], int] | None = None,
    ) -> None:
        self.primary = primary
        self.loaded: list[str] = []
        self.access: list[str] = []
        self.agent = None
        self.log = log or (lambda *args: None)
        self.turn_source = turn_source or (lambda: 0)
        self._loaded: set[str] = set()
        self._extend_access(primary.can_access)

    def _extend_access(self, ids: Iterable[str]) -> None:
        for skill_id in ids:
            skill_id = str(skill_id)
            if skill_id == self.primary.name or skill_id in self.access:
                continue
            try:
                get_skill(skill_id)
            except SkillError:
                continue
            self.access.append(skill_id)

    def bind_agent(self, agent) -> None:
        self.agent = agent

    @property
    def loaded_ids(self) -> tuple[str, ...]:
        return tuple(self.loaded)

    def _current_turn(self) -> int:
        try:
            return max(0, int(self.turn_source()))
        except Exception:  # noqa: BLE001 - turn stamps must never break a load
            return 0

    def _reachable_text(self) -> str:
        return ", ".join(self.access) or "(none)"

    def catalog(self) -> str:
        if not self.access:
            return f"skills: (none reachable from {self.primary.id})"
        lines = [f"skills reachable from {self.primary.id}:"]
        for skill_id in self.access:
            try:
                skill = get_skill(skill_id)
            except SkillError:
                continue
            state = "loaded" if skill.id in self._loaded else "not loaded"
            lines.append(f"- {skill.id} [{state}] — {skill.description}")
        return "\n".join(lines)

    def load(self, skill_id: str) -> str:
        requested = str(skill_id or "").strip()
        if not requested:
            return (
                "error: a skill id is required; reachable: "
                f"{self._reachable_text()}"
            )
        try:
            skill = get_skill(requested)
        except SkillError:
            return (
                f"error: unknown skill {requested!r}; reachable: "
                f"{self._reachable_text()}"
            )
        if skill.id not in self.access:
            return (
                f"error: skill {skill.id!r} is not reachable; reachable: "
                f"{self._reachable_text()}"
            )
        if skill.id in self._loaded:
            return "already loaded"

        self.loaded.append(skill.id)
        self._loaded.add(skill.id)
        self._extend_access(skill.can_access)

        if self.agent is not None:
            self.agent.queue_injection(
                f"SKILL LOADED: {skill.id} (v{skill.version})\n"
                f"{skill.doctrine.strip()}"
            )
        granted = []
        if self.agent is not None and skill.tool_unlocks:
            granted = self.agent.add_tools(list(skill.tool_unlocks))

        self.log(f"[skill] loaded {skill.id} (turn {self._current_turn()})")
        return _format_planning_result(skill, granted)

    def preload(self, target_context: str | None) -> list[str]:
        """Load trigger-matching reachable skills before turn 1."""
        text = str(target_context or "").casefold()
        if not text:
            return []
        preloaded: list[str] = []
        # Loading one skill can extend the reachable set, so keep scanning
        # until a full pass adds nothing.
        while True:
            progress = False
            for skill_id in list(self.access):
                if skill_id in self._loaded:
                    continue
                try:
                    skill = get_skill(skill_id)
                except SkillError:
                    continue
                if any(
                    trigger.strip() and trigger.casefold() in text
                    for trigger in skill.triggers
                ):
                    result = self.load(skill_id)
                    if not result.startswith(("error:", "already loaded")):
                        preloaded.append(skill_id)
                        progress = True
            if not progress:
                break
        return preloaded

    def envelope(self) -> dict:
        return {
            "primary": self.primary.id,
            "loaded": list(self.loaded),
        }


def skill_tools(runtime: SkillRuntime) -> list[BaseTool]:
    """Build the parent-only ``skills_list`` and ``load_skill`` tools."""

    def skills_list() -> str:
        """List the skills reachable from the current primary skill.

        Shows each skill id, its one-line description, and whether it is
        loaded. Skills outside the access set are never listed.
        """
        return runtime.catalog()

    def load_skill(skill_id: str) -> str:
        """Load one reachable skill.

        Appends its doctrine for following turns, grants any declared tools,
        and returns the skill's planning template to merge with todos_add.
        """
        return runtime.load(skill_id)

    return [
        StructuredTool.from_function(
            skills_list,
            name="skills_list",
            description=(
                "List the skills reachable from the primary skill, with id, "
                "description, and loaded state. Use it before choosing a "
                "secondary skill to load."
            ),
        ),
        StructuredTool.from_function(
            load_skill,
            name="load_skill",
            description=(
                "Load one reachable skill by id. Its doctrine is appended for "
                "following turns and its planning template is returned; merge "
                "those items with todos_add instead of replacing the list."
            ),
        ),
    ]
