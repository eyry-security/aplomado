"""Visible, versioned prompt packs and overrides for Aplomado scans."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path


_PROMPT_TOKEN = re.compile(r"\{(target|target_context_block)\}")


class PromptError(ValueError):
    """A prompt pack name, template, or override file is invalid."""


@dataclass(frozen=True)
class PromptPack:
    """One immutable, versioned pair of system and per-run prompts."""

    name: str
    version: int
    system_prompt: str
    run_prompt_template: str
    overrides: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise PromptError("prompt pack name cannot be empty")
        if self.version < 1:
            raise PromptError("prompt pack version must be positive")
        if not self.system_prompt.strip():
            raise PromptError("system prompt cannot be empty")
        if not self.run_prompt_template.strip():
            raise PromptError("run prompt template cannot be empty")
        if "{target}" not in self.run_prompt_template:
            raise PromptError("run prompt template must contain {target}")

    @property
    def identifier(self) -> str:
        """Stable built-in ID, with an explicit suffix for local overrides."""
        identifier = f"{self.name}-v{self.version}"
        if self.overrides:
            identifier += "+" + "+".join(self.overrides)
        return identifier

    def render(self, target: str, target_context: str | None = None) -> str:
        """Render only documented tokens; unrelated braces remain untouched."""
        context_block = f"{target_context}\n\n" if target_context else ""
        values = {"target": target, "target_context_block": context_block}
        return _PROMPT_TOKEN.sub(lambda match: values[match.group(1)], self.run_prompt_template)


# The full security-reviewer system prompt. Changes here require a new pack
# version so operators can identify exactly which instructions drove a scan.
SYSTEM_PROMPT = """\
You are Aplomado, an AI security reviewer — the strike half of the Eyry suite.

Your job: investigate one target from inside a sandbox and report what you find.

SCOPE
- Probe, don't attack. Light recon only: DNS, HTTP requests, TLS handshakes.
  No brute-forcing, no fuzzing storms, no credential stuffing, no exploiting.
- The operator pointed you at this target; assume they're authorized, but stay
  on the target — don't wander to other hosts or scopes.

YOUR TOOLS
- shell(command): runs inside the sandbox through a strict command allowlist.
  Simple pipelines of light-recon tools are supported; shell expansion,
  redirection, background jobs, destructive utilities, and host-control tools
  are blocked. Python is available only in the default container sandbox.
- ffuf(url, wordlist="default", extra_args=""): content discovery with ffuf —
  finds hidden paths and exposed files. The URL needs the FUZZ keyword
  (added for you if missing); the ffuf binary is fetched automatically on
  first use, so don't install it yourself.
- fetch_url(url): plain GET from the host (no JS). Good for quick page pulls.
- read_file(path): reads files from the sandbox workdir.
- write_file(path, content): writes scratch files under scratch/ only. Writes
  over 1 MB, sensitive filenames, path traversal, and symlink paths are blocked.
- finish(result_json): end the run. Call it exactly once, when you're done.

RECON PLAYBOOK (adapt to the target; skip what doesn't apply)
1. DNS: dig +short A/AAAA/MX/TXT <host>; note wildcard DNS if present.
2. HTTP surface: curl -sSI http:// and https:// (redirects, HSTS, Server and
   X-Powered-By headers); GET / and skim the status, headers, and title.
3. TLS: python3's ssl module or openssl s_client -connect for cert
   subject/issuer/expiry and the protocol versions offered.
4. Security headers: content-security-policy, strict-transport-security,
   x-frame-options, x-content-type-options, referrer-policy.
5. Common files: /robots.txt, /security.txt, /.well-known/security.txt,
   /.git/HEAD, /server-status, /.env — GET each and note the status code.
6. Record versions and technologies wherever they're exposed.

BE HONEST ABOUT TOOL LIMITS
- The sandbox image is slim: curl, python3, and dig are usually there; nmap,
  masscan, gobuster, nikto, and friends are NOT. Run `command -v <tool>`
  before depending on one. If it's missing, do the job with curl/python
  instead. Never claim you ran a tool you didn't.

FINISH FORMAT
Call finish() with a single JSON object, as a string:
{
  "target": "<host or URL>",
  "summary": "<one paragraph: overall verdict>",
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "<one line>",
      "detail": "<what it is and why it matters>",
      "evidence": "<the actual observed output that proves it — short>"
    }
  ]
}

Severity guide: critical = remotely exploitable now; high = serious weakness,
likely exploitable; medium = misconfiguration that aids an attacker;
low = hygiene issue; info = observation worth noting. Nothing found? Emit one
info finding describing what you checked. Never invent evidence: if you didn't
observe it, don't report it.
"""

RUN_PROMPT_TEMPLATE = """\
TARGET: {target}

{target_context_block}Investigate the target, then call finish() with your findings JSON."""

DEFAULT_PROMPT_PACK_ID = "recon-v1"
_RECON_V1 = PromptPack(
    name="recon",
    version=1,
    system_prompt=SYSTEM_PROMPT,
    run_prompt_template=RUN_PROMPT_TEMPLATE,
)
_PROMPT_PACKS = {DEFAULT_PROMPT_PACK_ID: _RECON_V1}


def available_prompt_packs() -> tuple[PromptPack, ...]:
    """Return built-in packs in stable display order."""
    return tuple(_PROMPT_PACKS.values())


def get_prompt_pack(identifier: str | None = None) -> PromptPack:
    """Resolve a built-in prompt pack; ``default`` tracks the current default."""
    requested = identifier or DEFAULT_PROMPT_PACK_ID
    if requested == "default":
        requested = DEFAULT_PROMPT_PACK_ID
    try:
        return _PROMPT_PACKS[requested]
    except KeyError as exc:
        choices = ", ".join(_PROMPT_PACKS)
        raise PromptError(
            f"unknown prompt pack {identifier!r}; available: {choices}"
        ) from exc


def _read_override(path: str, label: str) -> str:
    try:
        content = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PromptError(f"cannot read {label} {path!r}: {exc}") from exc
    if not content.strip():
        raise PromptError(f"{label} {path!r} is empty")
    return content


def load_prompt_pack(
    identifier: str | None = None,
    *,
    system_prompt_file: str | None = None,
    run_prompt_file: str | None = None,
) -> PromptPack:
    """Resolve a built-in pack and apply optional UTF-8 text-file overrides."""
    pack = get_prompt_pack(identifier)
    overrides: list[str] = []
    changes: dict[str, object] = {}
    if system_prompt_file:
        changes["system_prompt"] = _read_override(
            system_prompt_file, "system prompt file"
        )
        overrides.append("system")
    if run_prompt_file:
        changes["run_prompt_template"] = _read_override(
            run_prompt_file, "run prompt file"
        )
        overrides.append("run")
    if not changes:
        return pack
    changes["overrides"] = tuple(overrides)
    return replace(pack, **changes)


def build_prompt(
    target: str,
    target_context: str | None = None,
    prompt_pack: PromptPack | None = None,
) -> str:
    """Assemble the run prompt using the selected pack."""
    return (prompt_pack or get_prompt_pack()).render(target, target_context)
