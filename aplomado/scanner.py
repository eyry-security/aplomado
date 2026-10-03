"""Run an Aplomado scan: a PinnaceAgent with the security-reviewer prompt."""

from __future__ import annotations

import json

from pinnace import PinnaceAgent

from .findings import normalize_findings

SYSTEM_PROMPT = """You are Aplomado, an AI security reviewer — the strike half of the Eyry suite.
Your job: investigate one target from inside a sandbox and report what you find.

SCOPE
- Probe, don't attack. Light recon only: DNS, HTTP requests, TLS handshakes.
  No brute-forcing, no fuzzing storms, no credential stuffing, no exploiting.
- The operator pointed you at this target; assume they're authorized, but stay
  on the target — don't wander to other hosts or scopes.

YOUR TOOLS
- shell(command): runs inside the sandbox. Prefer curl and python3.
- fetch_url(url): plain GET from the host (no JS). Good for quick page pulls.
- read_file / write_file: sandbox workdir scratch space.
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


class AplomadoError(RuntimeError):
    """Aplomado-side failures: bad input, missing files, scan setup."""


def load_target_file(path: str) -> tuple[str, str]:
    """Read one Vedette JSONL record; return (target label, context block).

    Takes the first non-empty line. The label prefers url > host > input.
    Raises AplomadoError on missing file, empty file, or bad JSON.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            line = next((ln.strip() for ln in fh if ln.strip()), "")
    except OSError as e:
        raise AplomadoError(f"can't read target file {path!r}: {e}") from e
    if not line:
        raise AplomadoError(f"target file {path!r} is empty")
    try:
        record = json.loads(line)
    except json.JSONDecodeError as e:
        raise AplomadoError(f"target file {path!r}: first line isn't JSON: {e}") from e
    if not isinstance(record, dict):
        raise AplomadoError(f"target file {path!r}: first line isn't a JSON object")
    label = (
        record.get("url") or record.get("host") or record.get("input") or line[:120]
    )
    context = "Target context (one Vedette prober record):\n" + json.dumps(
        record, indent=2
    )
    return str(label), context


def build_prompt(target: str, target_context: str | None = None) -> str:
    """Assemble the run prompt from the target and optional prober context."""
    parts = [f"TARGET: {target}"]
    if target_context:
        parts.append(target_context)
    parts.append("Investigate the target, then call finish() with your findings JSON.")
    return "\n\n".join(parts)


def _unwrap_finish_payload(structured: object) -> object:
    """Undo pinnace's finish() wrapping.

    finish() takes a JSON object as a string; when the model hands it something
    that isn't valid JSON, parse_finish returns {"result": <raw string>}.
    Unwrap that single-key form so normalization sees the raw payload.
    """
    if isinstance(structured, dict) and set(structured) == {"result"}:
        return structured["result"]
    return structured


def run_scan(
    target: str,
    *,
    model=None,
    sandbox=None,
    target_context: str | None = None,
    max_turns: int = 30,
    session_id: str | None = None,
    session_store=None,
    log=None,
) -> dict:
    """Run one scan and return the normalized findings envelope.

    model: a langchain chat model, a "provider:model" ref, or None (then
        PinnaceAgent falls back to $PINNACE_MODEL / its default).
    sandbox: a pinnace Sandbox, or None for the default Docker sandbox.
    """
    agent = PinnaceAgent(
        model=model,
        sandbox=sandbox,
        system_prompt=SYSTEM_PROMPT,
        max_turns=max_turns,
        session_id=session_id,
        session_store=session_store,
        log=log or (lambda *a: None),
    )
    result = agent.run(build_prompt(target, target_context))
    if result.finished:
        return normalize_findings(_unwrap_finish_payload(result.structured), target)
    return normalize_findings(
        {
            "summary": result.final or "scan ended without calling finish()",
            "findings": [],
        },
        target,
    )
