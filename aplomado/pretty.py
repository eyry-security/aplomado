"""Terminal pretty-printing for Aplomado.

Colors are ANSI-only (no dependencies) and automatically disabled when
stderr/stdout isn't a TTY or NO_COLOR is set, so pipes and --json stay clean.
"""

from __future__ import annotations

import os
import sys

_CODES = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

_SEVERITY_COLORS = {
    "critical": ("red", "bold"),
    "high": ("red",),
    "medium": ("yellow",),
    "low": ("green",),
    "info": ("blue",),
}


def _enabled(stream) -> bool:
    return stream.isatty() and os.environ.get("NO_COLOR") is None


def color(text: str, *names: str, stream=None) -> str:
    """Wrap text in ANSI codes. Plain text when color is disabled."""
    if not _enabled(stream or sys.stderr):
        return text
    codes = "".join(_CODES[n] for n in names if n in _CODES)
    return f"{codes}{text}{_CODES['reset']}" if codes else text


def severity_tag(severity: str, stream=None) -> str:
    """Colored [SEVERITY] tag, e.g. [HIGH] in red."""
    s = (severity or "info").upper()
    return color(f"[{s}]", *_SEVERITY_COLORS.get(s.lower(), ()), stream=stream)


def colorize_log(msg: str) -> str:
    """Highlight nested [pinnace] markers in a log line."""
    if "[pinnace]" not in msg:
        return msg
    msg = msg.replace("[pinnace]", color("[pinnace]", "blue", "bold"))
    if "tool:" in msg:
        msg = msg.replace("tool:", color("tool:", "yellow"))
    if "turn " in msg:
        # highlight the turn number phrase dimly
        import re

        msg = re.sub(
            r"turn \d+",
            lambda m: color(m.group(0), "dim"),
            msg,
        )
    if "finish()" in msg:
        msg = msg.replace("finish()", color("finish()", "green", "bold"))
    return msg
