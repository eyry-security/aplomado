"""Model selection defaults shared by the CLI, scanner, and thinking paths."""

from __future__ import annotations

import os

DEFAULT_MODEL = "deepseek:deepseek-flash"


def resolve_model(model=None):
    """Return an explicit model, else $PINNACE_MODEL, else Aplomado's default."""
    if model is not None:
        return model
    return os.environ.get("PINNACE_MODEL") or DEFAULT_MODEL
