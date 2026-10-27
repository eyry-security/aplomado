"""Compatibility module for the authenticated screenshot tool.

The implementation lives in :mod:`aplomado.browser`; this module re-exports the
screenshot-facing names for callers that group evidence capture separately.
"""

from .browser import (
    BrowserError,
    BrowserSession,
    SHOT_DIR,
    capture_screenshot,
    format_screenshot,
    is_login_url,
    screenshot_path,
    screenshot_tool,
)

__all__ = [
    "BrowserError",
    "BrowserSession",
    "SHOT_DIR",
    "capture_screenshot",
    "format_screenshot",
    "is_login_url",
    "screenshot_path",
    "screenshot_tool",
]
