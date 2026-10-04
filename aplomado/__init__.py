"""Aplomado — sandboxed AI security scanner built on Pinnace."""

from .config import ScanConfig
from .findings import Finding, ScanResult
from .scanner import Scanner

__version__ = "0.1.0"
__all__ = ["Finding", "ScanConfig", "Scanner", "ScanResult", "__version__"]
