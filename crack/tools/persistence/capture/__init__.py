"""
Command capture layer for the persistence system.

Provides captured_run() - a drop-in replacement for subprocess.run()
that automatically persists all command I/O.
"""

from .subprocess_wrapper import captured_run, CapturedResult, CapturedRunner

__all__ = [
    "captured_run",
    "CapturedResult",
    "CapturedRunner",
]
