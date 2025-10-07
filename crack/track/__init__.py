"""
Enumeration Checklist Module

A modular, extensible target enumeration tracking system for OSCP preparation.

Usage:
    crack checklist <TARGET>                    # Interactive checklist
    crack checklist <TARGET> --import file.xml  # Import nmap results
    crack checklist <TARGET> --mark-done task   # Mark task complete
    crack checklist <TARGET> --export           # Generate markdown report
"""

from .core.state import TargetProfile
from .core.task_tree import TaskNode
from .core.events import EventBus

__all__ = [
    'TargetProfile',
    'TaskNode',
    'EventBus',
]

__version__ = '1.0.0'
