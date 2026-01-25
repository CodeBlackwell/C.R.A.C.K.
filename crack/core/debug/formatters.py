"""Log formatters for console and JSON output."""

import json
from typing import Dict, Any


class Colors:
    """ANSI color codes for debug output."""
    DIM = '\033[2m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class ConsoleFormatter:
    """Format log entries for colored console output."""

    LEVEL_COLORS = {
        "verbose": Colors.DIM,
        "normal": Colors.CYAN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
    }

    LEVEL_PREFIXES = {
        "verbose": "[.]",
        "normal": "[*]",
        "warning": "[!]",
        "error": "[X]",
    }

    def format(self, entry: Dict[str, Any]) -> str:
        """Format entry for console output."""
        level = entry.get("level", "normal")
        color = self.LEVEL_COLORS.get(level, "")
        prefix = self.LEVEL_PREFIXES.get(level, "[*]")

        component = entry.get("component", "")
        step = entry.get("step", "")
        message = entry.get("message", "")

        # Format context (key=value pairs)
        context_parts = []
        for key, value in entry.items():
            if key in ("timestamp", "component", "step", "level", "message"):
                continue
            # Truncate long values
            val_str = str(value)
            if len(val_str) > 50:
                val_str = val_str[:47] + "..."
            context_parts.append(f"{key}={val_str}")

        context_str = f" {Colors.DIM}[{', '.join(context_parts)}]{Colors.RESET}" if context_parts else ""

        return f"{color}{prefix}{Colors.RESET} {Colors.MAGENTA}{component}/{step}{Colors.RESET}: {message}{context_str}"


class JsonFormatter:
    """Format log entries as JSON lines."""

    def format(self, entry: Dict[str, Any]) -> str:
        """Format entry as JSON line."""
        return json.dumps(entry, default=str)
