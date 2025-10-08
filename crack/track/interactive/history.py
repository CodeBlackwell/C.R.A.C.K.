"""Command History - Track and search executed commands"""

from typing import List, Dict, Any, Optional
from datetime import datetime


class CommandHistory:
    """Track command execution history"""

    def __init__(self):
        self.commands: List[Dict[str, Any]] = []
        self.max_size = 100  # Limit history size

    def add(self, command: str, source: str, task_id: str = None, success: bool = True):
        """Add command to history

        Args:
            command: Full command string
            source: Source (template, manual, task)
            task_id: Task ID if from task execution
            success: Whether command succeeded
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'source': source,
            'task_id': task_id,
            'success': success
        }

        self.commands.append(entry)

        # Trim if exceeds max size
        if len(self.commands) > self.max_size:
            self.commands = self.commands[-self.max_size:]

    def search(self, query: str, fuzzy_matcher=None) -> List[tuple]:
        """Search history with fuzzy matching

        Args:
            query: Search query string
            fuzzy_matcher: Function(query, text) -> (bool, score)

        Returns:
            List of (entry, score) tuples sorted by score descending
        """
        if not fuzzy_matcher:
            # Simple substring match
            results = [(cmd, 80) for cmd in self.commands if query.lower() in cmd['command'].lower()]
            return results

        results = []
        for cmd in self.commands:
            match, score = fuzzy_matcher(query, cmd['command'])
            if match and score >= 40:
                results.append((cmd, score))

        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent commands

        Args:
            limit: Number of recent commands to return

        Returns:
            List of command entries
        """
        return list(reversed(self.commands[-limit:]))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for checkpoint"""
        return {
            'commands': self.commands,
            'max_size': self.max_size
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CommandHistory':
        """Deserialize from checkpoint"""
        history = cls()
        history.commands = data.get('commands', [])
        history.max_size = data.get('max_size', 100)
        return history
