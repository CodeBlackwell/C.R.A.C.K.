"""Chain session storage for interactive execution progress tracking.

Minimal session management:
- Save/load current step index
- Persist variables across steps
- Enable resume functionality
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime


class ChainSession:
    """Minimal chain progress tracking for interactive execution"""

    def __init__(self, chain_id: str, target: str):
        """Initialize new chain session

        Args:
            chain_id: Unique chain identifier
            target: Target IP/hostname
        """
        self.chain_id = chain_id
        self.target = target
        self.current_step_index = 0
        self.completed_steps: List[str] = []
        self.variables: Dict[str, str] = {}  # Persist across steps
        self.step_outputs: Dict[str, str] = {}  # Store outputs for reference
        self.started = datetime.now().isoformat()
        self.updated = self.started

    def mark_step_complete(self, step_id: str, output: Optional[str] = None):
        """Mark step as complete and store output

        Args:
            step_id: Step identifier
            output: Command output (optional)
        """
        if step_id not in self.completed_steps:
            self.completed_steps.append(step_id)

        if output:
            self.step_outputs[step_id] = output

        self.updated = datetime.now().isoformat()

    def advance_step(self):
        """Move to next step"""
        self.current_step_index += 1
        self.updated = datetime.now().isoformat()

    def add_variables(self, new_vars: Dict[str, str]):
        """Add/update variables from current step

        Args:
            new_vars: Variables to persist
        """
        self.variables.update(new_vars)
        self.updated = datetime.now().isoformat()

    def save(self):
        """Save session to ~/.crack/chain_sessions/{chain_id}-{target}.json"""
        session_dir = Path.home() / '.crack' / 'chain_sessions'
        session_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize target for filename (replace dots/colons with underscores)
        safe_target = self.target.replace('.', '_').replace(':', '_')
        session_file = session_dir / f"{self.chain_id}-{safe_target}.json"

        data = {
            'chain_id': self.chain_id,
            'target': self.target,
            'current_step_index': self.current_step_index,
            'completed_steps': self.completed_steps,
            'variables': self.variables,
            'step_outputs': self.step_outputs,
            'started': self.started,
            'updated': self.updated
        }

        with open(session_file, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, chain_id: str, target: str) -> Optional['ChainSession']:
        """Load existing session or return None

        Args:
            chain_id: Unique chain identifier
            target: Target IP/hostname

        Returns:
            ChainSession if exists, None otherwise
        """
        session_dir = Path.home() / '.crack' / 'chain_sessions'
        safe_target = target.replace('.', '_').replace(':', '_')
        session_file = session_dir / f"{chain_id}-{safe_target}.json"

        if not session_file.exists():
            return None

        try:
            with open(session_file, 'r') as f:
                data = json.load(f)

            # Reconstruct session from data
            session = cls(data['chain_id'], data['target'])
            session.current_step_index = data.get('current_step_index', 0)
            session.completed_steps = data.get('completed_steps', [])
            session.variables = data.get('variables', {})
            session.step_outputs = data.get('step_outputs', {})
            session.started = data.get('started', session.started)
            session.updated = data.get('updated', session.updated)

            return session

        except (json.JSONDecodeError, KeyError) as e:
            # Corrupted session file - return None to start fresh
            return None

    @classmethod
    def exists(cls, chain_id: str, target: str) -> bool:
        """Check if session file exists

        Args:
            chain_id: Unique chain identifier
            target: Target IP/hostname

        Returns:
            True if session exists
        """
        session_dir = Path.home() / '.crack' / 'chain_sessions'
        safe_target = target.replace('.', '_').replace(':', '_')
        session_file = session_dir / f"{chain_id}-{safe_target}.json"
        return session_file.exists()

    def delete(self):
        """Delete session file"""
        session_dir = Path.home() / '.crack' / 'chain_sessions'
        safe_target = self.target.replace('.', '_').replace(':', '_')
        session_file = session_dir / f"{self.chain_id}-{safe_target}.json"

        if session_file.exists():
            session_file.unlink()
