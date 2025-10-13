"""Chain session storage for interactive execution progress tracking.

Enhanced session management:
- Save/load current step index
- Persist variables across steps (session-scoped)
- Store step-scoped variables (from parsing)
- Store parsed findings for inspection
- Enable resume functionality with full context
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
        self.variables: Dict[str, str] = {}  # Session-scoped variables
        self.step_outputs: Dict[str, str] = {}  # Raw command outputs
        self.step_findings: Dict[str, Dict[str, Any]] = {}  # Parsed findings per step
        self.step_variables: Dict[str, Dict[str, str]] = {}  # Step-scoped variables
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
        """Add/update session-scoped variables

        Args:
            new_vars: Variables to persist across all steps
        """
        self.variables.update(new_vars)
        self.updated = datetime.now().isoformat()

    def store_step_findings(self, step_id: str, findings: Dict[str, Any]):
        """Store parsed findings for a step

        Args:
            step_id: Step identifier
            findings: Findings dictionary from parser
        """
        self.step_findings[step_id] = findings
        self.updated = datetime.now().isoformat()

    def store_step_variables(self, step_id: str, variables: Dict[str, str]):
        """Store step-scoped variables (from parsing/selection)

        Args:
            step_id: Step identifier
            variables: Variables specific to this step
        """
        self.step_variables[step_id] = variables
        self.updated = datetime.now().isoformat()

    def get_step_findings(self, step_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve findings for a specific step

        Args:
            step_id: Step identifier

        Returns:
            Findings dict or None
        """
        return self.step_findings.get(step_id)

    def get_step_variables(self, step_id: str) -> Dict[str, str]:
        """Retrieve variables for a specific step

        Args:
            step_id: Step identifier

        Returns:
            Variables dict (empty if not found)
        """
        return self.step_variables.get(step_id, {})

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
            'step_findings': self.step_findings,
            'step_variables': self.step_variables,
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
            session.step_findings = data.get('step_findings', {})
            session.step_variables = data.get('step_variables', {})
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
