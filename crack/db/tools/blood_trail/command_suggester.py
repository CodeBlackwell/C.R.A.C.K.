"""
Blood-trail Attack Command Suggester

Generates attack command suggestions based on BloodHound query results.
Maps query findings to CRACK command database entries with variable substitution.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from .command_mappings import (
    QUERY_COMMAND_MAPPINGS,
    EDGE_COMMAND_MAPPINGS,
    VARIABLE_MAPPINGS,
    SENSITIVE_PLACEHOLDERS,
)


@dataclass
class CommandSuggestion:
    """Single command suggestion with template and ready-to-run versions"""
    command_id: str
    name: str
    context: str                              # Why this command for this result
    template: str                             # Command with <PLACEHOLDERS>
    ready_to_run: str                         # Command with values substituted
    variables_filled: Dict[str, str] = field(default_factory=dict)
    variables_needed: List[str] = field(default_factory=list)
    oscp_relevance: str = "medium"

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "command_id": self.command_id,
            "name": self.name,
            "context": self.context,
            "template": self.template,
            "ready_to_run": self.ready_to_run,
            "variables_filled": self.variables_filled,
            "variables_needed": self.variables_needed,
            "oscp_relevance": self.oscp_relevance,
        }


@dataclass
class AttackSequence:
    """Multi-step attack chain built from BloodHound path"""
    name: str
    description: str
    path_nodes: List[str]                     # Node names in path
    edge_types: List[str]                     # Edge types between nodes
    steps: List[CommandSuggestion] = field(default_factory=list)

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "name": self.name,
            "description": self.description,
            "path_nodes": self.path_nodes,
            "edge_types": self.edge_types,
            "steps": [s.to_dict() for s in self.steps],
            "total_steps": self.total_steps,
        }


class CommandSuggester:
    """
    Generates attack command suggestions from blood-trail query results.

    Maps BloodHound findings to CRACK command database entries,
    performing variable substitution from query result fields.

    Example:
        suggester = CommandSuggester()
        suggestions = suggester.suggest_for_query(
            "quick-asrep-roastable",
            [{"User": "MIKE@CORP.COM", "IsPrivileged": False}]
        )
    """

    def __init__(self, commands_db_path: Optional[Path] = None):
        """
        Initialize the suggester with command database.

        Args:
            commands_db_path: Path to CRACK commands directory.
                            Defaults to db/data/commands/
        """
        if commands_db_path is None:
            # Find commands relative to this file
            base = Path(__file__).parent.parent.parent.parent
            commands_db_path = base / "db" / "data" / "commands"

        self.commands_db_path = commands_db_path
        self.commands: Dict[str, Dict] = {}
        self._load_commands()

    def _load_commands(self):
        """Load all command definitions from CRACK database"""
        if not self.commands_db_path.exists():
            return

        for json_file in self.commands_db_path.rglob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)

                for cmd in data.get("commands", []):
                    if "id" in cmd:
                        self.commands[cmd["id"]] = cmd
            except Exception:
                continue  # Skip malformed files

    def suggest_for_query(
        self,
        query_id: str,
        records: List[Dict],
        max_per_record: int = 3,
        max_total: int = 10
    ) -> Union[List[CommandSuggestion], List[AttackSequence]]:
        """
        Generate command suggestions for a query result.

        Args:
            query_id: Blood-trail query ID (e.g., "quick-asrep-roastable")
            records: Query result records
            max_per_record: Maximum suggestions per record
            max_total: Maximum total suggestions

        Returns:
            List of CommandSuggestion objects, or AttackSequence for chain queries
        """
        mapping = QUERY_COMMAND_MAPPINGS.get(query_id)
        if not mapping:
            return []

        # Chain queries trigger sequence building
        if mapping == "BUILD_SEQUENCE":
            return self._build_sequences(query_id, records)

        suggestions = []
        seen_commands = set()

        for record in records[:max_total]:
            for cmd_info in mapping[:max_per_record]:
                cmd_id = cmd_info["command_id"]

                # Avoid duplicate commands for same target
                target = self._extract_target(record)
                key = (cmd_id, target)
                if key in seen_commands:
                    continue
                seen_commands.add(key)

                suggestion = self._create_suggestion(
                    cmd_id,
                    cmd_info["context"],
                    record
                )
                if suggestion:
                    suggestions.append(suggestion)

                if len(suggestions) >= max_total:
                    break
            if len(suggestions) >= max_total:
                break

        return suggestions

    def _extract_target(self, record: Dict) -> str:
        """Extract primary target identifier from record"""
        for field in ["Computer", "Target", "Victim", "User", "Principal"]:
            if field in record:
                return str(record[field])
        return ""

    def _create_suggestion(
        self,
        cmd_id: str,
        context: str,
        record: Dict
    ) -> Optional[CommandSuggestion]:
        """
        Create a single command suggestion with variable substitution.

        Args:
            cmd_id: Command ID from CRACK database
            context: Context string explaining why this command
            record: Query result record for variable extraction

        Returns:
            CommandSuggestion or None if command not found
        """
        cmd = self.commands.get(cmd_id)
        if not cmd:
            return None

        template = cmd.get("command", "")
        if not template:
            return None

        ready = template
        filled = {}
        needed = []

        # Auto-fill from record using VARIABLE_MAPPINGS
        for field_name, placeholder in VARIABLE_MAPPINGS.items():
            if field_name in record and placeholder in ready:
                value = str(record[field_name])
                # Clean up value (remove domain suffix for some fields)
                if "@" in value and placeholder == "<USERNAME>":
                    # Keep full UPN for now
                    pass
                ready = ready.replace(placeholder, value)
                filled[placeholder] = value

        # Identify remaining placeholders
        remaining = re.findall(r'<[A-Z_]+>', ready)
        for placeholder in remaining:
            if placeholder in SENSITIVE_PLACEHOLDERS:
                needed.append(placeholder)

        # Get OSCP relevance from command
        oscp_rel = cmd.get("oscp_relevance", "medium")
        if not oscp_rel:
            # Try to infer from tags
            tags = cmd.get("tags", [])
            for tag in tags:
                if tag.startswith("OSCP:"):
                    oscp_rel = tag.split(":")[1].lower()
                    break

        return CommandSuggestion(
            command_id=cmd_id,
            name=cmd.get("name", cmd_id),
            context=context,
            template=template,
            ready_to_run=ready,
            variables_filled=filled,
            variables_needed=needed,
            oscp_relevance=oscp_rel,
        )

    def _build_sequences(
        self,
        query_id: str,
        records: List[Dict],
        max_sequences: int = 3
    ) -> List[AttackSequence]:
        """
        Build multi-step attack sequences from path query results.

        Chain queries return paths with nodes and edges. This method
        generates attack sequences by mapping each edge to commands.

        Args:
            query_id: Query ID that triggered sequence building
            records: Path query results with Path/EdgeTypes fields
            max_sequences: Maximum number of sequences to generate

        Returns:
            List of AttackSequence objects
        """
        sequences = []

        for record in records[:max_sequences]:
            # Extract path information
            path = self._extract_path(record)
            edges = self._extract_edges(record)

            if not path or not edges:
                continue

            # Build steps for each edge
            steps = []
            for i, edge in enumerate(edges):
                # Get commands for this edge type
                cmd_ids = EDGE_COMMAND_MAPPINGS.get(edge, [])
                if not cmd_ids:
                    continue

                # Use primary command for the edge
                cmd_id = cmd_ids[0]

                # Build context record for variable substitution
                context_record = {}
                if i + 1 < len(path):
                    context_record["Target"] = path[i + 1]
                    context_record["Computer"] = path[i + 1]
                if i < len(path):
                    context_record["User"] = path[i]
                    context_record["Principal"] = path[i]

                step = self._create_suggestion(
                    cmd_id,
                    f"Step {i + 1}: {edge}",
                    context_record
                )
                if step:
                    steps.append(step)

            if steps:
                # Generate readable path name
                path_str = " -> ".join(path[:4])
                if len(path) > 4:
                    path_str += f" -> ... ({len(path)} total)"

                sequences.append(AttackSequence(
                    name=f"Path: {path_str}",
                    description=f"{len(steps)}-step attack chain via {', '.join(edges[:3])}",
                    path_nodes=path,
                    edge_types=edges,
                    steps=steps,
                ))

        return sequences

    def _extract_path(self, record: Dict) -> List[str]:
        """Extract path nodes from query result"""
        # Different queries use different field names
        for field in ["Path", "path", "Nodes", "nodes"]:
            if field in record:
                val = record[field]
                if isinstance(val, list):
                    return [str(n) for n in val]
                elif isinstance(val, str):
                    # Parse string path like "A -> B -> C"
                    return [n.strip() for n in val.split("->")]
        return []

    def _extract_edges(self, record: Dict) -> List[str]:
        """Extract edge types from query result"""
        for field in ["EdgeTypes", "edgeTypes", "Edges", "edges", "RelationshipTypes"]:
            if field in record:
                val = record[field]
                if isinstance(val, list):
                    return [str(e) for e in val]
                elif isinstance(val, str):
                    return [e.strip() for e in val.split(",")]
        return []

    def get_commands_for_edge(self, edge_type: str) -> List[CommandSuggestion]:
        """
        Get all commands applicable for a specific edge type.

        Args:
            edge_type: BloodHound edge type (e.g., "AdminTo", "GenericAll")

        Returns:
            List of CommandSuggestion objects
        """
        cmd_ids = EDGE_COMMAND_MAPPINGS.get(edge_type, [])
        suggestions = []

        for cmd_id in cmd_ids:
            suggestion = self._create_suggestion(
                cmd_id,
                f"Exploit {edge_type} relationship",
                {}
            )
            if suggestion:
                suggestions.append(suggestion)

        return suggestions

    def suggest_for_owned_user(
        self,
        user: str,
        access_types: List[Dict]
    ) -> List[CommandSuggestion]:
        """
        Generate suggestions for an owned user's access.

        Args:
            user: Owned user principal name
            access_types: List of access records (Target, AccessType, etc.)

        Returns:
            List of CommandSuggestion objects
        """
        suggestions = []
        seen = set()

        for access in access_types:
            target = access.get("Target", access.get("Computer", ""))
            access_type = access.get("AccessType", "AdminTo")

            # Get commands for this access type
            cmd_ids = EDGE_COMMAND_MAPPINGS.get(access_type, [])

            for cmd_id in cmd_ids[:2]:  # Max 2 commands per access
                key = (cmd_id, target)
                if key in seen:
                    continue
                seen.add(key)

                record = {
                    "User": user,
                    "Target": target,
                    "Computer": target,
                }

                suggestion = self._create_suggestion(
                    cmd_id,
                    f"{access_type} to {target}",
                    record
                )
                if suggestion:
                    suggestions.append(suggestion)

        return suggestions
