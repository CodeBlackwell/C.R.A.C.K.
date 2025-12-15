"""
Cheatsheet Registry - Management for educational cheatsheet collections
"""

import json
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class CheatsheetScenario:
    """Represents a detailed scenario within a cheatsheet"""
    title: str
    context: str
    approach: str
    commands: List[str]  # Command IDs
    expected_outcome: str
    why_this_works: str


@dataclass
class CheatsheetSection:
    """Represents a section within a cheatsheet"""
    title: str
    notes: str
    commands: List[str]  # Command IDs


@dataclass
class EducationalHeader:
    """Educational context for recognizing when to use this cheatsheet"""
    how_to_recognize: List[str]
    when_to_look_for: List[str]


@dataclass
class Cheatsheet:
    """Represents a complete cheatsheet collection"""
    id: str
    name: str
    description: str
    educational_header: EducationalHeader
    scenarios: List[CheatsheetScenario]
    sections: List[CheatsheetSection]
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> 'Cheatsheet':
        """Create from dictionary"""
        # Parse educational header
        header_data = data.get('educational_header', {})
        educational_header = EducationalHeader(
            how_to_recognize=header_data.get('how_to_recognize', []),
            when_to_look_for=header_data.get('when_to_look_for', [])
        )

        # Parse scenarios
        scenarios = []
        for scenario_data in data.get('scenarios', []):
            scenarios.append(CheatsheetScenario(
                title=scenario_data.get('title', ''),
                context=scenario_data.get('context', ''),
                approach=scenario_data.get('approach', ''),
                commands=scenario_data.get('commands', []),
                expected_outcome=scenario_data.get('expected_outcome', ''),
                why_this_works=scenario_data.get('why_this_works', '')
            ))

        # Parse sections
        sections = []
        for section_data in data.get('sections', []):
            sections.append(CheatsheetSection(
                title=section_data.get('title', ''),
                notes=section_data.get('notes', ''),
                commands=section_data.get('commands', [])
            ))

        return cls(
            id=data.get('id', ''),
            name=data.get('name', ''),
            description=data.get('description', ''),
            educational_header=educational_header,
            scenarios=scenarios,
            sections=sections,
            tags=data.get('tags', [])
        )

    def get_all_command_refs(self) -> List[str]:
        """Get all unique command IDs referenced in this cheatsheet"""
        command_ids = set()

        # From scenarios
        for scenario in self.scenarios:
            command_ids.update(scenario.commands)

        # From sections
        for section in self.sections:
            command_ids.update(section.commands)

        return sorted(list(command_ids))


class CheatsheetRegistry:
    """Registry for managing cheatsheet collections"""

    def __init__(self, base_path: str = None, command_registry=None, theme=None):
        """
        Initialize cheatsheet registry

        Args:
            base_path: Path to reference/ directory
            command_registry: HybridCommandRegistry or SQLCommandRegistryAdapter for resolving command refs
            theme: ReferenceTheme for colored output
        """
        if base_path is None:
            base_path = Path(__file__).parent.parent
        self.base_path = Path(base_path)
        self.command_registry = command_registry
        self.theme = theme
        if self.theme is None:
            from crack.core.themes.colors import ReferenceTheme
            self.theme = ReferenceTheme()

        self.cheatsheets: Dict[str, Cheatsheet] = {}
        self._load_cheatsheets()

    def _load_cheatsheets(self):
        """Load cheatsheets from JSON files (recursively searches subdirectories)"""
        cheatsheets_path = self.base_path / 'data' / 'cheatsheets'
        if not cheatsheets_path.exists():
            cheatsheets_path.mkdir(parents=True, exist_ok=True)
            return

        # Load all JSON files in cheatsheets directory and subdirectories
        for json_file in cheatsheets_path.rglob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                    # Support both single cheatsheet and array format
                    if 'cheatsheets' in data:
                        # Array format (matches schema)
                        for sheet_data in data['cheatsheets']:
                            sheet = Cheatsheet.from_dict(sheet_data)
                            self.cheatsheets[sheet.id] = sheet
                    else:
                        # Single cheatsheet format (simpler for individual files)
                        sheet = Cheatsheet.from_dict(data)
                        self.cheatsheets[sheet.id] = sheet
            except Exception as e:
                print(f"{self.theme.error('Error')} loading {json_file}: {e}")

    def get_cheatsheet(self, cheatsheet_id: str) -> Optional[Cheatsheet]:
        """Get cheatsheet by ID"""
        return self.cheatsheets.get(cheatsheet_id)

    def list_cheatsheets(self) -> List[Cheatsheet]:
        """Get all cheatsheets"""
        return list(self.cheatsheets.values())

    def search_cheatsheets(self, query: str) -> List[Cheatsheet]:
        """Search cheatsheets by name, description, or tags"""
        query_lower = query.lower()
        results = []

        for sheet in self.cheatsheets.values():
            # Check name, description, tags
            if (query_lower in sheet.name.lower() or
                query_lower in sheet.description.lower() or
                any(query_lower in tag.lower() for tag in sheet.tags)):
                results.append(sheet)

        return results

    def filter_by_tags(self, tags: List[str]) -> List[Cheatsheet]:
        """Filter cheatsheets by tags (case-insensitive)"""
        tags_upper = [tag.upper() for tag in tags]
        results = []

        for sheet in self.cheatsheets.values():
            sheet_tags_upper = [tag.upper() for tag in sheet.tags]
            if all(tag in sheet_tags_upper for tag in tags_upper):
                results.append(sheet)

        return results

    def resolve_command(self, command_id: str):
        """
        Resolve a command ID to a Command object

        Returns:
            Command object or None if not found
        """
        if self.command_registry is None:
            return None
        return self.command_registry.get_command(command_id)

    def validate_command_refs(self, cheatsheet: Cheatsheet) -> Dict[str, Any]:
        """
        Validate that all command references in a cheatsheet exist

        Returns:
            Dict with 'valid' bool and 'missing' list of command IDs
        """
        if self.command_registry is None:
            return {'valid': False, 'missing': [], 'error': 'No command registry available'}

        missing = []
        for cmd_id in cheatsheet.get_all_command_refs():
            if self.command_registry.get_command(cmd_id) is None:
                missing.append(cmd_id)

        return {
            'valid': len(missing) == 0,
            'missing': missing
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        total_scenarios = sum(len(sheet.scenarios) for sheet in self.cheatsheets.values())
        total_sections = sum(len(sheet.sections) for sheet in self.cheatsheets.values())
        total_command_refs = sum(len(sheet.get_all_command_refs()) for sheet in self.cheatsheets.values())

        return {
            'total_cheatsheets': len(self.cheatsheets),
            'total_scenarios': total_scenarios,
            'total_sections': total_sections,
            'total_command_references': total_command_refs,
            'cheatsheet_ids': sorted(self.cheatsheets.keys())
        }
