"""
Hybrid Command Registry - Core functionality for command management
"""

import json
import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
import glob


@dataclass
class CommandVariable:
    """Represents a variable/placeholder in a command"""
    name: str
    description: str
    example: str = ""
    required: bool = True
    common_values: List[str] = field(default_factory=list)


@dataclass
class FlagDefinition:
    """Represents a command-line flag with description"""
    flag: str
    description: str
    default_value: Optional[str] = None


@dataclass
class ExampleDefinition:
    """Represents a command usage example"""
    command: str
    description: str
    context: str = ""


@dataclass
class EducationalContent:
    """Represents educational/learning content for a command"""
    purpose: str = ""
    manual_alternative: str = ""
    common_failures: List[str] = field(default_factory=list)
    when_to_use: List[str] = field(default_factory=list)
    time_estimate: str = ""
    technical_notes: List[str] = field(default_factory=list)


@dataclass
class Command:
    """Represents a reference command"""
    id: str
    name: str
    category: str
    command: str
    description: str
    subcategory: str = ""
    filled_example: str = ""  # Pre-defined example with placeholders filled
    tags: List[str] = field(default_factory=list)
    variables: List[CommandVariable] = field(default_factory=list)
    flag_explanations: Dict[str, str] = field(default_factory=dict)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    troubleshooting: Dict[str, str] = field(default_factory=dict)
    notes: str = ""
    oscp_relevance: str = "medium"
    # Educational fields for technique selection
    advantages: List[str] = field(default_factory=list)
    disadvantages: List[str] = field(default_factory=list)
    use_cases: List[str] = field(default_factory=list)
    # Additional metadata fields for auto-generated commands
    output_analysis: List[str] = field(default_factory=list)
    common_uses: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    # PowerShell/platform-specific fields
    os: str = ""
    flags: List[FlagDefinition] = field(default_factory=list)
    examples: List[ExampleDefinition] = field(default_factory=list)
    educational: Optional[EducationalContent] = None
    oscp_priority: str = ""
    related_commands: List[str] = field(default_factory=list)
    custom_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Handle nested dataclasses
        data['variables'] = [asdict(var) for var in self.variables]
        if self.flags:
            data['flags'] = [asdict(flag) for flag in self.flags]
        if self.examples:
            data['examples'] = [asdict(ex) for ex in self.examples]
        if self.educational:
            data['educational'] = asdict(self.educational)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> 'Command':
        """Create from dictionary - filters unknown fields and deserializes nested dataclasses"""
        from dataclasses import fields as dataclass_fields

        # Get valid field names for Command dataclass
        valid_fields = {f.name for f in dataclass_fields(cls)}

        # Filter data to only include valid fields
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}

        # Handle nested dataclasses - variables (existing)
        if 'variables' in filtered_data and filtered_data['variables']:
            filtered_data['variables'] = [
                CommandVariable(**var) if isinstance(var, dict) else var
                for var in filtered_data['variables']
            ]

        # Handle nested dataclasses - flags
        if 'flags' in filtered_data and filtered_data['flags']:
            filtered_data['flags'] = [
                FlagDefinition(**flag) if isinstance(flag, dict) else flag
                for flag in filtered_data['flags']
            ]

        # Handle nested dataclasses - examples
        if 'examples' in filtered_data and filtered_data['examples']:
            filtered_data['examples'] = [
                ExampleDefinition(**ex) if isinstance(ex, dict) else ex
                for ex in filtered_data['examples']
            ]

        # Handle nested dataclasses - educational
        if 'educational' in filtered_data and filtered_data['educational']:
            if isinstance(filtered_data['educational'], dict):
                # Filter educational fields to only include valid EducationalContent fields
                from dataclasses import fields as dataclass_fields
                edu_valid_fields = {f.name for f in dataclass_fields(EducationalContent)}
                edu_filtered = {k: v for k, v in filtered_data['educational'].items() if k in edu_valid_fields}
                filtered_data['educational'] = EducationalContent(**edu_filtered)

        return cls(**filtered_data)

    def fill_placeholders(self, values: Dict[str, str]) -> str:
        """Fill command placeholders with provided values"""
        filled = self.command
        for var in self.variables:
            if var.name in values:
                filled = filled.replace(var.name, values[var.name])
            elif var.example:  # Use example as default if no value provided
                filled = filled.replace(var.name, var.example)
        return filled

    def extract_placeholders(self) -> List[str]:
        """Extract all placeholders from command"""
        return re.findall(r'<[A-Z_]+>', self.command)

    def matches_search(self, query: str) -> bool:
        """Check if command matches search query (punctuation-insensitive)

        For multi-term queries (space-separated), ALL terms must match (AND logic).
        Each term is matched against ID, name, description, command text, and tags.

        Examples:
            - "tgsrep" -> matches "TGS-REP" (punctuation normalized)
            - "firewall windows" -> matches only commands with BOTH terms
            - "oscphigh" -> matches "OSCP:HIGH"
        """
        # Split query into terms (space-separated)
        terms = query.lower().split()

        # Build searchable content (all lowercase)
        # BUG FIX: Added self.id to searchable fields
        searchable_content = ' '.join([
            self.id.lower(),
            self.name.lower(),
            self.description.lower(),
            self.command.lower(),
            ' '.join(self.tags).lower()
        ])

        # Normalize punctuation for both content and query terms
        searchable_normalized = _normalize_punctuation(searchable_content)

        # ALL normalized terms must be present (AND logic)
        return all(_normalize_punctuation(term) in searchable_normalized for term in terms)


def _normalize_punctuation(text: str) -> str:
    """Remove punctuation for fuzzy search matching

    Removes: hyphens, underscores, colons, periods, slashes
    Used by: Command.matches_search() for punctuation-insensitive substring matching
    """
    return text.replace('-', '').replace('_', '').replace(':', '').replace('.', '').replace('/', '')


class HybridCommandRegistry:
    """Main registry for managing commands from multiple sources"""

    def __init__(self, base_path: str = None, config_manager=None, theme=None):
        """Initialize registry with base reference path"""
        if base_path is None:
            base_path = Path(__file__).parent.parent
        self.base_path = Path(base_path)
        self.config_manager = config_manager
        self.theme = theme
        if self.theme is None:
            # Import here to avoid circular dependency
            from crack.core.themes.colors import ReferenceTheme
            self.theme = ReferenceTheme()

        # Initialize shared components (lazy import to avoid circular dependency)
        from .command_filler import CommandFiller
        self.filler = CommandFiller(config_manager, theme)

        self.commands: Dict[str, Command] = {}
        self.categories = {
            'recon': '01-recon',
            'web': '02-web',
            'exploitation': '03-exploitation',
            'post-exploit': '04-post-exploitation',
            'enumeration': '05-enumeration',
            'pivoting': '06-pivoting',
            'file-transfer': '07-file-transfer',
            'custom': 'custom'
        }
        self.subcategories: Dict[str, List[str]] = {}
        self._load_commands()

    def _load_commands(self):
        """Load commands from all sources"""
        # Load from JSON files
        self._load_json_commands()
        # TODO: Load from markdown files
        # self._load_markdown_commands()

    def _load_json_commands(self):
        """Load commands from JSON files (supports both flat and subdirectory structure)"""
        json_path = self.base_path / 'db' / 'data' / 'commands'
        if not json_path.exists():
            json_path.mkdir(parents=True, exist_ok=True)
            return

        # Load from root level JSON files (backward compatibility)
        for json_file in json_path.glob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    category = json_file.stem  # Use filename as category
                    for cmd_data in data.get('commands', []):
                        # Add category if not present
                        if 'category' not in cmd_data:
                            cmd_data['category'] = category
                        cmd = Command.from_dict(cmd_data)
                        self.commands[cmd.id] = cmd
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

        # Load from subdirectory JSON files (new structure)
        for category_dir in json_path.iterdir():
            if category_dir.is_dir():
                category_name = category_dir.name
                subcategories = []

                for json_file in category_dir.glob('*.json'):
                    try:
                        subcategory = json_file.stem
                        subcategories.append(subcategory)

                        with open(json_file, 'r') as f:
                            data = json.load(f)
                            for cmd_data in data.get('commands', []):
                                # Set category and subcategory
                                cmd_data['category'] = category_name
                                cmd_data['subcategory'] = subcategory
                                cmd = Command.from_dict(cmd_data)
                                self.commands[cmd.id] = cmd
                    except Exception as e:
                        print(f"Error loading {json_file}: {e}")

                if subcategories:
                    self.subcategories[category_name] = sorted(subcategories)

    def add_command(self, command: Command):
        """Add a command to the registry"""
        self.commands[command.id] = command

    def get_command(self, command_id: str) -> Optional[Command]:
        """Get command by ID"""
        return self.commands.get(command_id)

    def search(self, query: str) -> List[Command]:
        """Search commands by query"""
        results = []
        for cmd in self.commands.values():
            if cmd.matches_search(query):
                results.append(cmd)
        return sorted(results, key=lambda x: x.oscp_relevance, reverse=True)

    def filter_by_category(self, category: str, subcategory: str = None) -> List[Command]:
        """Get all commands in a category, optionally filtered by subcategory"""
        results = [
            cmd for cmd in self.commands.values()
            if cmd.category == category
        ]

        if subcategory:
            results = [cmd for cmd in results if cmd.subcategory == subcategory]

        return results

    def get_subcategories(self, category: str) -> List[str]:
        """Get all subcategories for a category"""
        return self.subcategories.get(category, [])

    def filter_by_tags(self, tags: List[str], exclude_tags: List[str] = None) -> List[Command]:
        """Filter commands by tags (case-insensitive)"""
        exclude_tags = exclude_tags or []
        results = []

        # Convert search tags to uppercase for case-insensitive matching
        tags_upper = [tag.upper() for tag in tags]
        exclude_tags_upper = [tag.upper() for tag in exclude_tags]

        for cmd in self.commands.values():
            # Convert command tags to uppercase for comparison
            cmd_tags_upper = [tag.upper() for tag in cmd.tags]

            # Check if command has all required tags (case-insensitive)
            if all(tag in cmd_tags_upper for tag in tags_upper):
                # Check if command has none of the excluded tags (case-insensitive)
                if not any(tag in cmd_tags_upper for tag in exclude_tags_upper):
                    results.append(cmd)

        return results

    def get_quick_wins(self) -> List[Command]:
        """Get commands tagged as quick wins"""
        return self.filter_by_tags(['QUICK_WIN'])

    def get_oscp_high(self) -> List[Command]:
        """Get OSCP high-relevance commands"""
        return [
            cmd for cmd in self.commands.values()
            if cmd.oscp_relevance == 'high' or 'OSCP:HIGH' in cmd.tags
        ]

    def save_to_json(self, category: str = None):
        """Save commands to JSON files"""
        if category:
            self._save_category_json(category)
        else:
            for cat in self.categories.keys():
                self._save_category_json(cat)

    def _save_category_json(self, category: str):
        """Save a single category to JSON"""
        commands = self.filter_by_category(category)
        if not commands:
            return

        json_path = self.base_path / 'db' / 'data' / 'commands' / f'{category}.json'
        json_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'category': category,
            'commands': [cmd.to_dict() for cmd in commands]
        }

        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)

    def validate_schema(self) -> List[str]:
        """Validate all commands against schema"""
        errors = []
        for cmd_id, cmd in self.commands.items():
            # Check required fields
            if not cmd.id:
                errors.append(f"Command missing ID")
            if not cmd.command:
                errors.append(f"Command {cmd_id} missing command text")
            if not cmd.description:
                errors.append(f"Command {cmd_id} missing description")

            # Check placeholder consistency
            placeholders = cmd.extract_placeholders()
            var_names = [var.name for var in cmd.variables]

            for placeholder in placeholders:
                if placeholder not in var_names:
                    errors.append(f"Command {cmd_id}: placeholder {placeholder} not defined in variables")

        return errors

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics"""
        total = len(self.commands)
        by_category = {}
        by_subcategory = {}

        # First, get counts for predefined categories
        for cat in self.categories.keys():
            by_category[cat] = len(self.filter_by_category(cat))

            # Count commands per subcategory
            subcats = self.get_subcategories(cat)
            if subcats:
                by_subcategory[cat] = {}
                for subcat in subcats:
                    count = len(self.filter_by_category(cat, subcat))
                    by_subcategory[cat][subcat] = count

        # Also include any additional categories found in commands (for testing/custom categories)
        for cmd in self.commands.values():
            if cmd.category and cmd.category not in by_category:
                by_category[cmd.category] = len(self.filter_by_category(cmd.category))

                # Check for subcategories
                subcats = self.get_subcategories(cmd.category)
                if subcats:
                    by_subcategory[cmd.category] = {}
                    for subcat in subcats:
                        count = len(self.filter_by_category(cmd.category, subcat))
                        by_subcategory[cmd.category][subcat] = count

        tag_counts = {}
        for cmd in self.commands.values():
            for tag in cmd.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            'total_commands': total,
            'by_category': by_category,
            'by_subcategory': by_subcategory,
            'top_tags': sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'quick_wins': len(self.get_quick_wins()),
            'oscp_high': len(self.get_oscp_high())
        }

    def interactive_fill(self, command: Command) -> str:
        """
        Interactively fill command placeholders - DELEGATES to CommandFiller

        Args:
            command: Command dataclass to fill

        Returns:
            Filled command string
        """
        return self.filler.fill_command(command)


# Convenience functions for module-level access
def load_registry(base_path: str = None) -> HybridCommandRegistry:
    """Load the command registry"""
    return HybridCommandRegistry(base_path)


def quick_search(query: str, base_path: str = None) -> List[Command]:
    """Quick search without instantiating registry"""
    registry = HybridCommandRegistry(base_path)
    return registry.search(query)