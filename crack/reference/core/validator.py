"""
Command validation and schema enforcement
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Tuple, Any
from jsonschema import validate, ValidationError


class CommandValidator:
    """Validate commands against schema and best practices"""

    def __init__(self):
        self.schema = self._load_schema()
        self.placeholder_pattern = re.compile(r'<[A-Z_]+>')
        self.tag_pattern = re.compile(r'\[[A-Z_:]+\]')

    def _load_schema(self) -> dict:
        """Load the command JSON schema"""
        schema_path = Path(__file__).parent.parent / 'data' / 'schemas' / 'command.schema.json'
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                return json.load(f)
        return {}

    def validate_json(self, data: dict) -> Tuple[bool, List[str]]:
        """Validate JSON data against schema"""
        errors = []

        if not self.schema:
            errors.append("Schema not found - cannot validate structure")
            return False, errors

        try:
            validate(instance=data, schema=self.schema)
            return True, []
        except ValidationError as e:
            errors.append(f"Schema validation error: {e.message}")
            return False, errors

    def validate_command(self, command: dict) -> Tuple[bool, List[str]]:
        """Validate a single command"""
        errors = []
        warnings = []

        # Required fields
        required_fields = ['id', 'name', 'category', 'command', 'description']
        for field in required_fields:
            if field not in command or not command[field]:
                errors.append(f"Missing required field: {field}")

        # Validate ID format
        if 'id' in command:
            if not re.match(r'^[a-z0-9_-]+$', command['id']):
                errors.append(f"Invalid ID format: {command['id']}. Use lowercase letters, numbers, underscores, and hyphens only.")

        # Validate category
        valid_categories = ['recon', 'web', 'exploitation', 'post-exploit', 'pivoting', 'custom']
        if 'category' in command and command['category'] not in valid_categories:
            errors.append(f"Invalid category: {command['category']}. Must be one of: {', '.join(valid_categories)}")

        # Validate placeholders
        if 'command' in command:
            placeholders = self.placeholder_pattern.findall(command['command'])
            defined_vars = [var.get('name', '') for var in command.get('variables', [])]

            for placeholder in placeholders:
                if placeholder not in defined_vars:
                    warnings.append(f"Placeholder {placeholder} used but not defined in variables")

            # Check for variables that aren't used
            for var_name in defined_vars:
                if var_name not in command['command']:
                    warnings.append(f"Variable {var_name} defined but not used in command")

        # Validate tags format
        if 'tags' in command:
            for tag in command['tags']:
                if not isinstance(tag, str):
                    errors.append(f"Tag must be string: {tag}")
                # Tags should be uppercase
                if tag != tag.upper():
                    warnings.append(f"Tag should be uppercase: {tag}")

        # Validate OSCP relevance
        if 'oscp_relevance' in command:
            valid_relevance = ['high', 'medium', 'low']
            if command['oscp_relevance'] not in valid_relevance:
                errors.append(f"Invalid OSCP relevance: {command['oscp_relevance']}. Must be one of: {', '.join(valid_relevance)}")

        # Check for dangerous patterns
        if 'command' in command:
            dangerous_patterns = [
                (r'rm\s+-rf\s+/', "Dangerous rm -rf / pattern detected"),
                (r':(){ :|:& };:', "Fork bomb pattern detected"),
                (r'dd\s+if=/dev/zero\s+of=/', "Dangerous dd pattern detected")
            ]
            for pattern, message in dangerous_patterns:
                if re.search(pattern, command['command']):
                    warnings.append(message)

        return (len(errors) == 0, errors + warnings)

    def validate_file(self, filepath: Path) -> Tuple[bool, List[str]]:
        """Validate a JSON command file"""
        errors = []

        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in {filepath}: {e}")
            return False, errors
        except Exception as e:
            errors.append(f"Error reading {filepath}: {e}")
            return False, errors

        # Validate against schema
        valid, schema_errors = self.validate_json(data)
        errors.extend(schema_errors)

        # Validate individual commands
        if 'commands' in data:
            for i, command in enumerate(data['commands']):
                valid, cmd_errors = self.validate_command(command)
                for error in cmd_errors:
                    errors.append(f"Command {i} ({command.get('id', 'unknown')}): {error}")

        # Check for duplicate IDs
        if 'commands' in data:
            ids = [cmd.get('id') for cmd in data['commands'] if 'id' in cmd]
            duplicates = [id for id in ids if ids.count(id) > 1]
            if duplicates:
                errors.append(f"Duplicate command IDs found: {', '.join(set(duplicates))}")

        return (len(errors) == 0, errors)

    def validate_directory(self, directory: Path) -> Dict[str, List[str]]:
        """Validate all JSON files in a directory"""
        results = {}

        json_files = list(directory.glob('**/*.json'))
        if not json_files:
            results['general'] = ["No JSON files found in directory"]
            return results

        for json_file in json_files:
            valid, errors = self.validate_file(json_file)
            if errors:
                results[str(json_file)] = errors

        return results

    def check_best_practices(self, command: dict) -> List[str]:
        """Check command against best practices"""
        suggestions = []

        # Check for good description
        if 'description' in command:
            if len(command['description']) < 10:
                suggestions.append("Description is too short. Provide more detail.")
            if len(command['description']) > 200:
                suggestions.append("Description is too long. Keep it concise.")

        # Check for examples in variables
        if 'variables' in command:
            for var in command['variables']:
                if 'example' not in var or not var['example']:
                    suggestions.append(f"Variable {var.get('name', 'unknown')} should have an example")

        # Check for success/failure indicators
        if 'success_indicators' not in command or not command.get('success_indicators'):
            suggestions.append("Consider adding success indicators to help users verify the command worked")

        # Check for alternatives
        if 'alternatives' not in command or not command.get('alternatives'):
            suggestions.append("Consider adding alternative commands for when this one fails")

        # Check for notes on common issues
        if 'notes' not in command or not command.get('notes'):
            suggestions.append("Consider adding notes about common issues or prerequisites")

        # Tag recommendations
        if 'tags' in command:
            tags = command['tags']

            # Suggest OSCP relevance tag
            if not any('OSCP' in tag for tag in tags):
                suggestions.append("Consider adding OSCP relevance tag (OSCP:HIGH, OSCP:MEDIUM, OSCP:LOW)")

            # Suggest noise level
            if not any(tag in ['NOISY', 'STEALTH'] for tag in tags):
                suggestions.append("Consider indicating noise level with NOISY or STEALTH tag")

            # Suggest platform
            if not any(tag in ['LINUX', 'WINDOWS', 'CROSS_PLATFORM'] for tag in tags):
                suggestions.append("Consider indicating platform compatibility")

        return suggestions

    def generate_report(self, directory: Path) -> str:
        """Generate a validation report for a directory"""
        report = "# Command Validation Report\n\n"

        validation_results = self.validate_directory(directory)

        if not validation_results:
            report += "✅ All files passed validation!\n\n"
        else:
            report += f"⚠️  Found issues in {len(validation_results)} file(s)\n\n"

            for filepath, errors in validation_results.items():
                report += f"## {filepath}\n"
                for error in errors:
                    report += f"- {error}\n"
                report += "\n"

        # Count statistics
        total_commands = 0
        total_files = 0
        categories = {}

        for json_file in directory.glob('**/*.json'):
            total_files += 1
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    if 'commands' in data:
                        total_commands += len(data['commands'])
                        for cmd in data['commands']:
                            cat = cmd.get('category', 'unknown')
                            categories[cat] = categories.get(cat, 0) + 1
            except:
                pass

        report += "## Statistics\n\n"
        report += f"- Total JSON files: {total_files}\n"
        report += f"- Total commands: {total_commands}\n"
        report += f"- Commands by category:\n"
        for cat, count in sorted(categories.items()):
            report += f"  - {cat}: {count}\n"

        return report

    def fix_common_issues(self, command: dict) -> dict:
        """Attempt to fix common issues in a command"""
        fixed = command.copy()

        # Fix ID format
        if 'id' in fixed:
            fixed['id'] = re.sub(r'[^a-z0-9_-]', '_', fixed['id'].lower())

        # Fix tag case
        if 'tags' in fixed:
            fixed['tags'] = [tag.upper() for tag in fixed['tags']]

        # Add missing fields with defaults
        defaults = {
            'tags': [],
            'variables': [],
            'alternatives': [],
            'oscp_relevance': 'medium',
            'notes': ''
        }
        for field, default in defaults.items():
            if field not in fixed:
                fixed[field] = default

        # Extract and define undefined placeholders
        if 'command' in fixed:
            placeholders = self.placeholder_pattern.findall(fixed['command'])
            defined_vars = [var.get('name', '') for var in fixed.get('variables', [])]

            for placeholder in placeholders:
                if placeholder not in defined_vars:
                    # Add missing variable definition
                    fixed['variables'].append({
                        'name': placeholder,
                        'description': f'Value for {placeholder}',
                        'example': '',
                        'required': True
                    })

        return fixed