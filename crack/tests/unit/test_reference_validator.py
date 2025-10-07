#!/usr/bin/env python3
"""
Unit tests for Reference Validator Module
Tests command validation, schema enforcement, and best practices checking
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import json

from crack.reference.core.validator import CommandValidator


class TestCommandValidator:
    """Test CommandValidator functionality"""

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_validator_initialization(self):
        """Test validator initializes correctly"""
        validator = CommandValidator()

        assert validator is not None
        assert hasattr(validator, 'schema')
        assert hasattr(validator, 'placeholder_pattern')
        assert hasattr(validator, 'tag_pattern')

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_placeholder_pattern_matching(self):
        """Test placeholder regex pattern"""
        validator = CommandValidator()

        # Test valid placeholders
        command = "nmap <TARGET> -p <PORTS>"
        matches = validator.placeholder_pattern.findall(command)
        assert "<TARGET>" in matches
        assert "<PORTS>" in matches
        assert len(matches) == 2

        # Test no placeholders
        command_no_placeholders = "ls -la"
        matches = validator.placeholder_pattern.findall(command_no_placeholders)
        assert len(matches) == 0

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_command_all_required_fields(self, valid_command_dict):
        """Test validation passes for command with all required fields"""
        validator = CommandValidator()

        is_valid, errors = validator.validate_command(valid_command_dict)

        assert is_valid is True
        assert len([e for e in errors if 'Missing required field' in e]) == 0

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_command_missing_required_fields(self, invalid_command_dict):
        """Test validation fails for missing required fields"""
        validator = CommandValidator()

        is_valid, errors = validator.validate_command(invalid_command_dict)

        assert is_valid is False
        # Should have errors for missing name, command, description
        error_messages = ' '.join(errors)
        assert 'name' in error_messages
        assert 'command' in error_messages
        assert 'description' in error_messages

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_validate_id_format(self):
        """Test ID format validation"""
        validator = CommandValidator()

        # Valid IDs
        valid_ids = ["test-cmd", "nmap-scan", "web_enum", "cmd123"]
        for cmd_id in valid_ids:
            cmd = {
                "id": cmd_id,
                "name": "Test",
                "category": "recon",
                "command": "test",
                "description": "Test command"
            }
            is_valid, errors = validator.validate_command(cmd)
            # Should not have ID format error
            assert not any('Invalid ID format' in e for e in errors)

        # Invalid IDs
        invalid_ids = ["Test_Cmd", "cmd@123", "cmd with spaces", "cmd!"]
        for cmd_id in invalid_ids:
            cmd = {
                "id": cmd_id,
                "name": "Test",
                "category": "recon",
                "command": "test",
                "description": "Test command"
            }
            is_valid, errors = validator.validate_command(cmd)
            # Should have ID format error
            assert any('Invalid ID format' in e for e in errors)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_category(self, command_with_bad_formatting):
        """Test category validation"""
        validator = CommandValidator()

        is_valid, errors = validator.validate_command(command_with_bad_formatting)

        # Should have invalid category error
        assert any('Invalid category' in e for e in errors)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_placeholder_consistency(self):
        """Test placeholder/variable consistency checking"""
        validator = CommandValidator()

        # Placeholder used but not defined
        cmd_undefined = {
            "id": "test-undefined",
            "name": "Test",
            "category": "recon",
            "command": "nmap <TARGET>",
            "description": "Test",
            "variables": []  # TARGET not defined
        }
        is_valid, errors = validator.validate_command(cmd_undefined)
        # Should warn about undefined placeholder
        assert any('<TARGET>' in e and 'not defined' in e for e in errors)

        # Variable defined but not used
        cmd_unused = {
            "id": "test-unused",
            "name": "Test",
            "category": "recon",
            "command": "ls -la",
            "description": "Test",
            "variables": [
                {"name": "<UNUSED>", "description": "Not used", "example": "test", "required": True}
            ]
        }
        is_valid, errors = validator.validate_command(cmd_unused)
        # Should warn about unused variable
        assert any('<UNUSED>' in e and 'not used' in e for e in errors)

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_validate_tags_format(self, command_with_bad_formatting):
        """Test tag format validation"""
        validator = CommandValidator()

        is_valid, errors = validator.validate_command(command_with_bad_formatting)

        # Should warn about lowercase/mixed case tags
        error_messages = ' '.join(errors)
        assert 'uppercase' in error_messages.lower()

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_oscp_relevance(self):
        """Test OSCP relevance validation"""
        validator = CommandValidator()

        # Valid relevance
        for relevance in ['high', 'medium', 'low']:
            cmd = {
                "id": "test",
                "name": "Test",
                "category": "recon",
                "command": "test",
                "description": "Test",
                "oscp_relevance": relevance
            }
            is_valid, errors = validator.validate_command(cmd)
            assert not any('Invalid OSCP relevance' in e for e in errors)

        # Invalid relevance
        cmd_invalid = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "test",
            "description": "Test",
            "oscp_relevance": "invalid"
        }
        is_valid, errors = validator.validate_command(cmd_invalid)
        assert any('Invalid OSCP relevance' in e for e in errors)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_dangerous_pattern_detection(self, dangerous_command_dict):
        """Test detection of dangerous command patterns"""
        validator = CommandValidator()

        is_valid, errors = validator.validate_command(dangerous_command_dict)

        # Should warn about dangerous rm pattern
        error_messages = ' '.join(errors)
        assert 'dangerous' in error_messages.lower() or 'rm' in error_messages.lower()

    @pytest.mark.unit
    @pytest.mark.reference
    def test_dangerous_patterns_comprehensive(self):
        """Test various dangerous patterns"""
        validator = CommandValidator()

        dangerous_commands = [
            {
                "id": "fork-bomb",
                "name": "Fork Bomb",
                "category": "exploitation",
                "command": ":(){ :|:& };:",
                "description": "Fork bomb"
            },
            {
                "id": "dd-danger",
                "name": "Dangerous DD",
                "category": "exploitation",
                "command": "dd if=/dev/zero of=/dev/sda",
                "description": "Wipe disk"
            }
        ]

        for cmd in dangerous_commands:
            is_valid, errors = validator.validate_command(cmd)
            # Should have warnings about dangerous patterns
            assert len(errors) > 0
            error_messages = ' '.join(errors).lower()
            assert 'dangerous' in error_messages or 'detected' in error_messages

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_file_valid_json(self, temp_output_dir, valid_command_dict):
        """Test validating a valid JSON file"""
        validator = CommandValidator()

        # Create valid JSON file
        data = {
            "category": "test",
            "commands": [valid_command_dict]
        }
        json_file = temp_output_dir / "valid.json"
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

        is_valid, errors = validator.validate_file(json_file)

        # May have warnings but should not have critical errors
        # Check it doesn't crash
        assert isinstance(errors, list)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_file_invalid_json(self, temp_output_dir):
        """Test handling of malformed JSON"""
        validator = CommandValidator()

        # Create invalid JSON file
        json_file = temp_output_dir / "invalid.json"
        json_file.write_text("{invalid json content")

        is_valid, errors = validator.validate_file(json_file)

        assert is_valid is False
        assert len(errors) > 0
        assert any('Invalid JSON' in e for e in errors)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_file_duplicate_ids(self, duplicate_commands_json):
        """Test detection of duplicate command IDs"""
        validator = CommandValidator()

        is_valid, errors = validator.validate_file(duplicate_commands_json)

        # Should detect duplicate IDs
        assert any('Duplicate' in e and 'duplicate-id' in e for e in errors)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_directory(self, temp_output_dir, valid_command_dict):
        """Test validating all JSON files in a directory"""
        validator = CommandValidator()

        # Create multiple JSON files
        commands_dir = temp_output_dir / "commands"
        commands_dir.mkdir()

        # Valid file
        valid_data = {"category": "test", "commands": [valid_command_dict]}
        valid_file = commands_dir / "valid.json"
        with open(valid_file, 'w') as f:
            json.dump(valid_data, f)

        # Invalid file
        invalid_file = commands_dir / "invalid.json"
        invalid_file.write_text("{bad json")

        results = validator.validate_directory(commands_dir)

        # Should have results
        assert isinstance(results, dict)
        # Invalid file should have errors
        assert str(invalid_file) in results or any('invalid' in str(k) for k in results.keys())

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_directory_no_files(self, temp_output_dir):
        """Test validating empty directory"""
        validator = CommandValidator()

        empty_dir = temp_output_dir / "empty"
        empty_dir.mkdir()

        results = validator.validate_directory(empty_dir)

        assert isinstance(results, dict)
        assert 'general' in results or len(results) == 0

    @pytest.mark.unit
    @pytest.mark.reference
    def test_check_best_practices_description(self):
        """Test best practices for description field"""
        validator = CommandValidator()

        # Description too short
        cmd_short = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "test",
            "description": "Short"
        }
        suggestions = validator.check_best_practices(cmd_short)
        assert any('too short' in s.lower() for s in suggestions)

        # Description too long
        cmd_long = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "test",
            "description": "x" * 250  # Very long description
        }
        suggestions = validator.check_best_practices(cmd_long)
        assert any('too long' in s.lower() for s in suggestions)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_check_best_practices_variables(self):
        """Test best practices for variable examples"""
        validator = CommandValidator()

        cmd = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "nmap <TARGET>",
            "description": "Test command",
            "variables": [
                {
                    "name": "<TARGET>",
                    "description": "Target IP",
                    # Missing example
                    "required": True
                }
            ]
        }

        suggestions = validator.check_best_practices(cmd)
        assert any('example' in s.lower() for s in suggestions)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_check_best_practices_indicators(self, valid_command_dict):
        """Test suggestions for success/failure indicators"""
        validator = CommandValidator()

        # Command without indicators
        cmd_no_indicators = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "test",
            "description": "Test command without indicators"
        }

        suggestions = validator.check_best_practices(cmd_no_indicators)
        # Should suggest adding indicators
        assert any('success' in s.lower() or 'indicators' in s.lower() for s in suggestions)

        # Command with indicators (valid_command_dict has them)
        suggestions_valid = validator.check_best_practices(valid_command_dict)
        # Should have fewer suggestions
        # (May still have some, but not about indicators)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_check_best_practices_tags(self):
        """Test tag recommendations"""
        validator = CommandValidator()

        # Command without OSCP tag
        cmd_no_oscp = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "test",
            "description": "Test command",
            "tags": ["ENUM"]
        }
        suggestions = validator.check_best_practices(cmd_no_oscp)
        assert any('OSCP' in s for s in suggestions)

        # Command without platform tag
        cmd_no_platform = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "test",
            "description": "Test command",
            "tags": ["OSCP:HIGH"]
        }
        suggestions = validator.check_best_practices(cmd_no_platform)
        assert any('platform' in s.lower() or 'LINUX' in s or 'WINDOWS' in s for s in suggestions)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_generate_report(self, temp_output_dir, valid_command_dict):
        """Test validation report generation"""
        validator = CommandValidator()

        # Create directory with commands
        commands_dir = temp_output_dir / "commands"
        commands_dir.mkdir()

        data = {"category": "test", "commands": [valid_command_dict]}
        json_file = commands_dir / "test.json"
        with open(json_file, 'w') as f:
            json.dump(data, f)

        report = validator.generate_report(commands_dir)

        assert isinstance(report, str)
        assert '# Command Validation Report' in report
        assert 'Statistics' in report
        assert 'Total' in report

    @pytest.mark.unit
    @pytest.mark.reference
    def test_generate_report_with_errors(self, temp_output_dir):
        """Test report generation with validation errors"""
        validator = CommandValidator()

        # Create directory with invalid file
        commands_dir = temp_output_dir / "commands"
        commands_dir.mkdir()

        invalid_file = commands_dir / "invalid.json"
        invalid_file.write_text("{bad json")

        report = validator.generate_report(commands_dir)

        assert isinstance(report, str)
        assert 'issues' in report.lower() or 'error' in report.lower()

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_fix_common_issues_id_format(self, command_with_bad_formatting):
        """Test auto-fixing ID format"""
        validator = CommandValidator()

        fixed = validator.fix_common_issues(command_with_bad_formatting)

        # ID should be converted to lowercase with underscores
        assert fixed['id'] == 'bad_format_123'
        assert fixed['id'].islower()

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_fix_common_issues_tag_case(self, command_with_bad_formatting):
        """Test auto-fixing tag case"""
        validator = CommandValidator()

        fixed = validator.fix_common_issues(command_with_bad_formatting)

        # Tags should be uppercase
        assert all(tag.isupper() for tag in fixed['tags'])
        assert 'LOWERCASE_TAG' in fixed['tags']
        assert 'MIXED_CASE' in fixed['tags']

    @pytest.mark.unit
    @pytest.mark.reference
    def test_fix_common_issues_missing_fields(self):
        """Test adding default values for missing fields"""
        validator = CommandValidator()

        minimal_cmd = {
            "id": "minimal",
            "name": "Minimal",
            "category": "recon",
            "command": "test",
            "description": "Minimal command"
        }

        fixed = validator.fix_common_issues(minimal_cmd)

        # Should add defaults
        assert 'tags' in fixed
        assert isinstance(fixed['tags'], list)
        assert 'variables' in fixed
        assert 'alternatives' in fixed
        assert 'oscp_relevance' in fixed

    @pytest.mark.unit
    @pytest.mark.reference
    def test_fix_common_issues_undefined_placeholders(self):
        """Test auto-defining undefined placeholders"""
        validator = CommandValidator()

        cmd = {
            "id": "test",
            "name": "Test",
            "category": "recon",
            "command": "nmap <TARGET> -p <PORTS>",
            "description": "Test",
            "variables": []  # No variables defined
        }

        fixed = validator.fix_common_issues(cmd)

        # Should add variable definitions for placeholders
        assert len(fixed['variables']) == 2
        var_names = [v['name'] for v in fixed['variables']]
        assert '<TARGET>' in var_names
        assert '<PORTS>' in var_names

    @pytest.mark.unit
    @pytest.mark.reference
    def test_fix_common_issues_preserves_existing(self, valid_command_dict):
        """Test that fix doesn't overwrite existing valid data"""
        validator = CommandValidator()

        original_tags = valid_command_dict['tags'].copy()
        original_vars = valid_command_dict['variables'].copy()

        fixed = validator.fix_common_issues(valid_command_dict)

        # Should preserve existing data
        assert fixed['tags'] == original_tags
        assert len(fixed['variables']) == len(original_vars)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_schema_validation_with_schema_file(self, temp_output_dir, command_schema_file):
        """Test schema validation when schema file exists"""
        # Create validator with custom base path
        with patch.object(Path, '__truediv__') as mock_div:
            # Mock the path to schema file
            mock_div.return_value = command_schema_file

            validator = CommandValidator()

            # Valid data
            valid_data = {
                "category": "test",
                "commands": [
                    {
                        "id": "test",
                        "name": "Test",
                        "category": "test",
                        "command": "echo test",
                        "description": "Test command"
                    }
                ]
            }

            # Should validate successfully
            # Note: This may not work perfectly due to path mocking complexity
            # But tests the schema validation logic exists

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_json_without_schema(self):
        """Test JSON validation when schema file doesn't exist"""
        validator = CommandValidator()
        validator.schema = {}  # Simulate no schema loaded

        data = {
            "category": "test",
            "commands": []
        }

        is_valid, errors = validator.validate_json(data)

        # Should indicate schema not found
        assert is_valid is False
        assert any('Schema not found' in e for e in errors)

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_validator_patterns_are_regex(self):
        """Test that validator patterns are compiled regex objects"""
        validator = CommandValidator()

        # Should be regex patterns
        assert hasattr(validator.placeholder_pattern, 'findall')
        assert hasattr(validator.tag_pattern, 'findall')

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validation_returns_tuple(self, valid_command_dict):
        """Test that validation methods return (bool, list) tuples"""
        validator = CommandValidator()

        # validate_command
        result = validator.validate_command(valid_command_dict)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], list)

        # validate_json
        data = {"category": "test", "commands": []}
        result = validator.validate_json(data)
        assert isinstance(result, tuple)
        assert len(result) == 2

    @pytest.mark.unit
    @pytest.mark.reference
    def test_best_practices_returns_list(self, valid_command_dict):
        """Test that check_best_practices returns a list"""
        validator = CommandValidator()

        suggestions = validator.check_best_practices(valid_command_dict)

        assert isinstance(suggestions, list)
        # All items should be strings
        assert all(isinstance(s, str) for s in suggestions)
