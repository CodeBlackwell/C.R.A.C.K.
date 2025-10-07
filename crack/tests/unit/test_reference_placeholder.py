#!/usr/bin/env python3
"""
Unit tests for Reference Placeholder Module
Tests variable substitution and placeholder engine functionality
"""

import pytest
from unittest.mock import Mock, patch

from crack.reference.core.placeholder import PlaceholderEngine
from crack.reference.core.config import ConfigManager


class TestPlaceholderEngine:
    """Test PlaceholderEngine functionality"""

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_initialization(self):
        """Test placeholder engine initialization"""
        engine = PlaceholderEngine()

        assert engine is not None
        assert hasattr(engine, 'config_manager')

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_initialization_with_config(self, mock_config_file):
        """Test initialization with config manager"""
        config = ConfigManager(config_path=str(mock_config_file))
        engine = PlaceholderEngine(config_manager=config)

        assert engine.config_manager == config

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_extract_placeholders(self):
        """Test extracting placeholders from command"""
        engine = PlaceholderEngine()

        command = "nmap -sV <TARGET> -p <PORTS> -oA <OUTPUT>"
        placeholders = engine.extract_placeholders(command)

        assert "<TARGET>" in placeholders
        assert "<PORTS>" in placeholders
        assert "<OUTPUT>" in placeholders
        assert len(placeholders) == 3

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_extract_no_placeholders(self):
        """Test command with no placeholders"""
        engine = PlaceholderEngine()

        command = "ls -la /tmp"
        placeholders = engine.extract_placeholders(command)

        assert len(placeholders) == 0

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_substitute_placeholders(self):
        """Test substituting placeholders with values"""
        engine = PlaceholderEngine()

        command = "curl http://<TARGET>:<PORT>"
        values = {
            "<TARGET>": "192.168.45.100",
            "<PORT>": "8080"
        }

        result = engine.substitute(command, values)
        assert result == "curl http://192.168.45.100:8080"

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_substitute_partial(self):
        """Test partial substitution leaves remaining placeholders"""
        engine = PlaceholderEngine()

        command = "nmap <TARGET> -p <PORTS>"
        values = {"<TARGET>": "192.168.1.1"}

        result = engine.substitute(command, values)
        assert "192.168.1.1" in result
        assert "<PORTS>" in result

    @pytest.mark.unit
    @pytest.mark.reference
    def test_substitute_with_config(self, mock_config_file):
        """Test substitution using config values"""
        config = ConfigManager(config_path=str(mock_config_file))
        engine = PlaceholderEngine(config_manager=config)

        command = "nc -lvnp <LPORT>"

        # Get config values
        config_values = config.get_placeholder_values()

        result = engine.substitute(command, config_values)

        # Should substitute LPORT from config
        assert "4444" in result

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_get_placeholder_description(self):
        """Test getting placeholder descriptions"""
        engine = PlaceholderEngine()

        # Common placeholders should have descriptions
        assert "<TARGET>" in engine.definitions
        desc = engine.definitions["<TARGET>"].description
        assert desc is not None
        assert "target" in desc.lower()

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_validate_required_placeholders(self):
        """Test validating placeholder values"""
        engine = PlaceholderEngine()

        # Validate correct IP format for TARGET
        is_valid, message = engine.validate_value("<TARGET>", "192.168.1.1")
        assert is_valid is True

        # Validate incorrect format
        is_valid, message = engine.validate_value("<TARGET>", "not_an_ip")
        assert is_valid is True  # TARGET allows hostnames too

        # Validate TARGET_IP with IP regex
        is_valid, message = engine.validate_value("<TARGET_IP>", "192.168.1.1")
        assert is_valid is True

        is_valid, message = engine.validate_value("<TARGET_IP>", "invalid")
        assert is_valid is False

    @pytest.mark.unit
    @pytest.mark.reference
    def test_get_config_value_for_placeholder(self, mock_config_file):
        """Test getting config value for a placeholder"""
        config = ConfigManager(config_path=str(mock_config_file))
        engine = PlaceholderEngine(config_manager=config)

        # Config values should be loaded into user_values
        value = engine.get_value("<LHOST>")
        assert value == "10.10.14.5"

        value = engine.get_value("<TARGET>")
        assert value == "192.168.45.100"

        # Non-configured placeholder
        value = engine.get_value("<UNKNOWN>")
        assert value is None

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_multiple_same_placeholder(self):
        """Test substituting when same placeholder appears multiple times"""
        engine = PlaceholderEngine()

        command = "echo <MSG> && printf <MSG>"
        values = {"<MSG>": "test"}

        result = engine.substitute(command, values)
        assert result == "echo test && printf test"

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_case_sensitive_placeholders(self):
        """Test that placeholders are case-sensitive"""
        engine = PlaceholderEngine()

        command = "echo <target> <TARGET>"
        values = {"<TARGET>": "value1"}

        result = engine.substitute(command, values)
        assert "value1" in result
        assert "<target>" in result  # Lowercase not substituted

    @pytest.mark.unit
    @pytest.mark.reference
    def test_interactive_fill_workflow(self, mock_config_file, monkeypatch):
        """Test interactive fill workflow with config"""
        config = ConfigManager(config_path=str(mock_config_file))
        engine = PlaceholderEngine(config_manager=config)

        command = "nmap -sV <TARGET>"

        # Mock user input - press enter to use config
        inputs = iter([""])
        monkeypatch.setattr('builtins.input', lambda x: next(inputs))

        # Extract placeholders
        placeholders = engine.extract_placeholders(command)
        assert "<TARGET>" in placeholders

        # Check that config value is available in user_values
        config_value = engine.get_value("<TARGET>")
        assert config_value == "192.168.45.100"

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_empty_command(self):
        """Test handling of empty command"""
        engine = PlaceholderEngine()

        result = engine.extract_placeholders("")
        assert result == []

        result = engine.substitute("", {})
        assert result == ""

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_special_characters_in_values(self):
        """Test substitution with special characters"""
        engine = PlaceholderEngine()

        command = "echo '<MSG>'"
        values = {"<MSG>": "test$special&chars"}

        result = engine.substitute(command, values)
        assert "test$special&chars" in result

    @pytest.mark.unit
    @pytest.mark.reference
    def test_placeholder_suggestions(self):
        """Test getting placeholder suggestions"""
        engine = PlaceholderEngine()

        # Test suggest_values for specific placeholders
        port_suggestions = engine.suggest_values("<PORT>")
        assert isinstance(port_suggestions, list)
        assert "80" in port_suggestions or "443" in port_suggestions

        lport_suggestions = engine.suggest_values("<LPORT>")
        assert isinstance(lport_suggestions, list)
        assert "4444" in lport_suggestions

    @pytest.mark.unit
    @pytest.mark.reference
    def test_format_placeholder_prompt(self):
        """Test exporting placeholder definitions"""
        engine = PlaceholderEngine()

        # Test export_definitions method
        definitions = engine.export_definitions()

        assert isinstance(definitions, dict)
        assert "<TARGET>" in definitions
        assert "description" in definitions["<TARGET>"]
        assert "example" in definitions["<TARGET>"]

        # Verify TARGET definition structure
        target_def = definitions["<TARGET>"]
        assert target_def["description"] is not None
        assert target_def["example"] is not None
