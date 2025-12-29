"""
Tests for Placeholder Engine and Variable Substitution

Business Value Focus:
- PlaceholderEngine.substitute() correctness (commands work after fill)
- extract_placeholders() accuracy (all variables detected)
- Validation works correctly (bad input caught early)
- Config value integration (auto-fill from config)
- Default value fallback (sensible defaults used)

These tests ensure users get correctly filled commands that will
execute without placeholder artifacts.
"""

import pytest
import os
from pathlib import Path
from unittest.mock import Mock, patch
from typing import Dict, Any


# =============================================================================
# PlaceholderEngine.substitute() Tests (BV: HIGH)
# =============================================================================

class TestPlaceholderSubstitute:
    """Tests for placeholder substitution."""

    def test_substitutes_single_placeholder(self, placeholder_engine):
        """
        BV: Single placeholder correctly replaced.

        Scenario:
          Given: Command with one placeholder
          When: substitute() called with value
          Then: Placeholder replaced with value
        """
        text = "nmap -p 80 <TARGET>"
        result = placeholder_engine.substitute(text, {"<TARGET>": "192.168.1.100"})

        assert result == "nmap -p 80 192.168.1.100"
        assert "<TARGET>" not in result

    def test_substitutes_multiple_placeholders(self, placeholder_engine):
        """
        BV: Multiple placeholders all replaced.
        """
        text = "nmap -p <PORT> <TARGET> -o <OUTPUT>"
        result = placeholder_engine.substitute(text, {
            "<TARGET>": "192.168.1.100",
            "<PORT>": "443",
            "<OUTPUT>": "scan.txt"
        })

        assert result == "nmap -p 443 192.168.1.100 -o scan.txt"
        assert "<" not in result and ">" not in result

    def test_substitutes_same_placeholder_multiple_times(self, placeholder_engine):
        """
        BV: Repeated placeholder all get replaced.
        """
        text = "ping <TARGET> && nmap <TARGET>"
        result = placeholder_engine.substitute(text, {"<TARGET>": "10.10.10.1"})

        assert result == "ping 10.10.10.1 && nmap 10.10.10.1"

    def test_uses_default_value_when_not_provided(self, placeholder_engine):
        """
        BV: Default values used when user provides nothing.

        Scenario:
          Given: Placeholder with default_value in definition
          When: No value provided in substitute()
          Then: Default value used
        """
        text = "sleep <DELAY>"
        result = placeholder_engine.substitute(text, {})

        # <DELAY> has default_value='1' in standard definitions
        assert result == "sleep 1"

    def test_provided_value_overrides_default(self, placeholder_engine):
        """
        BV: User-provided values take precedence over defaults.
        """
        text = "sleep <DELAY>"
        result = placeholder_engine.substitute(text, {"<DELAY>": "5"})

        assert result == "sleep 5"

    def test_leaves_unknown_placeholders_unchanged(self, placeholder_engine):
        """
        BV: Unknown placeholders not accidentally corrupted.
        """
        text = "custom <UNKNOWN_PLACEHOLDER> command"
        result = placeholder_engine.substitute(text, {})

        # Unknown placeholder has no default, should remain
        assert "<UNKNOWN_PLACEHOLDER>" in result

    def test_empty_values_dict_uses_defaults(self, placeholder_engine):
        """
        BV: Empty values dict triggers default fallback.
        """
        text = "nc -lvnp <LPORT>"
        result = placeholder_engine.substitute(text, {})

        # <LPORT> has default_value='4444'
        assert result == "nc -lvnp 4444"

    def test_none_values_dict_uses_defaults(self, placeholder_engine):
        """
        BV: None values dict handled like empty.
        """
        text = "nc -lvnp <LPORT>"
        result = placeholder_engine.substitute(text, None)

        assert result == "nc -lvnp 4444"


# =============================================================================
# PlaceholderEngine with Config Integration (BV: HIGH)
# =============================================================================

class TestPlaceholderWithConfig:
    """Tests for placeholder engine with config manager integration."""

    def test_uses_config_values_for_substitution(self, mock_config_manager):
        """
        BV: Config values automatically applied.

        Scenario:
          Given: ConfigManager with preset values
          When: PlaceholderEngine initialized with config
          Then: Config values used in substitution
        """
        from reference.core.placeholder import PlaceholderEngine

        engine = PlaceholderEngine(config_manager=mock_config_manager)
        text = "nmap <TARGET>"
        result = engine.substitute(text, {})

        assert result == "nmap 192.168.1.100"

    def test_explicit_value_overrides_config(self, mock_config_manager):
        """
        BV: User-provided values override config.
        """
        from reference.core.placeholder import PlaceholderEngine

        engine = PlaceholderEngine(config_manager=mock_config_manager)
        text = "nmap <TARGET>"
        result = engine.substitute(text, {"<TARGET>": "10.10.10.1"})

        assert result == "nmap 10.10.10.1"  # Not the config value

    def test_merges_config_with_provided_values(self, mock_config_manager):
        """
        BV: Some from config, some from user input.
        """
        from reference.core.placeholder import PlaceholderEngine

        engine = PlaceholderEngine(config_manager=mock_config_manager)
        text = "reverse shell to <LHOST>:<LPORT> from <TARGET>"
        result = engine.substitute(text, {"<TARGET>": "victim.local"})

        # LHOST from config, TARGET from provided
        assert "10.10.14.5" in result  # Config LHOST
        assert "4444" in result  # Config LPORT
        assert "victim.local" in result  # Provided TARGET


# =============================================================================
# PlaceholderEngine.extract_placeholders() Tests (BV: HIGH)
# =============================================================================

class TestExtractPlaceholders:
    """Tests for placeholder extraction from text."""

    def test_extracts_single_placeholder(self, placeholder_engine):
        """
        BV: Single placeholder detected.
        """
        result = placeholder_engine.extract_placeholders("nmap <TARGET>")

        assert result == ["<TARGET>"]

    def test_extracts_multiple_placeholders(self, placeholder_engine):
        """
        BV: All placeholders detected in order.
        """
        result = placeholder_engine.extract_placeholders("nmap -p <PORT> <TARGET> -o <OUTPUT>")

        assert "<PORT>" in result
        assert "<TARGET>" in result
        assert "<OUTPUT>" in result
        assert len(result) == 3

    def test_extracts_duplicate_placeholders(self, placeholder_engine):
        """
        BV: Duplicates included (for counting occurrences).
        """
        result = placeholder_engine.extract_placeholders("<TARGET> ping <TARGET>")

        assert result.count("<TARGET>") == 2

    def test_returns_empty_for_no_placeholders(self, placeholder_engine):
        """
        BV: No placeholders returns empty list.
        """
        result = placeholder_engine.extract_placeholders("ls -la")

        assert result == []

    def test_only_extracts_uppercase_angle_bracket_format(self, placeholder_engine):
        """
        BV: Only <UPPERCASE> format recognized as placeholder.
        """
        text = "<VALID> {invalid} $invalid <invalid> <Also_Invalid>"
        result = placeholder_engine.extract_placeholders(text)

        assert result == ["<VALID>"]

    def test_extracts_placeholders_with_underscores(self, placeholder_engine):
        """
        BV: Underscores in placeholder names supported.
        """
        result = placeholder_engine.extract_placeholders("cmd <TARGET_IP> <DC_IP>")

        assert "<TARGET_IP>" in result
        assert "<DC_IP>" in result


# =============================================================================
# PlaceholderEngine.validate_value() Tests (BV: MEDIUM)
# =============================================================================

class TestValidateValue:
    """Tests for value validation against placeholder definitions."""

    def test_valid_ip_passes_validation(self, placeholder_engine):
        """
        BV: Correctly formatted values pass validation.
        """
        valid, message = placeholder_engine.validate_value("<TARGET_IP>", "192.168.1.100")

        assert valid is True

    def test_invalid_ip_fails_validation(self, placeholder_engine):
        """
        BV: Incorrectly formatted values caught early.
        """
        valid, message = placeholder_engine.validate_value("<TARGET_IP>", "not-an-ip")

        assert valid is False
        assert "format" in message.lower() or "match" in message.lower()

    def test_valid_port_passes_validation(self, placeholder_engine):
        """
        BV: Valid port numbers accepted.
        """
        valid, message = placeholder_engine.validate_value("<PORT>", "8080")

        assert valid is True

    def test_invalid_port_fails_validation(self, placeholder_engine):
        """
        BV: Non-numeric port caught.
        """
        valid, message = placeholder_engine.validate_value("<PORT>", "http")

        assert valid is False

    def test_unknown_placeholder_always_valid(self, placeholder_engine):
        """
        BV: Unknown placeholders pass (no validation rules).
        """
        valid, message = placeholder_engine.validate_value("<CUSTOM_UNKNOWN>", "anything")

        assert valid is True

    def test_password_has_no_validation(self, placeholder_engine):
        """
        BV: Passwords accept any value (security flexibility).
        """
        valid, message = placeholder_engine.validate_value("<PASSWORD>", "!@#$%^&*()")

        assert valid is True

    def test_url_validation(self, placeholder_engine):
        """
        BV: URLs must have http/https scheme.
        """
        valid_http, _ = placeholder_engine.validate_value("<URL>", "http://test.com")
        valid_https, _ = placeholder_engine.validate_value("<URL>", "https://test.com")
        invalid, _ = placeholder_engine.validate_value("<URL>", "ftp://test.com")

        assert valid_http is True
        assert valid_https is True
        assert invalid is False


# =============================================================================
# PlaceholderEngine Value Management Tests (BV: MEDIUM)
# =============================================================================

class TestPlaceholderValueManagement:
    """Tests for set_value/get_value/clear_values methods."""

    def test_set_and_get_value(self, placeholder_engine):
        """
        BV: Values can be stored and retrieved.
        """
        placeholder_engine.set_value("<TARGET>", "192.168.1.1")
        result = placeholder_engine.get_value("<TARGET>")

        assert result == "192.168.1.1"

    def test_get_nonexistent_value_returns_none(self, placeholder_engine):
        """
        BV: Missing values return None gracefully.
        """
        result = placeholder_engine.get_value("<NONEXISTENT>")

        assert result is None

    def test_clear_values_removes_all_user_values(self, placeholder_engine):
        """
        BV: Clear resets to clean state.
        """
        placeholder_engine.set_value("<TARGET>", "192.168.1.1")
        placeholder_engine.set_value("<PORT>", "8080")
        placeholder_engine.clear_values()

        assert placeholder_engine.get_value("<TARGET>") is None
        assert placeholder_engine.get_value("<PORT>") is None

    def test_stored_value_used_in_substitute(self, placeholder_engine):
        """
        BV: Stored values automatically used in substitution.
        """
        placeholder_engine.set_value("<TARGET>", "10.10.10.1")
        result = placeholder_engine.substitute("ping <TARGET>", {})

        assert result == "ping 10.10.10.1"


# =============================================================================
# Environment Variable Loading Tests (BV: MEDIUM)
# =============================================================================

class TestEnvironmentVariableLoading:
    """Tests for loading values from environment variables."""

    def test_loads_lhost_from_environment(self):
        """
        BV: LHOST loaded from environment for reverse shells.
        """
        from reference.core.placeholder import PlaceholderEngine

        with patch.dict(os.environ, {"LHOST": "10.10.14.99"}):
            engine = PlaceholderEngine()
            result = engine.get_value("<LHOST>")

            assert result == "10.10.14.99"

    def test_loads_interface_from_environment(self):
        """
        BV: Interface loaded from environment.
        """
        from reference.core.placeholder import PlaceholderEngine

        with patch.dict(os.environ, {"INTERFACE": "tun0"}):
            engine = PlaceholderEngine()
            result = engine.get_value("<INTERFACE>")

            assert result == "tun0"


# =============================================================================
# Custom Placeholder Definition Tests (BV: LOW)
# =============================================================================

class TestCustomPlaceholderDefinition:
    """Tests for adding custom placeholder definitions."""

    def test_add_custom_placeholder(self, placeholder_engine):
        """
        BV: Users can define project-specific placeholders.
        """
        placeholder_engine.add_custom_placeholder(
            name="<CUSTOM_DOMAIN>",
            description="Custom domain for testing",
            example="test.local",
            default="default.local"
        )

        text = "dig <CUSTOM_DOMAIN>"
        result = placeholder_engine.substitute(text, {})

        assert result == "dig default.local"

    def test_custom_placeholder_with_validation(self, placeholder_engine):
        """
        BV: Custom placeholders can have validation.
        """
        placeholder_engine.add_custom_placeholder(
            name="<CUSTOM_PORT>",
            description="Custom port",
            example="8080",
            regex=r"^\d{1,5}$"
        )

        valid, _ = placeholder_engine.validate_value("<CUSTOM_PORT>", "8080")
        invalid, _ = placeholder_engine.validate_value("<CUSTOM_PORT>", "not-a-port")

        assert valid is True
        assert invalid is False


# =============================================================================
# Suggest Values Tests (BV: LOW)
# =============================================================================

class TestSuggestValues:
    """Tests for placeholder value suggestions."""

    def test_suggests_common_ports(self, placeholder_engine):
        """
        BV: Users get helpful port suggestions.
        """
        suggestions = placeholder_engine.suggest_values("<PORT>")

        assert "80" in suggestions
        assert "443" in suggestions
        assert "22" in suggestions

    def test_suggests_common_wordlists(self, placeholder_engine):
        """
        BV: Users get common wordlist paths.
        """
        suggestions = placeholder_engine.suggest_values("<WORDLIST>")

        assert any("rockyou" in s for s in suggestions)

    def test_unknown_placeholder_no_suggestions(self, placeholder_engine):
        """
        BV: Unknown placeholders return empty suggestions.
        """
        suggestions = placeholder_engine.suggest_values("<UNKNOWN>")

        assert suggestions == []


# =============================================================================
# Export Definitions Tests (BV: LOW)
# =============================================================================

class TestExportDefinitions:
    """Tests for exporting placeholder definitions."""

    def test_exports_all_definitions(self, placeholder_engine):
        """
        BV: All definitions exportable for documentation.
        """
        result = placeholder_engine.export_definitions()

        assert isinstance(result, dict)
        assert "<TARGET>" in result
        assert "<LHOST>" in result
        assert "<PORT>" in result

    def test_export_includes_metadata(self, placeholder_engine):
        """
        BV: Export includes description and example.
        """
        result = placeholder_engine.export_definitions()

        target_def = result.get("<TARGET>", {})
        assert "description" in target_def
        assert "example" in target_def


# =============================================================================
# Command.fill_placeholders Integration Tests (BV: HIGH)
# =============================================================================

class TestCommandFillPlaceholders:
    """Tests for Command.fill_placeholders() method."""

    def test_fills_all_defined_placeholders(self):
        """
        BV: Command fills all placeholders from provided values.
        """
        from reference.core.registry import Command, CommandVariable

        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="nmap -p <PORT> <TARGET>",
            description="Test",
            variables=[
                CommandVariable(name="<PORT>", description="Port", example="80"),
                CommandVariable(name="<TARGET>", description="Target", example="192.168.1.1")
            ]
        )

        filled = cmd.fill_placeholders({
            "<PORT>": "443",
            "<TARGET>": "10.10.10.1"
        })

        assert filled == "nmap -p 443 10.10.10.1"

    def test_falls_back_to_example_for_missing_values(self):
        """
        BV: Missing values use variable examples.
        """
        from reference.core.registry import Command, CommandVariable

        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="nc -lvnp <LPORT>",
            description="Test",
            variables=[
                CommandVariable(name="<LPORT>", description="Port", example="4444")
            ]
        )

        filled = cmd.fill_placeholders({})

        assert filled == "nc -lvnp 4444"

    def test_partial_values_uses_examples_for_missing(self):
        """
        BV: Mix of provided and example values.
        """
        from reference.core.registry import Command, CommandVariable

        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="nmap -p <PORT> <TARGET>",
            description="Test",
            variables=[
                CommandVariable(name="<PORT>", description="Port", example="80"),
                CommandVariable(name="<TARGET>", description="Target", example="192.168.1.1")
            ]
        )

        filled = cmd.fill_placeholders({
            "<TARGET>": "victim.local"
            # <PORT> not provided
        })

        assert filled == "nmap -p 80 victim.local"

    def test_undefined_placeholder_left_intact(self):
        """
        BV: Placeholders without variables left as-is.
        """
        from reference.core.registry import Command

        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="custom <UNDEFINED>",
            description="Test",
            variables=[]  # No variables defined
        )

        filled = cmd.fill_placeholders({})

        assert "<UNDEFINED>" in filled


# =============================================================================
# PlaceholderDefinition Dataclass Tests (BV: LOW)
# =============================================================================

class TestPlaceholderDefinition:
    """Tests for PlaceholderDefinition dataclass."""

    def test_creates_with_required_fields(self):
        """
        BV: Definition created with minimal fields.
        """
        from reference.core.placeholder import PlaceholderDefinition

        defn = PlaceholderDefinition(
            name="<TEST>",
            description="Test placeholder",
            example="test_value"
        )

        assert defn.name == "<TEST>"
        assert defn.description == "Test placeholder"
        assert defn.example == "test_value"
        assert defn.default_value is None
        assert defn.validation_regex is None
        assert defn.source is None

    def test_creates_with_all_fields(self):
        """
        BV: Definition created with all fields.
        """
        from reference.core.placeholder import PlaceholderDefinition

        defn = PlaceholderDefinition(
            name="<PORT>",
            description="Port number",
            example="80",
            validation_regex=r"^\d+$",
            default_value="8080",
            source="PORT_ENV"
        )

        assert defn.validation_regex == r"^\d+$"
        assert defn.default_value == "8080"
        assert defn.source == "PORT_ENV"
