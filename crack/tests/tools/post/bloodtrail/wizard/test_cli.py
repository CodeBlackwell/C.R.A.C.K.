"""
Tests for BloodTrail Wizard CLI Integration (Phase 6).

Tests CLI argument parsing and handler integration.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from argparse import Namespace
from pathlib import Path


class TestWizardCLIIntegration:
    """Test CLI integration for wizard mode."""

    def test_wizard_flag_triggers_wizard_mode(self):
        """Test that --wizard flag triggers wizard mode execution."""
        from tools.post.bloodtrail.cli.commands.wizard import WizardCommands

        # Mock args with wizard flag
        args = Namespace(
            wizard=True,
            wizard_target=None,
            bh_data_dir="10.10.10.182",
            wizard_resume=None
        )

        # Mock WizardFlow at the wizard package level (where it's imported FROM)
        with patch('tools.post.bloodtrail.wizard.WizardFlow') as mock_flow_class:
            mock_flow = Mock()
            mock_flow.run.return_value = Mock()
            mock_flow_class.return_value = mock_flow

            result = WizardCommands.handle(args)

            # Verify WizardFlow was created with correct parameters
            mock_flow_class.assert_called_once_with(target="10.10.10.182", resume=False)

            # Verify run() was called
            mock_flow.run.assert_called_once()

            # Verify success return code
            assert result == 0

    def test_wizard_command_returns_zero_on_success(self):
        """Test that wizard command returns exit code 0 on success."""
        from tools.post.bloodtrail.cli.commands.wizard import WizardCommands

        args = Namespace(
            wizard=True,
            wizard_target=None,
            bh_data_dir="192.168.1.100",
            wizard_resume=None
        )

        # Mock WizardFlow to return successfully
        with patch('tools.post.bloodtrail.wizard.WizardFlow') as mock_flow_class:
            mock_flow = Mock()
            mock_flow.run.return_value = Mock(current_step="done")
            mock_flow_class.return_value = mock_flow

            result = WizardCommands.handle(args)

            assert result == 0

    def test_wizard_resume_flag_loads_state(self):
        """Test that --wizard-resume loads saved state and resumes."""
        from tools.post.bloodtrail.cli.commands.wizard import WizardCommands

        # Mock args with resume flag
        args = Namespace(
            wizard=False,
            wizard_resume="10.10.10.182",
            wizard_target=None,
            bh_data_dir=None
        )

        # Mock WizardFlow
        with patch('tools.post.bloodtrail.wizard.WizardFlow') as mock_flow_class:
            mock_flow = Mock()
            mock_flow.run.return_value = Mock()
            mock_flow_class.return_value = mock_flow

            result = WizardCommands.handle(args)

            # Verify WizardFlow was created with resume=True
            mock_flow_class.assert_called_once_with(target="10.10.10.182", resume=True)

            # Verify run() was called
            mock_flow.run.assert_called_once()

            # Verify success
            assert result == 0

    def test_wizard_help_shows_in_tiered_help(self):
        """Test that --wizard appears in help output with proper description."""
        from tools.post.bloodtrail.cli.parser import create_parser

        # Create parser
        parser = create_parser()

        # Get help text
        help_text = parser.format_help()

        # Verify wizard arguments are present
        assert "--wizard" in help_text
        assert "--wizard-resume" in help_text
        assert "--wizard-target" in help_text

        # Verify in appropriate section (should be near top for discoverability)
        assert "Wizard" in help_text or "wizard" in help_text

    def test_wizard_target_alternative_to_positional(self):
        """Test that --wizard-target can be used instead of positional."""
        from tools.post.bloodtrail.cli.commands.wizard import WizardCommands

        # Mock args with wizard-target instead of bh_data_dir
        args = Namespace(
            wizard=True,
            wizard_target="192.168.5.10",
            bh_data_dir=None,
            wizard_resume=None
        )

        with patch('tools.post.bloodtrail.wizard.WizardFlow') as mock_flow_class:
            mock_flow = Mock()
            mock_flow.run.return_value = Mock()
            mock_flow_class.return_value = mock_flow

            result = WizardCommands.handle(args)

            # Verify WizardFlow received wizard_target value
            mock_flow_class.assert_called_once_with(target="192.168.5.10", resume=False)
            assert result == 0

    def test_wizard_not_handled_returns_minus_one(self):
        """Test that WizardCommands returns -1 when wizard flags not set."""
        from tools.post.bloodtrail.cli.commands.wizard import WizardCommands

        # Mock args without wizard flags
        args = Namespace(
            wizard=False,
            wizard_resume=None,
            wizard_target=None,
            bh_data_dir="/path/to/bh/json"
        )

        result = WizardCommands.handle(args)

        # Should return -1 (not handled)
        assert result == -1

    def test_wizard_commands_registered_in_command_groups(self):
        """Test that WizardCommands is in COMMAND_GROUPS list."""
        from tools.post.bloodtrail.cli.commands import COMMAND_GROUPS
        from tools.post.bloodtrail.cli.commands.wizard import WizardCommands

        # Verify WizardCommands is in the registry
        assert WizardCommands in COMMAND_GROUPS

        # Verify it's BEFORE EnumerateCommands (higher priority)
        from tools.post.bloodtrail.cli.commands.enumerate import EnumerateCommands

        wizard_idx = COMMAND_GROUPS.index(WizardCommands)
        enum_idx = COMMAND_GROUPS.index(EnumerateCommands)

        assert wizard_idx < enum_idx, "WizardCommands should have higher priority than EnumerateCommands"

    def test_wizard_flow_exception_handling(self):
        """Test that exceptions during wizard flow are handled gracefully."""
        from tools.post.bloodtrail.cli.commands.wizard import WizardCommands

        args = Namespace(
            wizard=True,
            wizard_target=None,
            bh_data_dir="10.10.10.182",
            wizard_resume=None
        )

        # Mock WizardFlow to raise an exception
        with patch('tools.post.bloodtrail.wizard.WizardFlow') as mock_flow_class:
            mock_flow = Mock()
            mock_flow.run.side_effect = Exception("Test error")
            mock_flow_class.return_value = mock_flow

            # Should re-raise exception for higher-level handling
            with pytest.raises(Exception):
                WizardCommands.handle(args)
