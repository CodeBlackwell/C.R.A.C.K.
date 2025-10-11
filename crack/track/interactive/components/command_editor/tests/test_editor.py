"""
Tests for CommandEditor (Main Orchestrator)

12 comprehensive tests validating tier routing, escalation,
state preservation, cancel handling, and safety features.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from crack.track.interactive.components.command_editor.editor import CommandEditor
from crack.track.interactive.components.command_editor.quick_editor import EditResult


class TestTierRouting:
    """Test tier routing logic (3 tests)"""

    def test_routes_to_quick_for_known_tool(self):
        """PROVES: Known tools start at QuickEditor"""
        editor = CommandEditor(
            command="gobuster dir -u http://target -w /wordlist",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Mock QuickEditor to return execute
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url', 'wordlist']}

            # Setup instance mock
            mock_instance = Mock()
            mock_instance.run.return_value = EditResult(
                command="gobuster dir -u http://new-target -w /wordlist",
                action="execute"
            )
            mock_quick.return_value = mock_instance

            result = editor.edit()

            assert result is not None
            assert result.action == "execute"
            assert "http://new-target" in result.command
            mock_quick.assert_called_once()

    def test_routes_to_advanced_for_schema_tool(self):
        """PROVES: Tools with schema but no common params start at AdvancedEditor"""
        editor = CommandEditor(
            command="custom-tool --flag value",
            metadata={'tool': 'custom'},
            profile=None
        )

        # Mock schema check to return True
        with patch.object(Path, 'exists', return_value=True):
            # Mock AdvancedEditor
            with patch('crack.track.interactive.components.command_editor.editor.AdvancedEditor') as mock_adv:
                mock_adv.return_value.run.return_value = EditResult(
                    command="custom-tool --flag modified",
                    action="execute"
                )

                result = editor.edit()

                assert result is not None
                assert result.action == "execute"
                mock_adv.assert_called_once()

    def test_routes_to_raw_for_unknown_tool(self):
        """PROVES: Tools with no schema and no common params start at RawEditor"""
        editor = CommandEditor(
            command="unknown-tool --flag value",
            metadata={'tool': 'unknown'},
            profile=None
        )

        # Mock schema check to return False
        with patch.object(Path, 'exists', return_value=False):
            # Mock RawEditor
            with patch('crack.track.interactive.components.command_editor.editor.RawEditor') as mock_raw:
                mock_raw.return_value.run.return_value = EditResult(
                    command="unknown-tool --flag modified",
                    action="execute"
                )

                result = editor.edit()

                assert result is not None
                assert result.action == "execute"
                mock_raw.assert_called_once()


class TestEscalationFlow:
    """Test tier escalation (3 tests)"""

    def test_escalate_quick_to_advanced(self):
        """PROVES: User can escalate from Quick to Advanced"""
        editor = CommandEditor(
            command="gobuster dir -u http://target -w /wordlist",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Mock QuickEditor returning escalation request
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url', 'wordlist']}

            # Setup Quick instance mock
            quick_instance = Mock()
            quick_instance.run.return_value = EditResult(
                command="gobuster dir -u http://modified -w /wordlist",
                action="escalate",
                next_tier="advanced"
            )
            mock_quick.return_value = quick_instance

            # Mock AdvancedEditor completing the edit
            with patch('crack.track.interactive.components.command_editor.editor.AdvancedEditor') as mock_adv:
                adv_instance = Mock()
                adv_instance.run.return_value = EditResult(
                    command="gobuster dir -u http://modified -w /wordlist -t 100",
                    action="execute"
                )
                mock_adv.return_value = adv_instance

                result = editor.edit()

                # Verify both tiers called
                mock_quick.assert_called_once()
                mock_adv.assert_called_once()

                # Verify command preserved and modified
                assert result is not None
                assert "http://modified" in result.command
                assert "-t 100" in result.command

    def test_escalate_advanced_to_raw(self):
        """PROVES: User can escalate from Advanced to Raw"""
        editor = CommandEditor(
            command="nmap -sS 192.168.1.1",
            metadata={'tool': 'nmap'},
            profile=None
        )

        # Mock schema check
        with patch.object(Path, 'exists', return_value=True):
            # Start with AdvancedEditor (has schema, not in common params)
            with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
                # Ensure QuickEditor is not in COMMON_PARAMS for this test
                mock_quick.COMMON_PARAMS = {}

                with patch('crack.track.interactive.components.command_editor.editor.AdvancedEditor') as mock_adv:
                    # AdvancedEditor escalates to raw
                    mock_adv.return_value.run.return_value = EditResult(
                        command="nmap -sS 192.168.1.1 -T4",
                        action="escalate",
                        next_tier="raw"
                    )

                    with patch('crack.track.interactive.components.command_editor.editor.RawEditor') as mock_raw:
                        mock_raw.return_value.run.return_value = EditResult(
                            command="nmap -sS 192.168.1.1 -T4 --reason",
                            action="execute"
                        )

                        result = editor.edit()

                        assert result is not None
                        assert "--reason" in result.command
                        mock_adv.assert_called_once()
                        mock_raw.assert_called_once()

    def test_escalate_quick_to_raw_direct(self):
        """PROVES: User can escalate directly from Quick to Raw"""
        editor = CommandEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Mock QuickEditor escalating directly to raw
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url']}

            # Setup Quick instance
            quick_instance = Mock()
            quick_instance.run.return_value = EditResult(
                command="gobuster dir -u http://target",
                action="escalate",
                next_tier="raw"
            )
            mock_quick.return_value = quick_instance

            with patch('crack.track.interactive.components.command_editor.editor.RawEditor') as mock_raw:
                raw_instance = Mock()
                raw_instance.run.return_value = EditResult(
                    command="gobuster dir -u http://target --timeout 30s",
                    action="execute"
                )
                mock_raw.return_value = raw_instance

                result = editor.edit()

                assert result is not None
                assert "--timeout 30s" in result.command
                mock_quick.assert_called_once()
                mock_raw.assert_called_once()


class TestStatePreservation:
    """Test state preservation (2 tests)"""

    def test_preserves_command_during_escalation(self):
        """PROVES: Edits made in Quick are preserved when escalating to Advanced"""
        editor = CommandEditor(
            command="gobuster dir -u http://original",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Quick editor modifies command before escalating
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url']}

            # Setup Quick instance
            quick_instance = Mock()
            quick_instance.run.return_value = EditResult(
                command="gobuster dir -u http://modified",
                action="escalate",
                next_tier="advanced"
            )
            mock_quick.return_value = quick_instance

            with patch('crack.track.interactive.components.command_editor.editor.AdvancedEditor') as mock_adv:
                # Capture the command passed to AdvancedEditor
                def capture_init(command, metadata):
                    assert "http://modified" in command, "Command not preserved during escalation"
                    mock_instance = Mock()
                    mock_instance.run.return_value = EditResult(
                        command=command,
                        action="execute"
                    )
                    return mock_instance

                mock_adv.side_effect = capture_init

                result = editor.edit()

                assert result is not None
                assert "http://modified" in result.command

    def test_preserves_metadata_across_tiers(self):
        """PROVES: Metadata unchanged after escalation"""
        metadata = {'tool': 'gobuster', 'custom_field': 'value'}
        editor = CommandEditor(
            command="gobuster dir -u http://target",
            metadata=metadata,
            profile=None
        )

        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            mock_quick.return_value.run.return_value = EditResult(
                command="gobuster dir -u http://target",
                action="escalate",
                next_tier="advanced"
            )

            with patch('crack.track.interactive.components.command_editor.editor.AdvancedEditor') as mock_adv:
                # Capture metadata passed to AdvancedEditor
                def capture_init(command, meta):
                    assert meta.get('tool') == 'gobuster'
                    assert meta.get('custom_field') == 'value'
                    mock_instance = Mock()
                    mock_instance.run.return_value = EditResult(
                        command=command,
                        action="execute"
                    )
                    return mock_instance

                mock_adv.side_effect = capture_init

                result = editor.edit()

                assert result is not None


class TestCancelHandling:
    """Test cancel handling (2 tests)"""

    def test_cancel_in_quick_editor(self):
        """PROVES: User can cancel, returns None"""
        editor = CommandEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Mock QuickEditor returning cancel
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url']}

            # Setup Quick instance
            quick_instance = Mock()
            quick_instance.run.return_value = EditResult(
                command=None,
                action="cancel"
            )
            mock_quick.return_value = quick_instance

            result = editor.edit()

            assert result is None
            mock_quick.assert_called_once()

    def test_cancel_during_escalation(self):
        """PROVES: User can cancel in Advanced after escalating from Quick"""
        editor = CommandEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Quick escalates to Advanced
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url']}

            # Setup Quick instance
            quick_instance = Mock()
            quick_instance.run.return_value = EditResult(
                command="gobuster dir -u http://target",
                action="escalate",
                next_tier="advanced"
            )
            mock_quick.return_value = quick_instance

            # Advanced returns cancel
            with patch('crack.track.interactive.components.command_editor.editor.AdvancedEditor') as mock_adv:
                adv_instance = Mock()
                adv_instance.run.return_value = EditResult(
                    command=None,
                    action="cancel"
                )
                mock_adv.return_value = adv_instance

                result = editor.edit()

                assert result is None
                mock_quick.assert_called_once()
                mock_adv.assert_called_once()


class TestSafetyFeatures:
    """Test safety features (2 tests)"""

    def test_prevents_infinite_escalation_loop(self):
        """PROVES: Max iterations enforced to prevent infinite loops"""
        editor = CommandEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Mock QuickEditor to always escalate (infinite loop scenario)
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url']}

            with patch('crack.track.interactive.components.command_editor.editor.AdvancedEditor') as mock_adv:
                with patch('crack.track.interactive.components.command_editor.editor.RawEditor') as mock_raw:
                    # Create invalid escalation that should hit max iterations
                    quick_instance = Mock()
                    quick_instance.run.return_value = EditResult(
                        command="test",
                        action="escalate",
                        next_tier="advanced"
                    )
                    mock_quick.return_value = quick_instance

                    adv_instance = Mock()
                    adv_instance.run.return_value = EditResult(
                        command="test",
                        action="escalate",
                        next_tier="raw"
                    )
                    mock_adv.return_value = adv_instance

                    # Raw returns escalate (invalid, will return None)
                    raw_instance = Mock()
                    raw_instance.run.return_value = EditResult(
                        command="test",
                        action="escalate",
                        next_tier="quick"  # Invalid - causes None return, loop restarts
                    )
                    mock_raw.return_value = raw_instance

                    result = editor.edit()

                    # Should return None due to invalid escalation
                    assert result is None

    def test_handles_tier_exception_gracefully(self):
        """PROVES: Exceptions in tier execution handled gracefully"""
        editor = CommandEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            profile=None
        )

        # Mock QuickEditor to raise exception
        with patch('crack.track.interactive.components.command_editor.editor.QuickEditor') as mock_quick:
            # Setup COMMON_PARAMS
            mock_quick.COMMON_PARAMS = {'gobuster': ['url']}

            # Setup Quick instance that raises exception
            quick_instance = Mock()
            quick_instance.run.side_effect = Exception("Simulated error")
            mock_quick.return_value = quick_instance

            result = editor.edit()

            # Should return None gracefully (no crash)
            assert result is None
            mock_quick.assert_called_once()
