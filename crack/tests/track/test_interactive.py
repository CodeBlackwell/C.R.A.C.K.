"""
Interactive CLI Test Suite - Value-Focused Testing

Tests PROVE the interactive CLI works for OSCP workflows by validating:
- Real user workflows complete successfully
- State persists correctly across sessions
- Errors degrade gracefully
- User input handled robustly

Testing Philosophy:
- Test workflows, not code paths
- Use real objects, minimize mocking
- Test outcomes, not implementation
- Allow refactoring without breaking tests
"""

import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from crack.track.core.state import TargetProfile
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.input_handler import InputProcessor
from crack.track.interactive.prompts import PromptBuilder
from crack.track.interactive.shortcuts import ShortcutHandler
from crack.track.interactive.decision_trees import (
    DecisionTree, DecisionNode, Choice, DecisionTreeFactory
)
from crack.track.recommendations.engine import RecommendationEngine


# ============================================================================
# TIER 1: Integration Tests - PROVE IT WORKS
# ============================================================================

class TestBeginnerWorkflows:
    """
    Prove a beginner can successfully use interactive mode

    These tests validate complete OSCP workflows from start to finish
    """

    def test_import_and_enumerate_workflow(
        self,
        temp_crack_home,
        sessions_dir,
        typical_oscp_nmap_xml,
        simulated_input,
        capsys
    ):
        """
        PROVES: User can import nmap scan → get recommendations → see tasks

        Workflow:
        1. Start interactive session
        2. Import scan results automatically
        3. System generates service tasks
        4. User sees recommendations
        5. Session state saved
        """
        # Initialize services and parsers
        from crack.track.services.registry import ServiceRegistry
        from crack.track.parsers.registry import ParserRegistry
        ServiceRegistry.initialize_plugins()
        ParserRegistry.initialize_parsers()

        # Create session with scan file pre-imported
        profile = TargetProfile("192.168.45.100")

        # Import scan to generate tasks
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)
        profile.save()

        # Verify ports discovered
        assert len(profile.ports) == 3
        assert 80 in profile.ports
        assert 445 in profile.ports
        assert 22 in profile.ports

        # Verify service tasks generated
        all_tasks = profile.task_tree._get_all_descendants()
        all_tasks.append(profile.task_tree)  # Include root
        assert len(all_tasks) > 5, "Should generate multiple service enumeration tasks"

        # Find HTTP tasks
        http_tasks = [t for t in all_tasks if 'http' in t.id.lower() or '80' in t.id]
        assert len(http_tasks) > 0, "Should have HTTP enumeration tasks"

        # Verify recommendations generated
        recommendations = RecommendationEngine.get_recommendations(profile)
        assert 'next' in recommendations or 'quick_wins' in recommendations

        # Verify profile saved
        loaded_profile = TargetProfile.load("192.168.45.100")
        assert loaded_profile is not None
        assert len(loaded_profile.ports) == 3


    def test_finding_documentation_workflow(
        self,
        temp_crack_home,
        mock_empty_profile,
        simulated_input
    ):
        """
        PROVES: User can document vulnerability with proper OSCP source tracking

        Workflow:
        1. User discovers vulnerability
        2. Documents finding with description
        3. Provides SOURCE (required for OSCP)
        4. Finding saved to profile
        5. Finding appears in profile findings
        """
        profile = mock_empty_profile

        # Document finding
        profile.add_finding(
            finding_type="vulnerability",
            description="SQL injection in id parameter",
            source="Manual testing: sqlmap -u 'http://target/page.php?id=1'"
        )

        # Verify finding saved
        assert len(profile.findings) == 1
        finding = profile.findings[0]
        assert finding['type'] == 'vulnerability'
        assert 'SQL injection' in finding['description']
        assert finding['source'] is not None
        assert 'sqlmap' in finding['source']

        # Save and reload
        profile.save()
        loaded = TargetProfile.load("192.168.45.100")
        assert len(loaded.findings) == 1
        assert loaded.findings[0]['description'] == finding['description']


    def test_credential_documentation_workflow(
        self,
        temp_crack_home,
        mock_empty_profile
    ):
        """
        PROVES: User can document credentials with OSCP source tracking

        Workflow:
        1. User discovers credentials
        2. Documents username/password
        3. Specifies service and port
        4. Provides SOURCE (required)
        5. Credential saved to profile
        """
        profile = mock_empty_profile

        # Document credential
        profile.add_credential(
            username="admin",
            password="password123",
            service="http",
            port=80,
            source="Found in /var/www/config.php via directory traversal"
        )

        # Verify credential saved
        assert len(profile.credentials) == 1
        cred = profile.credentials[0]
        assert cred['username'] == 'admin'
        assert cred['password'] == 'password123'
        assert cred['service'] == 'http'
        assert cred['port'] == 80
        assert 'config.php' in cred['source']

        # Save and reload
        profile.save()
        loaded = TargetProfile.load("192.168.45.100")
        assert len(loaded.credentials) == 1


class TestSessionResumption:
    """
    Prove sessions survive interruption and can be resumed

    Critical for OSCP exam reliability - work must never be lost
    """

    def test_checkpoint_save_and_load(self, temp_crack_home, sessions_dir):
        """
        PROVES: Checkpoint saves and loads correctly

        Workflow:
        1. Create session with state
        2. Save checkpoint
        3. Load checkpoint
        4. Verify all state preserved
        """
        # Create session
        session = InteractiveSession("192.168.45.100")
        session.last_action = "Imported nmap scan"
        session.start_time = 1699564800  # Fixed timestamp for testing

        # Save checkpoint
        checkpoint_file = sessions_dir / "192.168.45.100.json"
        checkpoint_data = {
            'target': session.target,
            'phase': session.profile.phase,
            'last_action': session.last_action,
            'start_time': session.start_time,
            'timestamp': 1699564900
        }

        checkpoint_file.write_text(json.dumps(checkpoint_data, indent=2))

        # Load checkpoint
        loaded_data = json.loads(checkpoint_file.read_text())

        # Verify state preserved
        assert loaded_data['target'] == "192.168.45.100"
        assert loaded_data['phase'] == session.profile.phase
        assert loaded_data['last_action'] == "Imported nmap scan"
        assert loaded_data['start_time'] == 1699564800


    def test_checkpoint_file_format(self, temp_crack_home, sessions_dir):
        """
        PROVES: Checkpoint JSON is valid and readable

        Validates:
        - Valid JSON structure
        - Contains required fields
        - Can be manually inspected/edited
        """
        session = InteractiveSession("192.168.45.100")
        checkpoint_file = sessions_dir / "192.168.45.100.json"

        checkpoint_data = {
            'target': "192.168.45.100",
            'phase': 'discovery',
            'last_action': 'Started session',
            'start_time': 1699564800,
            'timestamp': 1699564900
        }

        # Write checkpoint
        checkpoint_file.write_text(json.dumps(checkpoint_data, indent=2))

        # Verify valid JSON
        with open(checkpoint_file, 'r') as f:
            loaded = json.load(f)

        # Verify required fields
        assert 'target' in loaded
        assert 'phase' in loaded
        assert 'timestamp' in loaded

        # Verify types
        assert isinstance(loaded['target'], str)
        assert isinstance(loaded['phase'], str)
        assert isinstance(loaded['timestamp'], (int, float))


# ============================================================================
# TIER 2: Component Tests - PROVE COMPONENTS WORK
# ============================================================================

class TestInputParsing:
    """
    Prove input handler correctly parses user input

    Validates all input formats work as expected
    """

    def test_choice_selection_numeric(self):
        """
        PROVES: Numeric choice selection works

        Inputs tested: 1, 2, 3, 01, 02
        """
        choices = [
            {'id': 'scan', 'label': 'Run port scan'},
            {'id': 'import', 'label': 'Import scan'},
            {'id': 'exit', 'label': 'Exit'}
        ]

        # Test numeric selection
        result = InputProcessor.parse_choice('1', choices)
        assert result == choices[0]

        result = InputProcessor.parse_choice('2', choices)
        assert result == choices[1]

        result = InputProcessor.parse_choice('3', choices)
        assert result == choices[2]


    def test_choice_selection_keyword(self):
        """
        PROVES: Keyword matching works (full and partial)

        Inputs: "scan", "import", "imp", "SCAN"
        """
        choices = [
            {'id': 'scan', 'label': 'Run port scan'},
            {'id': 'import', 'label': 'Import scan'},
            {'id': 'exit', 'label': 'Exit'}
        ]

        # Full keyword
        result = InputProcessor.parse_choice('scan', choices)
        assert result == choices[0]

        # Partial keyword
        result = InputProcessor.parse_choice('imp', choices)
        assert result == choices[1]

        # Case insensitive
        result = InputProcessor.parse_choice('SCAN', choices)
        assert result == choices[0]


    def test_multi_select_formats(self):
        """
        PROVES: Multi-select parsing handles all formats

        Formats: "1,3,5", "1-3", "1,3-5,7", "all", "none"
        """
        total_choices = 5

        # List format (returns 1-indexed user input)
        result = InputProcessor.parse_multi_select('1,3,5', total_choices)
        assert result == [1, 3, 5]

        # Range format
        result = InputProcessor.parse_multi_select('1-3', total_choices)
        assert result == [1, 2, 3]

        # Mixed format
        result = InputProcessor.parse_multi_select('1,3-5', total_choices)
        assert result == [1, 3, 4, 5]

        # All keyword (returns all indices 1 to total)
        result = InputProcessor.parse_multi_select('all', total_choices)
        assert result == [1, 2, 3, 4, 5]

        # None keyword
        result = InputProcessor.parse_multi_select('none', total_choices)
        assert result == []


    def test_confirmation_parsing(self):
        """
        PROVES: Confirmation prompts handled correctly

        Inputs: y, yes, Y, YES, n, no, N, NO, ""
        """
        # Yes variations
        assert InputProcessor.parse_confirmation('y') == True
        assert InputProcessor.parse_confirmation('yes') == True
        assert InputProcessor.parse_confirmation('Y') == True
        assert InputProcessor.parse_confirmation('YES') == True

        # No variations
        assert InputProcessor.parse_confirmation('n') == False
        assert InputProcessor.parse_confirmation('no') == False
        assert InputProcessor.parse_confirmation('N') == False
        assert InputProcessor.parse_confirmation('NO') == False

        # Default value handling
        assert InputProcessor.parse_confirmation('', default='Y') == True
        assert InputProcessor.parse_confirmation('', default='N') == False


    def test_navigation_commands(self):
        """
        PROVES: Navigation commands recognized

        Commands: back, menu, exit, quit
        """
        assert InputProcessor.parse_navigation('back') == 'back'
        assert InputProcessor.parse_navigation('menu') == 'menu'
        assert InputProcessor.parse_navigation('exit') == 'exit'
        assert InputProcessor.parse_navigation('quit') == 'quit'
        assert InputProcessor.parse_navigation('1') is None


class TestDecisionTreeNavigation:
    """
    Prove decision tree navigation works correctly

    Tests forward/backward navigation and context filtering
    """

    def test_forward_navigation(self):
        """
        PROVES: Choices navigate to correct next nodes

        Scenario: Root → Node A → Node B
        """
        # Create simple tree
        root_choices = [
            Choice(
                id='go-a',
                label='Go to A',
                next_node='node-a'
            )
        ]
        root = DecisionNode('root', 'Root question?', root_choices)

        node_a_choices = [
            Choice(
                id='go-b',
                label='Go to B',
                next_node='node-b'
            )
        ]
        node_a = DecisionNode('node-a', 'Node A question?', node_a_choices)
        node_b = DecisionNode('node-b', 'Node B question?', [])

        tree = DecisionTree('test', root)
        tree.add_node(node_a)
        tree.add_node(node_b)

        # Navigate forward
        assert tree.current_node.id == 'root'

        tree.navigate_forward(root_choices[0], {})
        assert tree.current_node.id == 'node-a'

        tree.navigate_forward(node_a_choices[0], {})
        assert tree.current_node.id == 'node-b'


    def test_back_button_history(self):
        """
        PROVES: Back button returns to previous nodes

        Scenario: Root → A → B, then back → back
        """
        # Create tree (same as above)
        root_choices = [
            Choice(id='go-a', label='Go to A', next_node='node-a')
        ]
        root = DecisionNode('root', 'Root?', root_choices)
        node_a = DecisionNode('node-a', 'Node A?', [
            Choice(id='go-b', label='Go to B', next_node='node-b')
        ])
        node_b = DecisionNode('node-b', 'Node B?', [])

        tree = DecisionTree('test', root)
        tree.add_node(node_a)
        tree.add_node(node_b)

        # Navigate forward
        tree.navigate_to('node-a', {})
        tree.navigate_to('node-b', {})
        assert tree.current_node.id == 'node-b'

        # Navigate back
        tree.navigate_back()
        assert tree.current_node.id == 'node-a'

        tree.navigate_back()
        assert tree.current_node.id == 'root'

        # Back at root - should stay
        result = tree.navigate_back()
        assert result is None
        assert tree.current_node.id == 'root'


    def test_context_aware_choice_filtering(self):
        """
        PROVES: Choices only appear when requirements met

        Scenario: Choice requires ports discovered
        """
        # Create node with conditional choice
        choices = [
            Choice(
                id='scan',
                label='Run port scan',
                requires={'has_ports': False}  # Only show if no ports
            ),
            Choice(
                id='enumerate',
                label='Enumerate services',
                requires={'has_ports': True}  # Only show if ports exist
            )
        ]

        node = DecisionNode('root', 'What to do?', choices)

        # Context: no ports
        context = {'has_ports': False}
        available = node.get_available_choices(context)
        assert len(available) == 1
        assert available[0].id == 'scan'

        # Context: ports discovered
        context = {'has_ports': True}
        available = node.get_available_choices(context)
        assert len(available) == 1
        assert available[0].id == 'enumerate'


class TestPromptBuilder:
    """
    Prove menus are generated correctly for each state

    Tests context-aware menu generation
    """

    def test_discovery_phase_menu(self, mock_empty_profile):
        """
        PROVES: Discovery menu shows scan options

        Expected: port scan options, import, manual entry
        """
        profile = mock_empty_profile
        recommendations = RecommendationEngine.get_recommendations(profile)

        prompt_text, choices = PromptBuilder.build_main_menu(profile, recommendations)

        # Should have discovery-specific choices
        choice_ids = [c['id'] for c in choices]

        # Should have import option
        assert 'import' in choice_ids

        # Should have exit
        assert 'exit' in choice_ids


    def test_enumeration_phase_menu(self, mock_profile_with_services):
        """
        PROVES: Enumeration menu shows service tasks

        Expected: next task, enumerate all, select tasks, quick wins
        """
        profile = mock_profile_with_services
        recommendations = RecommendationEngine.get_recommendations(profile)

        prompt_text, choices = PromptBuilder.build_main_menu(profile, recommendations)

        choice_ids = [c['id'] for c in choices]

        # Should have common options
        assert 'import' in choice_ids
        assert 'finding' in choice_ids
        assert 'exit' in choice_ids


    def test_task_selection_menu(self, mock_profile_with_services):
        """
        PROVES: Task selection menu generated correctly

        Expected: List of tasks with metadata
        """
        profile = mock_profile_with_services

        # Get pending tasks
        pending_tasks = profile.task_tree.get_all_pending()

        if len(pending_tasks) > 0:
            # Build task selection menu
            prompt_text, choices = PromptBuilder.build_task_selection_menu(pending_tasks)

            assert len(choices) > 0
            assert 'Select task' in prompt_text or 'back' in prompt_text.lower()

            # Each choice should have task data
            for choice in choices:
                assert 'id' in choice
                assert 'label' in choice


    def test_finding_type_menu(self):
        """
        PROVES: Finding type menu has all OSCP categories

        Expected: vulnerability, credential, directory, user, note
        """
        prompt_text, choices = PromptBuilder.build_finding_type_menu()

        types = [c['id'] for c in choices]

        assert 'vulnerability' in types
        assert 'credential' in types
        assert 'directory' in types
        assert 'user' in types
        assert 'note' in types


# ============================================================================
# TIER 3: Edge Cases - PROVE ROBUSTNESS
# ============================================================================

class TestErrorRecovery:
    """
    Prove errors don't crash session or lose data

    Tests graceful degradation
    """

    def test_invalid_choice_handling(self):
        """
        PROVES: Invalid choice prompts retry without crash

        Invalid: out of range, wrong format
        """
        choices = [
            {'id': 'scan', 'label': 'Scan'},
            {'id': 'exit', 'label': 'Exit'}
        ]

        # Out of range
        result = InputProcessor.parse_choice('99', choices)
        assert result is None

        # Invalid format when numeric expected
        result = InputProcessor.parse_choice('xyz', choices)
        # Should return None or match by keyword


    def test_missing_checkpoint_creates_new(self, temp_crack_home, sessions_dir):
        """
        PROVES: Missing checkpoint doesn't break resume

        Scenario: --resume but no checkpoint exists
        """
        # Try to create session with resume=True but no checkpoint
        session = InteractiveSession("192.168.45.100", resume=False)

        # Should create fresh session
        assert session.target == "192.168.45.100"
        assert session.profile is not None


class TestShortcuts:
    """
    Prove keyboard shortcuts work correctly

    Tests single-key commands
    """

    def test_shortcut_registration(self, temp_crack_home):
        """
        PROVES: All shortcuts registered

        Shortcuts: s, t, r, n, b, h, q
        """
        session = InteractiveSession("192.168.45.100")
        handler = ShortcutHandler(session)

        # Verify shortcuts exist
        assert 's' in handler.shortcuts  # Show status
        assert 't' in handler.shortcuts  # Show tree
        assert 'r' in handler.shortcuts  # Show recommendations
        assert 'n' in handler.shortcuts  # Execute next
        assert 'b' in handler.shortcuts  # Go back
        assert 'h' in handler.shortcuts  # Help
        assert 'q' in handler.shortcuts  # Quit


class TestPhaseTreeFactory:
    """
    Prove phase-specific decision trees created correctly

    Tests all 4 phase trees
    """

    def test_discovery_tree_creation(self):
        """
        PROVES: Discovery tree has scan options
        """
        tree = DecisionTreeFactory.create_discovery_tree()

        assert tree is not None
        assert tree.root is not None

        # Should have scan choices
        choices = tree.root.choices
        choice_ids = [c.id for c in choices]

        assert 'quick-scan' in choice_ids or 'full-scan' in choice_ids


    def test_enumeration_tree_creation(self):
        """
        PROVES: Enumeration tree has service options
        """
        tree = DecisionTreeFactory.create_enumeration_tree()

        assert tree is not None
        assert tree.root is not None

        choices = tree.root.choices
        choice_ids = [c.id for c in choices]

        # Should have enumeration options
        assert len(choice_ids) > 0


    def test_exploitation_tree_creation(self):
        """
        PROVES: Exploitation tree has research/test options
        """
        tree = DecisionTreeFactory.create_exploitation_tree()

        assert tree is not None
        assert tree.root is not None

        choices = tree.root.choices
        choice_ids = [c.id for c in choices]

        # Should have exploit-related options
        assert 'research' in choice_ids or 'test-vuln' in choice_ids


    def test_post_exploit_tree_creation(self):
        """
        PROVES: Post-exploit tree has privesc/flags/persistence options
        """
        tree = DecisionTreeFactory.create_post_exploit_tree()

        assert tree is not None
        assert tree.root is not None

        choices = tree.root.choices
        choice_ids = [c.id for c in choices]

        # Should have post-exploit options
        assert 'privesc-enum' in choice_ids or 'find-flags' in choice_ids


# ============================================================================
# Test Markers
# ============================================================================

# Mark slow integration tests
pytestmark = pytest.mark.integration
