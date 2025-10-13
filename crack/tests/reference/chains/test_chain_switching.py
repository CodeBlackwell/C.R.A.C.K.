"""
Integration tests for cross-chain activation and switching.

Tests the complete flow from parser activation → user selection → child chain launch → return.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from pathlib import Path

from crack.reference.chains.interactive import ChainInteractive
from crack.reference.chains.activation_manager import ActivationManager
from crack.reference.chains.parsing.base import ChainActivation, ParsingResult
from crack.reference.chains.session_storage import ChainSession


@pytest.fixture
def mock_chain_registry():
    """Mock ChainRegistry with test chains"""
    with patch('crack.reference.chains.interactive.ChainRegistry') as mock:
        registry = Mock()
        # Parent chain
        registry.get_chain.return_value = {
            'name': 'Test Parent Chain',
            'description': 'Parent chain for testing',
            'steps': [
                {
                    'id': 'step-1',
                    'name': 'Test Step',
                    'objective': 'Test objective',
                    'command_ref': 'test-command'
                }
            ]
        }
        mock.return_value = registry
        yield registry


@pytest.fixture
def mock_command_resolver():
    """Mock CommandResolver"""
    with patch('crack.reference.chains.interactive.CommandResolver') as mock:
        resolver = Mock()
        resolver.resolve_command_ref.return_value = True
        mock.return_value = resolver
        yield resolver


@pytest.fixture
def mock_command_registry():
    """Mock HybridCommandRegistry"""
    with patch('crack.reference.chains.interactive.HybridCommandRegistry') as mock:
        registry = Mock()
        cmd_mock = Mock()
        cmd_mock.name = 'test-command'
        cmd_mock.command = 'echo test'
        cmd_mock.extract_placeholders.return_value = []
        cmd_mock.fill_placeholders.return_value = 'echo test'
        cmd_mock.flag_explanations = {}
        registry.get_command.return_value = cmd_mock
        registry.interactive_fill.return_value = 'echo test'
        mock.return_value = registry
        yield registry


@pytest.fixture
def activation_manager():
    """Fresh ActivationManager for each test"""
    return ActivationManager()


@pytest.fixture
def sample_activations():
    """Sample chain activations from parser"""
    return [
        ChainActivation(
            chain_id='linux-privesc-sudo',
            reason='Found 3 GTFOBins-exploitable sudo entries',
            confidence='high',
            variables={'<BINARY>': 'vim'}
        ),
        ChainActivation(
            chain_id='linux-privesc-suid-basic',
            reason='Found 2 exploitable SUID binaries',
            confidence='medium',
            variables={'<BINARY>': 'find'}
        ),
        ChainActivation(
            chain_id='linux-capabilities',
            reason='Found 1 capability-based exploit',
            confidence='low',
            variables={}
        )
    ]


class TestActivationDetection:
    """Test activation detection in main loop"""

    def test_activation_detection_triggered_after_parsing(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry, tmp_path
    ):
        """Test that activation handler is called when parse result contains activations"""
        # Setup
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            session = Mock()
            session.current_step_index = 0
            session.variables = {'<TARGET>': '192.168.1.1'}
            session.step_outputs = {}
            mock_session_cls.return_value = session
            mock_session_cls.exists.return_value = False
            mock_session_cls.load.return_value = session

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor') as mock_proc:
                                # Create chain instance
                                chain = ChainInteractive('test-chain', target='192.168.1.1')

                                # Mock StepProcessor to return activations
                                parse_result = {
                                    'findings': {},
                                    'variables': {},
                                    'activates_chains': [
                                        ChainActivation(
                                            chain_id='linux-privesc-sudo',
                                            reason='Test activation',
                                            confidence='high'
                                        )
                                    ]
                                }
                                mock_proc.return_value.process_output.return_value = parse_result

                                # Mock _handle_chain_activations to track calls
                                with patch.object(chain, '_handle_chain_activations') as mock_handler:
                                    # Mock subprocess and confirmations
                                    with patch('subprocess.run') as mock_run:
                                        mock_run.return_value = Mock(returncode=0, stdout='test output', stderr='')

                                        with patch.object(chain, '_confirm') as mock_confirm:
                                            # First confirm = run command (yes)
                                            # Second confirm = mark complete (no, to stop)
                                            mock_confirm.side_effect = [True, False]

                                            # Run chain
                                            chain.run()

                                            # Verify activation handler was called
                                            mock_handler.assert_called_once()
                                            activations = mock_handler.call_args[0][0]
                                            assert len(activations) == 1
                                            assert activations[0].chain_id == 'linux-privesc-sudo'


class TestChainSwitchHandler:
    """Test _handle_chain_activations method"""

    def test_user_selects_first_activation(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager, sample_activations, tmp_path
    ):
        """Test user selecting first activation option"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            session = Mock()
            session.variables = {'<TARGET>': '192.168.1.1'}
            session.save = Mock()
            mock_session_cls.return_value = session
            mock_session_cls.exists.return_value = False
            mock_session_cls.load.return_value = session

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                # Create chain instance
                                chain = ChainInteractive(
                                    'test-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                # Mock _read_single_key to simulate user input
                                with patch.object(chain, '_read_single_key', return_value='1'):
                                    # Mock _launch_child_chain to avoid actual execution
                                    with patch.object(chain, '_launch_child_chain') as mock_launch:
                                        # Call handler
                                        chain._handle_chain_activations(sample_activations)

                                        # Verify session saved
                                        session.save.assert_called_once()

                                        # Verify child chain launched with first activation
                                        mock_launch.assert_called_once()
                                        launched_activation = mock_launch.call_args[0][0]
                                        assert launched_activation.chain_id == 'linux-privesc-sudo'

    def test_user_continues_current_chain(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager, sample_activations
    ):
        """Test user choosing to continue current chain (choice='c')"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            session = Mock()
            session.variables = {'<TARGET>': '192.168.1.1'}
            mock_session_cls.return_value = session
            mock_session_cls.exists.return_value = False

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                chain = ChainInteractive(
                                    'test-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                with patch.object(chain, '_read_single_key', return_value='c'):
                                    with patch.object(chain, '_launch_child_chain') as mock_launch:
                                        chain._handle_chain_activations(sample_activations)

                                        # Verify no child chain launched
                                        mock_launch.assert_not_called()

    def test_user_views_more_info(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager, sample_activations
    ):
        """Test user choosing to view detailed info (choice='i')"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            session = Mock()
            session.variables = {'<TARGET>': '192.168.1.1'}
            mock_session_cls.return_value = session
            mock_session_cls.exists.return_value = False

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                chain = ChainInteractive(
                                    'test-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                # Mock _read_single_key to return 'i' then 'c'
                                with patch.object(chain, '_read_single_key', side_effect=['i', 'c']):
                                    with patch.object(chain, '_show_activation_details') as mock_details:
                                        chain._handle_chain_activations(sample_activations)

                                        # Verify details shown
                                        mock_details.assert_called_once_with(sample_activations)


class TestCircularPrevention:
    """Test circular activation prevention"""

    def test_circular_activation_blocked(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager, sample_activations
    ):
        """Test that circular activation is prevented"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            session = Mock()
            session.variables = {'<TARGET>': '192.168.1.1'}
            mock_session_cls.return_value = session
            mock_session_cls.exists.return_value = False

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                # Setup: chain-a is already active
                                activation_manager.push_activation('chain-a')

                                # Create circular activation (back to chain-a)
                                circular_activation = [
                                    ChainActivation(
                                        chain_id='chain-a',
                                        reason='Circular test',
                                        confidence='high'
                                    )
                                ]

                                chain = ChainInteractive(
                                    'chain-b',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                with patch.object(chain, '_read_single_key', return_value='1'):
                                    with patch.object(chain, '_launch_child_chain') as mock_launch:
                                        chain._handle_chain_activations(circular_activation)

                                        # Verify launch NOT called (blocked)
                                        mock_launch.assert_not_called()


class TestVariableInheritance:
    """Test variable inheritance from parent to child"""

    def test_variables_inherited_from_parent_to_child(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager
    ):
        """Test that child chain inherits variables from parent"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            parent_session = Mock()
            parent_session.variables = {
                '<TARGET>': '192.168.1.1',
                '<LHOST>': '10.10.14.5'
            }
            child_session = Mock()
            child_session.variables = {}

            mock_session_cls.return_value = child_session
            mock_session_cls.exists.return_value = False
            mock_session_cls.load.return_value = parent_session

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                # Create child chain with parent variables
                                parent_vars = {
                                    '<TARGET>': '192.168.1.1',
                                    '<LHOST>': '10.10.14.5',
                                    '<BINARY>': 'vim'
                                }

                                child = ChainInteractive(
                                    'child-chain',
                                    target='192.168.1.1',
                                    parent_vars=parent_vars,
                                    activation_manager=activation_manager
                                )

                                # Verify variables merged into session
                                assert '<TARGET>' in child.session.variables
                                assert '<LHOST>' in child.session.variables
                                assert '<BINARY>' in child.session.variables


class TestChildChainLauncher:
    """Test _launch_child_chain method"""

    def test_child_chain_launched_and_returned(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager
    ):
        """Test complete child chain launch and return to parent"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            parent_session = Mock()
            parent_session.variables = {'<TARGET>': '192.168.1.1'}

            mock_session_cls.return_value = parent_session
            mock_session_cls.exists.return_value = False
            mock_session_cls.load.return_value = parent_session

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                parent = ChainInteractive(
                                    'parent-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                activation = ChainActivation(
                                    chain_id='child-chain',
                                    reason='Test launch',
                                    confidence='high',
                                    variables={'<BINARY>': 'vim'}
                                )

                                # Mock ChainInteractive class directly
                                with patch('crack.reference.chains.interactive.ChainInteractive') as mock_class:
                                    mock_child = Mock()
                                    mock_child.run = Mock()
                                    mock_class.return_value = mock_child

                                    # Launch child
                                    parent._launch_child_chain(activation)

                                    # Verify child created with correct params
                                    mock_class.assert_called_once()
                                    call_kwargs = mock_class.call_args[1]
                                    assert call_kwargs['chain_id'] == 'child-chain'
                                    assert call_kwargs['target'] == '192.168.1.1'
                                    assert '<BINARY>' in call_kwargs['parent_vars']

                                    # Verify activation recorded
                                    assert ('parent-chain', 'child-chain') in activation_manager.activation_history

                                    # Verify parent session reloaded
                                    assert mock_session_cls.load.called

    def test_keyboard_interrupt_handled_in_child(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager
    ):
        """Test keyboard interrupt in child chain is handled gracefully"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            parent_session = Mock()
            parent_session.variables = {'<TARGET>': '192.168.1.1'}

            mock_session_cls.return_value = parent_session
            mock_session_cls.exists.return_value = False
            mock_session_cls.load.return_value = parent_session

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                parent = ChainInteractive(
                                    'parent-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                activation = ChainActivation(
                                    chain_id='child-chain',
                                    reason='Test interrupt',
                                    confidence='high'
                                )

                                # Push activation for test
                                activation_manager.push_activation('parent-chain')

                                # Mock ChainInteractive to raise KeyboardInterrupt
                                with patch('crack.reference.chains.interactive.ChainInteractive') as mock_class:
                                    mock_child = Mock()
                                    mock_child.run = Mock(side_effect=KeyboardInterrupt)
                                    mock_class.return_value = mock_child

                                    # Launch child (should not raise)
                                    parent._launch_child_chain(activation)

                                    # Verify activation popped (cleanup happened)
                                    assert activation_manager.get_activation_depth() == 1  # Only parent


class TestSessionPersistence:
    """Test session save/restore during chain switching"""

    def test_session_saved_before_switch(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager, sample_activations
    ):
        """Test that session is saved before switching to child chain"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            session = Mock()
            session.variables = {'<TARGET>': '192.168.1.1'}
            session.save = Mock()

            mock_session_cls.return_value = session
            mock_session_cls.exists.return_value = False

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                chain = ChainInteractive(
                                    'test-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                with patch.object(chain, '_read_single_key', return_value='1'):
                                    with patch.object(chain, '_launch_child_chain'):
                                        chain._handle_chain_activations(sample_activations)

                                        # Verify session saved
                                        session.save.assert_called_once()

    def test_session_restored_after_child_returns(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager
    ):
        """Test that parent session is restored after child chain returns"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            parent_session = Mock()
            parent_session.variables = {'<TARGET>': '192.168.1.1'}

            mock_session_cls.return_value = parent_session
            mock_session_cls.exists.return_value = False
            mock_session_cls.load.return_value = parent_session

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                parent = ChainInteractive(
                                    'parent-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                activation = ChainActivation(
                                    chain_id='child-chain',
                                    reason='Test restore',
                                    confidence='high'
                                )

                                # Mock ChainInteractive class
                                with patch('crack.reference.chains.interactive.ChainInteractive') as mock_class:
                                    mock_child = Mock()
                                    mock_child.run = Mock()
                                    mock_class.return_value = mock_child

                                    # Launch child
                                    parent._launch_child_chain(activation)

                                    # Verify parent session loaded
                                    mock_session_cls.load.assert_called_with('parent-chain', '192.168.1.1')


class TestActivationManagerState:
    """Test activation manager state management"""

    def test_activation_manager_state_maintained(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager
    ):
        """Test that activation manager state is correctly maintained"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            parent_session = Mock()
            parent_session.variables = {'<TARGET>': '192.168.1.1'}

            mock_session_cls.return_value = parent_session
            mock_session_cls.exists.return_value = False
            mock_session_cls.load.return_value = parent_session

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                parent = ChainInteractive(
                                    'parent-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                activation = ChainActivation(
                                    chain_id='child-chain',
                                    reason='Test state',
                                    confidence='high'
                                )

                                # Mock ChainInteractive class
                                with patch('crack.reference.chains.interactive.ChainInteractive') as mock_class:
                                    mock_child = Mock()
                                    mock_child.run = Mock()
                                    mock_class.return_value = mock_child

                                    # Initial state
                                    assert activation_manager.get_activation_depth() == 0

                                    # Launch child
                                    parent._launch_child_chain(activation)

                                    # Verify history recorded
                                    assert ('parent-chain', 'child-chain') in activation_manager.activation_history

                                    # Verify stack cleaned up
                                    assert activation_manager.get_activation_depth() == 0


class TestMultipleActivations:
    """Test handling of multiple activations"""

    def test_multiple_activations_displayed_correctly(
        self, mock_chain_registry, mock_command_resolver, mock_command_registry,
        activation_manager, sample_activations, capsys
    ):
        """Test that multiple activations are displayed with correct formatting"""
        with patch('crack.reference.chains.interactive.ChainSession') as mock_session_cls:
            session = Mock()
            session.variables = {'<TARGET>': '192.168.1.1'}

            mock_session_cls.return_value = session
            mock_session_cls.exists.return_value = False

            with patch('crack.reference.chains.interactive.ChainLoader'):
                with patch('crack.reference.chains.interactive.ConfigManager'):
                    with patch('crack.reference.chains.interactive.VariableContext'):
                        with patch('crack.reference.chains.interactive.FindingSelector'):
                            with patch('crack.reference.chains.interactive.StepProcessor'):
                                chain = ChainInteractive(
                                    'test-chain',
                                    target='192.168.1.1',
                                    activation_manager=activation_manager
                                )

                                with patch.object(chain, '_read_single_key', return_value='c'):
                                    chain._handle_chain_activations(sample_activations)

                                    # Capture output
                                    captured = capsys.readouterr()

                                    # Verify all 3 activations shown
                                    assert 'linux-privesc-sudo' in captured.out
                                    assert 'linux-privesc-suid-basic' in captured.out
                                    assert 'linux-capabilities' in captured.out
                                    assert 'HIGH' in captured.out
                                    assert 'MEDIUM' in captured.out
                                    assert 'LOW' in captured.out
