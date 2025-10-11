"""
Tests for Chain Executor

Validates attack chain orchestration, progress tracking, and state persistence.
"""

import pytest
from crack.track.methodology.chain_executor import (
    ChainExecutor,
    ChainProgress,
    ChainStep,
    AttackChain,
    ChainRegistry
)
from crack.track.core.state import TargetProfile
from crack.track.core.events import EventBus


@pytest.fixture
def sample_steps():
    """Create sample chain steps"""
    return [
        ChainStep(
            'step1',
            'Port Scan',
            'nmap -sV target',
            success_indicators=[r'open', r'\d+ open ports'],
            failure_indicators=[r'failed', r'error']
        ),
        ChainStep(
            'step2',
            'Service Enumeration',
            'gobuster dir -u http://target',
            success_indicators=[r'Status: 200', r'Found'],
            failure_indicators=[r'Error', r'Connection refused']
        ),
        ChainStep(
            'step3',
            'Exploit',
            'exploit.py target',
            success_indicators=[r'shell', r'success'],
            failure_indicators=[r'failed', r'denied']
        )
    ]


@pytest.fixture
def sample_chain(sample_steps):
    """Create sample attack chain"""
    return AttackChain('web-rce', 'Web RCE Chain', sample_steps)


@pytest.fixture
def registry(sample_chain):
    """Create chain registry with sample chain"""
    reg = ChainRegistry()
    reg.register(sample_chain)
    return reg


@pytest.fixture
def profile():
    """Create target profile"""
    return TargetProfile('192.168.45.100')


@pytest.fixture
def executor(profile, registry):
    """Create chain executor"""
    return ChainExecutor('192.168.45.100', profile, registry)


@pytest.fixture(autouse=True)
def clear_events():
    """Clear event bus before each test"""
    EventBus.clear()
    yield
    EventBus.clear()


def test_chain_progress_initialization(sample_chain):
    """
    Test 1: ChainProgress creation and initialization

    GIVEN: Attack chain and target
    WHEN: ChainProgress is created
    THEN: All fields initialized correctly
    """
    progress = ChainProgress(sample_chain, '192.168.45.100')

    assert progress.chain == sample_chain
    assert progress.target == '192.168.45.100'
    assert progress.completed_steps == []
    assert progress.failed_steps == []
    assert progress.started_at is None
    assert progress.completed_at is None


def test_chain_progress_start_marks_time(sample_chain):
    """
    Test 2: ChainProgress.start() marks start time

    GIVEN: Unstarted ChainProgress
    WHEN: start() is called
    THEN: started_at is set to current timestamp
    """
    progress = ChainProgress(sample_chain, '192.168.45.100')

    assert progress.started_at is None

    progress.start()

    assert progress.started_at is not None
    assert isinstance(progress.started_at, str)
    assert 'T' in progress.started_at  # ISO format

    # Calling start again should not update timestamp
    original_start = progress.started_at
    progress.start()
    assert progress.started_at == original_start


def test_chain_progress_mark_step_complete(sample_chain):
    """
    Test 3: ChainProgress.mark_step_complete() updates list

    GIVEN: ChainProgress with pending steps
    WHEN: mark_step_complete() is called
    THEN: Step added to completed_steps list
    """
    progress = ChainProgress(sample_chain, '192.168.45.100')
    progress.start()

    assert len(progress.completed_steps) == 0

    progress.mark_step_complete('step1')

    assert len(progress.completed_steps) == 1
    assert 'step1' in progress.completed_steps

    # Marking again should not duplicate
    progress.mark_step_complete('step1')
    assert len(progress.completed_steps) == 1


def test_chain_progress_mark_step_failed(sample_chain):
    """
    Test 4: ChainProgress.mark_step_failed() tracks failures

    GIVEN: ChainProgress with pending steps
    WHEN: mark_step_failed() is called
    THEN: Step added to failed_steps list
    """
    progress = ChainProgress(sample_chain, '192.168.45.100')
    progress.start()

    assert len(progress.failed_steps) == 0

    progress.mark_step_failed('step2')

    assert len(progress.failed_steps) == 1
    assert 'step2' in progress.failed_steps

    # Marking again should not duplicate
    progress.mark_step_failed('step2')
    assert len(progress.failed_steps) == 1


def test_chain_progress_get_progress_calculates_percentage(sample_chain):
    """
    Test 5: ChainProgress.get_progress() calculates percentage

    GIVEN: ChainProgress with 3 steps
    WHEN: Steps are completed incrementally
    THEN: Progress percentage updates correctly
    """
    progress = ChainProgress(sample_chain, '192.168.45.100')
    progress.start()

    # No steps completed
    assert progress.get_progress() == 0.0

    # 1 of 3 steps completed
    progress.mark_step_complete('step1')
    assert progress.get_progress() == pytest.approx(0.333, rel=0.01)

    # 2 of 3 steps completed
    progress.mark_step_complete('step2')
    assert progress.get_progress() == pytest.approx(0.666, rel=0.01)

    # All steps completed
    progress.mark_step_complete('step3')
    assert progress.get_progress() == 1.0


def test_executor_initialization_loads_persisted_progress(profile, registry, sample_chain):
    """
    Test 6: ChainExecutor initialization loads persisted progress

    GIVEN: Profile with persisted chain progress
    WHEN: ChainExecutor is initialized
    THEN: Progress is restored from profile
    """
    # Persist chain progress to profile
    profile.metadata['attack_chains'] = {
        'web-rce': {
            'chain_id': 'web-rce',
            'target': '192.168.45.100',
            'completed_steps': ['step1', 'step2'],
            'failed_steps': [],
            'started_at': '2025-01-01T10:00:00',
            'completed_at': None,
            'progress': 0.666
        }
    }
    profile.save()

    # Create executor (should load progress)
    executor = ChainExecutor('192.168.45.100', profile, registry)

    assert 'web-rce' in executor.active_chains
    progress = executor.active_chains['web-rce']
    assert len(progress.completed_steps) == 2
    assert 'step1' in progress.completed_steps
    assert 'step2' in progress.completed_steps


def test_executor_activate_chain_creates_progress(executor, sample_chain):
    """
    Test 7: ChainExecutor.activate_chain() creates ChainProgress

    GIVEN: ChainExecutor with no active chains
    WHEN: activate_chain() is called
    THEN: ChainProgress is created and persisted
    """
    assert len(executor.active_chains) == 0

    result = executor.activate_chain('web-rce')

    assert result is True
    assert 'web-rce' in executor.active_chains
    progress = executor.active_chains['web-rce']
    assert progress.chain.id == 'web-rce'
    assert progress.started_at is not None

    # Check persistence
    assert 'attack_chains' in executor.profile.metadata
    assert 'web-rce' in executor.profile.metadata['attack_chains']


def test_executor_activate_chain_prevents_duplicates(executor):
    """
    Test 8: ChainExecutor.activate_chain() prevents duplicates

    GIVEN: ChainExecutor with active chain
    WHEN: Same chain is activated again
    THEN: Returns False, no duplicate created
    """
    # Activate chain
    result1 = executor.activate_chain('web-rce')
    assert result1 is True

    # Try to activate again
    result2 = executor.activate_chain('web-rce')
    assert result2 is False

    # Should still only have one active chain
    assert len(executor.active_chains) == 1


def test_executor_check_step_completion_validates_success(executor, sample_steps):
    """
    Test 9: ChainExecutor.check_step_completion() validates success indicators

    GIVEN: ChainStep with success indicators
    WHEN: Output matches success indicator
    THEN: Returns True
    """
    step = sample_steps[0]  # Port scan step
    output = """
    Starting Nmap scan...
    22/tcp open  ssh
    80/tcp open  http
    443/tcp open https
    """

    result = executor.check_step_completion(step, output)

    assert result is True


def test_executor_check_step_completion_validates_failure(executor, sample_steps):
    """
    Test 10: ChainExecutor.check_step_completion() validates failure indicators

    GIVEN: ChainStep with failure indicators
    WHEN: Output matches failure indicator
    THEN: Returns False
    """
    step = sample_steps[0]  # Port scan step
    output = """
    Starting Nmap scan...
    Error: Connection failed
    Unable to reach target
    """

    result = executor.check_step_completion(step, output)

    assert result is False


def test_executor_update_progress_persists_to_profile(executor):
    """
    Test 11: ChainExecutor.update_progress() persists to profile

    GIVEN: Active chain with step execution
    WHEN: update_progress() is called with success
    THEN: Progress persisted to profile
    """
    # Activate chain
    executor.activate_chain('web-rce')

    # Update progress
    output = "22/tcp open ssh"
    executor.update_progress('web-rce', 'step1', output, success=True)

    # Check persistence
    chain_data = executor.profile.metadata['attack_chains']
    assert 'web-rce' in chain_data
    assert 'step1' in chain_data['web-rce']['completed_steps']

    # Verify profile was saved
    reloaded_profile = TargetProfile.load('192.168.45.100')
    assert 'attack_chains' in reloaded_profile.metadata
    assert 'web-rce' in reloaded_profile.metadata['attack_chains']


def test_executor_get_next_steps_returns_prioritized_suggestions(executor):
    """
    Test 12: ChainExecutor.get_next_steps() returns prioritized suggestions

    GIVEN: Multiple active chains with different progress
    WHEN: get_next_steps() is called
    THEN: Returns next steps prioritized by progress
    """
    # Create additional chain
    chain2 = AttackChain('smb-enum', 'SMB Enumeration', [
        ChainStep('smb1', 'List shares', 'smbclient -L target'),
        ChainStep('smb2', 'Mount share', 'mount target')
    ])
    executor.registry.register(chain2)

    # Activate both chains
    executor.activate_chain('web-rce')
    executor.activate_chain('smb-enum')

    # Complete one step in web-rce (higher progress)
    executor.update_progress('web-rce', 'step1', 'open', success=True)

    # Get next steps
    suggestions = executor.get_next_steps(max_chains=2)

    assert len(suggestions) > 0

    # First suggestion should be from web-rce (higher progress)
    first_suggestion = suggestions[0]
    assert first_suggestion['chain_id'] == 'web-rce'
    assert first_suggestion['step'].id == 'step2'
    assert 'progress' in first_suggestion
    assert 'step_index' in first_suggestion


def test_executor_emits_events_on_activation():
    """
    Test 13: ChainExecutor emits events on chain activation

    GIVEN: ChainExecutor with registry
    WHEN: Chain is activated
    THEN: chain_activated event is emitted
    """
    # Setup event listener
    events_received = []

    def handler(data):
        events_received.append(data)

    EventBus.on('chain_activated', handler)

    # Create executor and activate chain
    profile = TargetProfile('192.168.45.100')
    chain = AttackChain('test-chain', 'Test Chain', [
        ChainStep('step1', 'Test', 'echo test')
    ])
    registry = ChainRegistry()
    registry.register(chain)

    executor = ChainExecutor('192.168.45.100', profile, registry)
    executor.activate_chain('test-chain')

    # Verify event was emitted
    assert len(events_received) == 1
    assert events_received[0]['chain_id'] == 'test-chain'
    assert events_received[0]['target'] == '192.168.45.100'
    assert events_received[0]['steps_total'] == 1


def test_executor_emits_events_on_step_completion():
    """
    Test 14: ChainExecutor emits events on step completion

    GIVEN: Active chain
    WHEN: Step is completed
    THEN: chain_step_completed event is emitted
    """
    # Setup event listener
    events_received = []

    def handler(data):
        events_received.append(data)

    EventBus.on('chain_step_completed', handler)

    # Create executor and activate chain
    profile = TargetProfile('192.168.45.100')
    chain = AttackChain('test-chain', 'Test Chain', [
        ChainStep('step1', 'Test', 'echo test')
    ])
    registry = ChainRegistry()
    registry.register(chain)

    executor = ChainExecutor('192.168.45.100', profile, registry)
    executor.activate_chain('test-chain')

    # Update progress
    executor.update_progress('test-chain', 'step1', 'success', success=True)

    # Verify event was emitted
    assert len(events_received) == 1
    assert events_received[0]['chain_id'] == 'test-chain'
    assert events_received[0]['step_id'] == 'step1'
    assert events_received[0]['success'] is True
    assert events_received[0]['complete'] is True


def test_chain_progress_marks_completion_time(sample_chain):
    """
    Test 15: ChainProgress marks completed_at when chain finishes

    GIVEN: ChainProgress with all steps completed
    WHEN: Final step is marked complete
    THEN: completed_at timestamp is set
    """
    progress = ChainProgress(sample_chain, '192.168.45.100')
    progress.start()

    assert progress.completed_at is None

    # Complete all steps
    progress.mark_step_complete('step1')
    progress.mark_step_complete('step2')
    assert progress.completed_at is None  # Not complete yet

    progress.mark_step_complete('step3')
    assert progress.completed_at is not None  # Now complete
    assert isinstance(progress.completed_at, str)
