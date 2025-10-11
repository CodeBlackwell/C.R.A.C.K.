"""
Tests for Methodology Engine

Validates proactive task generation based on OSCP methodology phases.
"""

import pytest
from crack.track.methodology.methodology_engine import MethodologyEngine
from crack.track.methodology.phases import Phase, PhaseTransition
from crack.track.core.state import TargetProfile


@pytest.fixture
def sample_profile():
    """Create a sample profile with services"""
    profile = TargetProfile('192.168.45.100')
    # Add some services
    profile.add_port(22, state='open', service='ssh', version='OpenSSH 8.2')
    profile.add_port(80, state='open', service='apache', version='2.4.49')
    profile.add_port(139, state='open', service='smb', version='Samba 4.10')
    profile.add_port(8080, state='open', service='tomcat', version='9.0.30')
    profile.add_port(21, state='open', service='ftp', version='vsftpd 3.0.3')
    return profile


@pytest.fixture
def methodology_engine(sample_profile):
    """Create a methodology engine with sample profile"""
    config = {'enabled': True}
    return MethodologyEngine('192.168.45.100', sample_profile, config)


def test_initialization_at_reconnaissance_phase(methodology_engine):
    """
    Test 1: Initialization at RECONNAISSANCE phase
    
    GIVEN: New methodology engine
    WHEN: Engine is initialized
    THEN: Current phase is RECONNAISSANCE
    """
    assert methodology_engine.current_phase == Phase.RECONNAISSANCE
    assert methodology_engine.phase_history == [Phase.RECONNAISSANCE]
    assert methodology_engine.target == '192.168.45.100'


def test_get_phase_suggestions_returns_tasks(methodology_engine):
    """
    Test 2: get_phase_suggestions() returns tasks
    
    GIVEN: Methodology engine with services detected
    WHEN: get_phase_suggestions() is called
    THEN: Returns list of task suggestions
    """
    suggestions = methodology_engine.get_phase_suggestions()
    
    assert isinstance(suggestions, list)
    assert len(suggestions) > 0
    
    # All suggestions should have required fields
    for task in suggestions:
        assert 'id' in task
        assert 'name' in task
        assert 'type' in task
        assert 'status' in task
        assert 'metadata' in task
        assert task['phase_alignment'] is True
        assert task['intelligence_source'] == 'methodology'


def test_quick_win_detection_tomcat(methodology_engine):
    """
    Test 3: Quick-win detection for Tomcat
    
    GIVEN: Profile with Tomcat service
    WHEN: Quick-win detection runs
    THEN: Suggests Tomcat default credentials test
    """
    suggestions = methodology_engine.get_phase_suggestions()
    
    # Find Tomcat quick-win
    tomcat_tasks = [t for t in suggestions if 'tomcat' in t['name'].lower()]
    
    assert len(tomcat_tasks) > 0
    tomcat_task = tomcat_tasks[0]
    
    assert 'metadata' in tomcat_task
    assert tomcat_task['metadata'].get('category') == 'quick_win'
    assert tomcat_task['metadata'].get('matches_oscp_pattern') is True
    assert tomcat_task['metadata'].get('oscp_likelihood') == 0.8


def test_quick_win_detection_smb_anonymous(methodology_engine):
    """
    Test 4: Quick-win detection for SMB anonymous access
    
    GIVEN: Profile with SMB service
    WHEN: Quick-win detection runs
    THEN: Suggests SMB anonymous access test
    """
    suggestions = methodology_engine.get_phase_suggestions()
    
    # Find SMB quick-win
    smb_tasks = [t for t in suggestions if 'smb' in t['name'].lower() and 'anonymous' in t['name'].lower()]
    
    assert len(smb_tasks) > 0
    smb_task = smb_tasks[0]
    
    assert 'metadata' in smb_task
    assert smb_task['metadata'].get('category') == 'quick_win'
    assert 'smbclient' in smb_task['metadata'].get('command', '')


def test_phase_transition_success_recon_to_service_enum(methodology_engine):
    """
    Test 5: Phase transition success (recon -> service enum)
    
    GIVEN: Engine at RECONNAISSANCE phase with ports discovered
    WHEN: Transition to SERVICE_ENUMERATION is attempted
    THEN: Transition succeeds
    """
    # Ensure ports are discovered (already done in fixture)
    assert len(methodology_engine.profile.ports) > 0
    
    # Attempt transition
    success = methodology_engine.transition_to(Phase.SERVICE_ENUMERATION)
    
    assert success is True
    assert methodology_engine.current_phase == Phase.SERVICE_ENUMERATION
    assert Phase.SERVICE_ENUMERATION in methodology_engine.phase_history


def test_phase_transition_blocked_missing_requirements():
    """
    Test 6: Phase transition blocked (missing requirements)
    
    GIVEN: Engine at RECONNAISSANCE with no ports discovered
    WHEN: Transition to SERVICE_ENUMERATION is attempted
    THEN: Transition fails
    """
    # Create profile with no ports
    empty_profile = TargetProfile('192.168.45.200')
    config = {'enabled': True}
    engine = MethodologyEngine('192.168.45.200', empty_profile, config)
    
    # Attempt transition (should fail - no ports)
    success = engine.transition_to(Phase.SERVICE_ENUMERATION)
    
    assert success is False
    assert engine.current_phase == Phase.RECONNAISSANCE


def test_backward_transition_allowed(methodology_engine):
    """
    Test 7: Backward transition allowed
    
    GIVEN: Engine at SERVICE_ENUMERATION phase
    WHEN: Transition back to RECONNAISSANCE is attempted
    THEN: Transition succeeds
    """
    # Move to service enumeration first
    methodology_engine.transition_to(Phase.SERVICE_ENUMERATION)
    assert methodology_engine.current_phase == Phase.SERVICE_ENUMERATION
    
    # Attempt backward transition
    success = methodology_engine.transition_to(Phase.RECONNAISSANCE)
    
    assert success is True
    assert methodology_engine.current_phase == Phase.RECONNAISSANCE


def test_phase_specific_tasks_for_reconnaissance(methodology_engine):
    """
    Test 8: Phase-specific tasks for reconnaissance
    
    GIVEN: Engine at RECONNAISSANCE phase
    WHEN: Phase-specific tasks are requested
    THEN: Returns reconnaissance tasks like full port scan
    """
    assert methodology_engine.current_phase == Phase.RECONNAISSANCE
    
    suggestions = methodology_engine.get_phase_suggestions()
    
    # Find reconnaissance-specific task
    recon_tasks = [t for t in suggestions if 'nmap' in t.get('metadata', {}).get('command', '')]
    
    assert len(recon_tasks) > 0


def test_all_tasks_tagged_with_phase_alignment(methodology_engine):
    """
    Test 9: All tasks tagged with phase_alignment
    
    GIVEN: Methodology engine generating suggestions
    WHEN: get_phase_suggestions() is called
    THEN: All tasks have phase_alignment=True
    """
    suggestions = methodology_engine.get_phase_suggestions()
    
    for task in suggestions:
        assert task.get('phase_alignment') is True
        assert 'current_phase' in task
        assert task['intelligence_source'] == 'methodology'


def test_phase_history_tracking(methodology_engine):
    """
    Test 10: Phase history tracking
    
    GIVEN: Engine transitioning through phases
    WHEN: Multiple transitions occur
    THEN: Phase history is tracked correctly
    """
    initial_history = methodology_engine.phase_history.copy()
    assert initial_history == [Phase.RECONNAISSANCE]
    
    # Transition to service enumeration
    methodology_engine.transition_to(Phase.SERVICE_ENUMERATION)
    
    assert len(methodology_engine.phase_history) == 2
    assert methodology_engine.phase_history == [Phase.RECONNAISSANCE, Phase.SERVICE_ENUMERATION]
    
    # Add findings to allow further transitions
    methodology_engine.profile.add_finding('vulnerability', 'CVE-2021-41773', source='nmap')
    
    # Transition to vulnerability discovery
    methodology_engine.transition_to(Phase.VULNERABILITY_DISCOVERY)
    
    assert len(methodology_engine.phase_history) == 3
    assert methodology_engine.phase_history[-1] == Phase.VULNERABILITY_DISCOVERY
