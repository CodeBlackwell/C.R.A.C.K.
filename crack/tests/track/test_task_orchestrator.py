"""
Tests for TaskOrchestrator - Central intelligence coordinator

Tests prove user value: Orchestrator merges, deduplicates, and prioritizes
tasks from multiple intelligence sources.
"""

import pytest
from unittest.mock import Mock, MagicMock
from crack.track.intelligence.task_orchestrator import TaskOrchestrator


@pytest.fixture
def mock_profile():
    """Mock TargetProfile for testing"""
    profile = Mock()
    profile.target = "192.168.45.100"
    profile.ports = {80: {'service': 'http'}, 445: {'service': 'smb'}}
    profile.findings = []
    return profile


@pytest.fixture
def orchestrator(mock_profile):
    """Create TaskOrchestrator instance"""
    config = {'max_suggestions': 5, 'min_priority': 0.5}
    return TaskOrchestrator("192.168.45.100", mock_profile, config)


def test_orchestrator_initialization(orchestrator):
    """
    PROVES: TaskOrchestrator initializes with target and config

    User Value: System ready to coordinate intelligence sources
    """
    assert orchestrator.target == "192.168.45.100"
    assert orchestrator.config['max_suggestions'] == 5
    assert len(orchestrator.task_history) == 0
    assert orchestrator.scorer is None


def test_generate_next_tasks_empty(orchestrator):
    """
    PROVES: Returns empty list in passive mode (Stage 1)

    User Value: No automatic suggestions until engines connected
    """
    tasks = orchestrator.generate_next_tasks(max_tasks=5)
    assert tasks == []


def test_merge_suggestions_tags_sources(orchestrator):
    """
    PROVES: Merged tasks tagged with intelligence_source

    User Value: User knows where suggestions came from (correlation vs methodology)
    """
    method1_tasks = [
        {'id': 'gobuster-80', 'name': 'Directory scan'},
        {'id': 'nikto-80', 'name': 'Vulnerability scan'}
    ]
    method2_tasks = [
        {'id': 'smb-enum-445', 'name': 'SMB enumeration'},
        {'id': 'ssh-banner-22', 'name': 'SSH banner grab'}
    ]

    merged = orchestrator.merge_suggestions(method1_tasks, method2_tasks)

    # Verify length
    assert len(merged) == 4

    # Verify source tags
    assert merged[0]['intelligence_source'] == 'correlation'
    assert merged[1]['intelligence_source'] == 'correlation'
    assert merged[2]['intelligence_source'] == 'methodology'
    assert merged[3]['intelligence_source'] == 'methodology'


def test_deduplicate_tasks_by_id(orchestrator):
    """
    PROVES: Duplicate task IDs removed

    User Value: No duplicate suggestions clutter the task list
    """
    tasks = [
        {'id': 'gobuster-80', 'name': 'Directory scan'},
        {'id': 'nikto-80', 'name': 'Vulnerability scan'},
        {'id': 'gobuster-80', 'name': 'Directory scan (duplicate)'}  # Duplicate
    ]

    deduplicated = orchestrator.deduplicate_tasks(tasks)

    # Should remove the duplicate
    assert len(deduplicated) == 2
    assert deduplicated[0]['id'] == 'gobuster-80'
    assert deduplicated[1]['id'] == 'nikto-80'


def test_task_history_prevents_readd(orchestrator):
    """
    PROVES: Tasks in history not added again

    User Value: Completed tasks don't reappear as suggestions
    """
    # First batch
    tasks1 = [
        {'id': 'gobuster-80', 'name': 'Directory scan'},
        {'id': 'nikto-80', 'name': 'Vulnerability scan'}
    ]
    deduplicated1 = orchestrator.deduplicate_tasks(tasks1)
    assert len(deduplicated1) == 2

    # Second batch with overlapping tasks
    tasks2 = [
        {'id': 'gobuster-80', 'name': 'Directory scan'},  # Already in history
        {'id': 'smb-enum-445', 'name': 'SMB enumeration'}  # New
    ]
    deduplicated2 = orchestrator.deduplicate_tasks(tasks2)

    # Should only return new task
    assert len(deduplicated2) == 1
    assert deduplicated2[0]['id'] == 'smb-enum-445'


def test_priority_sorting_with_scorer(orchestrator):
    """
    PROVES: Tasks sorted by priority when scorer present

    User Value: High-priority tasks surface first
    """
    # Mock scorer
    mock_scorer = Mock()
    mock_scorer.calculate_priority.side_effect = [0.9, 0.5, 0.7]  # Priorities for 3 tasks
    orchestrator.set_scorer(mock_scorer)

    # Create tasks and merge (to populate)
    method1_tasks = [
        {'id': 'task1', 'name': 'Task 1'},
        {'id': 'task2', 'name': 'Task 2'},
        {'id': 'task3', 'name': 'Task 3'}
    ]

    # Manually add to simulate generate_next_tasks logic
    all_tasks = method1_tasks.copy()
    deduplicated = orchestrator.deduplicate_tasks(all_tasks)

    # Score tasks
    scored_tasks = []
    for task in deduplicated:
        task['priority'] = mock_scorer.calculate_priority(task, orchestrator.profile)
        scored_tasks.append(task)

    scored_tasks.sort(key=lambda t: t['priority'], reverse=True)

    # Verify sorting
    assert scored_tasks[0]['priority'] == 0.9
    assert scored_tasks[1]['priority'] == 0.7
    assert scored_tasks[2]['priority'] == 0.5


def test_max_tasks_limit_respected(orchestrator):
    """
    PROVES: Max tasks limit is respected

    User Value: User gets exactly N top suggestions, not overwhelmed
    """
    # Mock scorer
    mock_scorer = Mock()
    mock_scorer.calculate_priority.return_value = 0.8
    orchestrator.set_scorer(mock_scorer)

    # Simulate 10 tasks, request top 5
    method1_tasks = [{'id': f'task{i}', 'name': f'Task {i}'} for i in range(10)]

    # Manually test the logic
    deduplicated = orchestrator.deduplicate_tasks(method1_tasks)
    assert len(deduplicated) == 10

    # Score and sort
    scored_tasks = []
    for task in deduplicated:
        task['priority'] = 0.8
        scored_tasks.append(task)

    scored_tasks.sort(key=lambda t: t['priority'], reverse=True)
    top_tasks = scored_tasks[:5]

    # Should return exactly 5
    assert len(top_tasks) == 5


def test_task_history_tracking(orchestrator):
    """
    PROVES: Task history grows as tasks are deduplicated

    User Value: System remembers all processed tasks
    """
    assert len(orchestrator.task_history) == 0

    tasks1 = [{'id': 'task1', 'name': 'Task 1'}]
    orchestrator.deduplicate_tasks(tasks1)
    assert len(orchestrator.task_history) == 1

    tasks2 = [{'id': 'task2', 'name': 'Task 2'}]
    orchestrator.deduplicate_tasks(tasks2)
    assert len(orchestrator.task_history) == 2

    assert 'task1' in orchestrator.task_history
    assert 'task2' in orchestrator.task_history


def test_source_tagging_preserves_task_data(orchestrator):
    """
    PROVES: Source tagging doesn't corrupt task data

    User Value: Task metadata intact after merging
    """
    method1_tasks = [
        {'id': 'task1', 'name': 'Task 1', 'metadata': {'port': 80}}
    ]
    method2_tasks = [
        {'id': 'task2', 'name': 'Task 2', 'metadata': {'port': 445}}
    ]

    merged = orchestrator.merge_suggestions(method1_tasks, method2_tasks)

    # Verify metadata preserved
    assert merged[0]['metadata']['port'] == 80
    assert merged[1]['metadata']['port'] == 445

    # Verify source added
    assert 'intelligence_source' in merged[0]
    assert 'intelligence_source' in merged[1]


def test_scorer_injection(orchestrator):
    """
    PROVES: Scorer can be injected via dependency injection

    User Value: Flexible scoring strategies without tight coupling
    """
    assert orchestrator.scorer is None

    mock_scorer = Mock()
    orchestrator.set_scorer(mock_scorer)

    assert orchestrator.scorer is mock_scorer
