"""
Visual rendering test for TaskListPanel

Demonstrates all panel states for manual verification.
Run this manually to see the actual rendered output.
"""

from unittest.mock import Mock
from crack.track.interactive.panels.task_list_panel import TaskListPanel
from rich.console import Console


def create_mock_profile():
    """Create mock profile with realistic task data"""
    profile = Mock()

    # Create sample tasks
    tasks = []

    # HTTP enumeration tasks
    for port in [80, 443, 8080]:
        for i, task_name in enumerate([
            f"WhatWeb Fingerprinting (Port {port})",
            f"Gobuster Directory Enumeration (Port {port})",
            f"Nikto Vulnerability Scan (Port {port})",
            f"HTTP Methods Enumeration (Port {port})",
        ]):
            task = Mock()
            task.id = f"http-task-{port}-{i}"
            task.name = task_name
            task.status = ['pending', 'in-progress', 'completed'][i % 3]
            task.metadata = {
                'port': port,
                'service': 'http' if port != 443 else 'https',
                'priority': 'HIGH' if i < 2 else 'MEDIUM',
                'tags': ['OSCP:HIGH', 'QUICK_WIN'] if i == 0 else ['WEB', 'RECON'],
                'time_estimate': f"{(i + 1) * 5} min",
                'command': f"whatweb http://192.168.45.100:{port}",
                'description': f"Perform {task_name.split('(')[0].strip()} for web enumeration"
            }
            tasks.append(task)

    # SSH enumeration tasks
    task = Mock()
    task.id = "ssh-enum-22"
    task.name = "SSH Version Detection (Port 22)"
    task.status = 'completed'
    task.metadata = {
        'port': 22,
        'service': 'ssh',
        'priority': 'LOW',
        'tags': ['RECON'],
        'time_estimate': '2 min',
        'command': 'ssh -V',
        'description': 'Detect SSH version'
    }
    tasks.append(task)

    # Multi-stage task example
    task = Mock()
    task.id = "multi-stage-exploit"
    task.name = "Multi-Stage Buffer Overflow Exploit"
    task.status = 'in-progress'
    task.metadata = {
        'port': 9999,
        'service': 'custom',
        'priority': 'HIGH',
        'tags': ['OSCP:HIGH', 'EXPLOIT'],
        'time_estimate': '30 min',
        'command': 'python3 exploit.py',
        'description': 'Execute staged exploit',
        'stages': 3,
        'current_stage': 2
    }
    tasks.append(task)

    profile.task_tree.get_all_tasks.return_value = tasks
    profile.target = "192.168.45.100"

    return profile


def test_render_all_states():
    """Render all TaskListPanel states for visual inspection"""
    console = Console()
    profile = create_mock_profile()

    console.print("\n[bold cyan]===== TEST 1: Default View (First Page) =====[/]\n")
    panel, choices = TaskListPanel.render(profile, page=1, page_size=5)
    console.print(panel)
    console.print(f"\n[dim]Generated {len(choices)} choices[/]")

    console.print("\n\n[bold cyan]===== TEST 2: Filter by Status (Pending) =====[/]\n")
    filter_state = {'status': 'pending', 'port': None, 'service': None, 'priority': None, 'tags': []}
    panel, choices = TaskListPanel.render(profile, filter_state=filter_state, page=1, page_size=5)
    console.print(panel)

    console.print("\n\n[bold cyan]===== TEST 3: Filter by Port (80) =====[/]\n")
    filter_state = {'status': 'all', 'port': 80, 'service': None, 'priority': None, 'tags': []}
    panel, choices = TaskListPanel.render(profile, filter_state=filter_state, page=1, page_size=5)
    console.print(panel)

    console.print("\n\n[bold cyan]===== TEST 4: Filter by Priority (HIGH) =====[/]\n")
    filter_state = {'status': 'all', 'port': None, 'service': None, 'priority': 'HIGH', 'tags': []}
    panel, choices = TaskListPanel.render(profile, filter_state=filter_state, page=1, page_size=5)
    console.print(panel)

    console.print("\n\n[bold cyan]===== TEST 5: Sort by Name =====[/]\n")
    panel, choices = TaskListPanel.render(profile, sort_by='name', page=1, page_size=5)
    console.print(panel)

    console.print("\n\n[bold cyan]===== TEST 6: Empty State (No Tasks) =====[/]\n")
    empty_profile = Mock()
    empty_profile.task_tree.get_all_tasks.return_value = []
    empty_profile.target = "192.168.45.100"
    panel, choices = TaskListPanel.render(empty_profile)
    console.print(panel)

    console.print("\n\n[bold cyan]===== TEST 7: Filtered Empty (No Matches) =====[/]\n")
    filter_state = {'status': 'failed', 'port': None, 'service': None, 'priority': None, 'tags': []}
    panel, choices = TaskListPanel.render(profile, filter_state=filter_state)
    console.print(panel)

    console.print("\n\n[bold cyan]===== TEST 8: Pagination (Page 2) =====[/]\n")
    panel, choices = TaskListPanel.render(profile, page=2, page_size=5)
    console.print(panel)

    console.print("\n\n[bold green]===== ALL VISUAL TESTS COMPLETE =====[/]\n")


if __name__ == "__main__":
    test_render_all_states()
