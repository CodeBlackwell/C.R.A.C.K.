#!/usr/bin/env python3
"""
Analyze Windows Core plugin metadata gaps
"""
import sys
sys.path.insert(0, '/home/kali/OSCP/crack')

from track.services.windows_core import WindowsCorePlugin

def analyze_metadata():
    plugin = WindowsCorePlugin()
    tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

    # Collect all leaf tasks
    all_tasks = []
    def collect_tasks(node):
        if node['type'] in ['command', 'manual']:
            all_tasks.append(node)
        if 'children' in node:
            for child in node['children']:
                collect_tasks(child)

    collect_tasks(tree)

    # Analyze metadata gaps
    missing_next_steps = []
    missing_success = []
    missing_failure = []
    missing_notes = []

    for task in all_tasks:
        metadata = task.get('metadata', {})
        task_id = task['id']

        if 'next_steps' not in metadata:
            missing_next_steps.append(task_id)
        if 'success_indicators' not in metadata:
            missing_success.append(task_id)
        if 'failure_indicators' not in metadata:
            missing_failure.append(task_id)
        if 'notes' not in metadata:
            missing_notes.append(task_id)

    print(f"Total tasks: {len(all_tasks)}")
    print(f"\nMissing next_steps: {len(missing_next_steps)}/{len(all_tasks)} (need 66/82 = 80%)")
    print(f"Currently have: {len(all_tasks) - len(missing_next_steps)}")
    print(f"Need to add: {max(0, 66 - (len(all_tasks) - len(missing_next_steps)))}")

    print(f"\nMissing success_indicators: {len(missing_success)}/{len(all_tasks)} (need 74/82 = 90%)")
    print(f"Currently have: {len(all_tasks) - len(missing_success)}")
    print(f"Need to add: {max(0, 74 - (len(all_tasks) - len(missing_success)))}")

    print(f"\nMissing failure_indicators: {len(missing_failure)}/{len(all_tasks)} (need 74/82 = 90%)")
    print(f"Currently have: {len(all_tasks) - len(missing_failure)}")
    print(f"Need to add: {max(0, 74 - (len(all_tasks) - len(missing_failure)))}")

    print(f"\nMissing notes: {len(missing_notes)}/{len(all_tasks)} (need 66/82 = 80%)")
    print(f"Currently have: {len(all_tasks) - len(missing_notes)}")
    print(f"Need to add: {max(0, 66 - (len(all_tasks) - len(missing_notes)))}")

    # Find tasks missing multiple fields (priority targets)
    priority_tasks = []
    for task in all_tasks:
        metadata = task.get('metadata', {})
        missing_count = 0
        missing_fields = []

        if 'next_steps' not in metadata:
            missing_count += 1
            missing_fields.append('next_steps')
        if 'success_indicators' not in metadata:
            missing_count += 1
            missing_fields.append('success_indicators')
        if 'failure_indicators' not in metadata:
            missing_count += 1
            missing_fields.append('failure_indicators')
        if 'notes' not in metadata:
            missing_count += 1
            missing_fields.append('notes')

        if missing_count >= 2:
            priority_tasks.append({
                'id': task['id'],
                'name': task['name'],
                'missing_count': missing_count,
                'missing_fields': missing_fields
            })

    print(f"\n\nPRIORITY TASKS (missing 2+ fields): {len(priority_tasks)}")
    priority_tasks.sort(key=lambda x: x['missing_count'], reverse=True)

    for i, task in enumerate(priority_tasks[:30], 1):
        print(f"{i}. {task['id']}")
        print(f"   Name: {task['name']}")
        print(f"   Missing: {', '.join(task['missing_fields'])}")
        print()

if __name__ == '__main__':
    analyze_metadata()
