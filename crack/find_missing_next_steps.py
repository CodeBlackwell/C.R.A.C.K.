#!/usr/bin/env python3
"""
Find tasks missing next_steps field
"""
import sys
sys.path.insert(0, '/home/kali/OSCP/crack')

from track.services.windows_core import WindowsCorePlugin

def find_missing():
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

    # Find tasks missing next_steps
    missing_next_steps = []
    for task in all_tasks:
        metadata = task.get('metadata', {})
        if 'next_steps' not in metadata:
            missing_next_steps.append({
                'id': task['id'],
                'name': task['name'],
                'type': task['type']
            })

    print(f"Total tasks: {len(all_tasks)}")
    print(f"Tasks with next_steps: {len(all_tasks) - len(missing_next_steps)}")
    print(f"Tasks missing next_steps: {len(missing_next_steps)}")
    print(f"Need: 36 (80% of 45)")
    print(f"Need to add: {max(0, 36 - (len(all_tasks) - len(missing_next_steps)))}")
    print(f"\nTasks missing next_steps:\n")

    for i, task in enumerate(missing_next_steps, 1):
        print(f"{i}. {task['id']}")
        print(f"   Name: {task['name']}")
        print(f"   Type: {task['type']}")
        print()

if __name__ == '__main__':
    find_missing()
