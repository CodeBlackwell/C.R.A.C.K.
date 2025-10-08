"""
Time Tracker - Track time spent on enumeration tasks

Provides statistics and analysis of task timing for OSCP exam preparation:
- Total time spent
- Time by category/phase
- Longest running tasks
- Currently running tasks
"""

from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta


class TimeStats:
    """Calculate time statistics from task tree"""

    @staticmethod
    def get_total_time(task_tree) -> int:
        """Get total time spent on all completed tasks (seconds)

        Args:
            task_tree: Root TaskNode

        Returns:
            Total seconds across all tasks with duration data
        """
        total = 0

        def sum_node(node):
            nonlocal total
            duration = node.get_duration()
            if duration:
                total += duration
            for child in node.children:
                sum_node(child)

        sum_node(task_tree)
        return total

    @staticmethod
    def get_phase_breakdown(task_tree) -> Dict[str, int]:
        """Get time breakdown by phase/category

        Extracts phase from task ID prefix (e.g., "nmap-80" -> "nmap")

        Args:
            task_tree: Root TaskNode

        Returns:
            Dict mapping phase/category to total seconds
        """
        breakdown = {}

        def categorize_node(node):
            # Determine phase from task ID or tags
            phase = 'other'
            if '-' in node.id:
                phase = node.id.split('-')[0]  # e.g., "nmap-80" -> "nmap"
            elif node.metadata.get('tags'):
                # Try to extract from tags
                for tag in node.metadata['tags']:
                    if tag.startswith('PHASE:'):
                        phase = tag.split(':', 1)[1].lower()
                        break

            duration = node.get_duration()
            if duration:
                if phase not in breakdown:
                    breakdown[phase] = 0
                breakdown[phase] += duration

            for child in node.children:
                categorize_node(child)

        categorize_node(task_tree)
        return breakdown

    @staticmethod
    def get_longest_tasks(task_tree, limit: int = 10) -> List[Tuple[Any, int]]:
        """Get longest running tasks

        Args:
            task_tree: Root TaskNode
            limit: Maximum number of tasks to return

        Returns:
            List of (TaskNode, duration_seconds) tuples sorted by duration descending
        """
        tasks_with_time = []

        def collect_node(node):
            duration = node.get_duration()
            if duration:
                tasks_with_time.append((node, duration))
            for child in node.children:
                collect_node(child)

        collect_node(task_tree)

        # Sort by duration descending
        tasks_with_time.sort(key=lambda x: x[1], reverse=True)
        return tasks_with_time[:limit]

    @staticmethod
    def get_running_tasks(task_tree) -> List[Any]:
        """Get tasks that are currently running (in-progress with start_time)

        Args:
            task_tree: Root TaskNode

        Returns:
            List of TaskNode objects that are in-progress
        """
        running = []

        def find_running(node):
            if node.status == 'in-progress' and 'start_time' in node.metadata:
                running.append(node)
            for child in node.children:
                find_running(child)

        find_running(task_tree)
        return running

    @staticmethod
    def format_duration(seconds: int) -> str:
        """Format seconds as HH:MM:SS

        Args:
            seconds: Duration in seconds

        Returns:
            Formatted string "HH:MM:SS"
        """
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    @staticmethod
    def get_average_task_time(task_tree) -> Optional[int]:
        """Get average task completion time

        Args:
            task_tree: Root TaskNode

        Returns:
            Average duration in seconds, or None if no timed tasks
        """
        total_time = 0
        task_count = 0

        def collect_node(node):
            nonlocal total_time, task_count
            duration = node.get_duration()
            if duration:
                total_time += duration
                task_count += 1
            for child in node.children:
                collect_node(child)

        collect_node(task_tree)

        if task_count == 0:
            return None
        return total_time // task_count

    @staticmethod
    def get_time_by_status(task_tree) -> Dict[str, int]:
        """Get time breakdown by task status

        Args:
            task_tree: Root TaskNode

        Returns:
            Dict mapping status to total seconds
        """
        breakdown = {
            'completed': 0,
            'in-progress': 0,
            'pending': 0,
            'skipped': 0
        }

        def categorize_node(node):
            duration = node.get_duration()
            if duration and node.status in breakdown:
                breakdown[node.status] += duration
            for child in node.children:
                categorize_node(child)

        categorize_node(task_tree)
        return breakdown

    @staticmethod
    def estimate_remaining_time(task_tree) -> Optional[int]:
        """Estimate time remaining based on average task time

        Uses average completed task time to estimate pending tasks

        Args:
            task_tree: Root TaskNode

        Returns:
            Estimated seconds remaining, or None if no data
        """
        avg_time = TimeStats.get_average_task_time(task_tree)
        if avg_time is None:
            return None

        # Count pending tasks
        pending_count = 0

        def count_pending(node):
            nonlocal pending_count
            if node.status == 'pending':
                pending_count += 1
            for child in node.children:
                count_pending(child)

        count_pending(task_tree)

        return avg_time * pending_count
