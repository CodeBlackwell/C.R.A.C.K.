"""
Recommendation engine for next-step suggestions

Provides context-aware recommendations based on:
- Current phase
- Completed tasks
- Pending tasks
- Discovered information
- Task priorities
"""

from typing import Dict, Any, List, Optional
from ..core.task_tree import TaskNode


class RecommendationEngine:
    """Generate context-aware enumeration recommendations"""

    @classmethod
    def recommend(cls, profile) -> Dict[str, Any]:
        """Alias for get_recommendations() for backwards compatibility"""
        return cls.get_recommendations(profile)

    @classmethod
    def get_recommendations(cls, profile) -> Dict[str, Any]:
        """Get recommendations for target

        Args:
            profile: TargetProfile instance

        Returns:
            Dictionary with recommendations:
            {
                'next': TaskNode or None,
                'quick_wins': [TaskNode, ...],
                'parallel': [TaskNode, ...],
                'blocked': [TaskNode, ...],
                'phase_status': str
            }
        """
        # Get all pending tasks
        all_pending = profile.task_tree.get_all_pending()

        # Categorize tasks
        quick_wins = cls._get_quick_wins(all_pending)
        parallel_tasks = cls._get_parallel_tasks(all_pending)
        ready_tasks = cls._get_ready_tasks(all_pending, profile)
        blocked_tasks = cls._get_blocked_tasks(all_pending, profile)

        # Get next recommended task
        next_task = cls._select_next_task(quick_wins, ready_tasks, parallel_tasks)

        # Get phase status
        phase_status = cls._get_phase_status(profile)

        return {
            'next': next_task,
            'quick_wins': quick_wins,
            'parallel': parallel_tasks,
            'ready': ready_tasks,
            'blocked': blocked_tasks,
            'phase_status': phase_status,
            'commands': cls._generate_commands(next_task, parallel_tasks[:3])  # Top 3 parallel
        }

    @classmethod
    def _get_quick_wins(cls, tasks: List[TaskNode]) -> List[TaskNode]:
        """Get tasks tagged as quick wins

        Args:
            tasks: List of pending tasks

        Returns:
            List of quick win tasks (limited to top 5 to avoid overwhelming user)
        """
        quick_wins = []
        for task in tasks:
            tags = task.metadata.get('tags', [])
            if 'QUICK_WIN' in tags:
                quick_wins.append(task)

        # Sort by priority and return top 5
        sorted_wins = sorted(quick_wins, key=lambda t: cls._get_priority(t), reverse=True)
        return sorted_wins[:5]  # Limit to 5 to avoid information overload

    @classmethod
    def _get_parallel_tasks(cls, tasks: List[TaskNode]) -> List[TaskNode]:
        """Get tasks that can run in parallel

        Args:
            tasks: List of pending tasks

        Returns:
            List of parallelizable tasks
        """
        # Tasks are parallel if:
        # 1. They are leaf tasks (no children)
        # 2. They don't depend on each other
        # 3. They are command-type tasks (not manual)

        parallel = []
        for task in tasks:
            if not task.children and task.type == 'command':
                # Check if dependencies are met
                deps = task.metadata.get('depends_on', [])
                if not deps:  # No dependencies = can run in parallel
                    parallel.append(task)

        return sorted(parallel, key=lambda t: cls._get_priority(t), reverse=True)

    @classmethod
    def _get_ready_tasks(cls, tasks: List[TaskNode], profile) -> List[TaskNode]:
        """Get tasks ready to execute (dependencies met)

        Args:
            tasks: List of pending tasks
            profile: Target profile

        Returns:
            List of ready tasks
        """
        ready = []
        for task in tasks:
            if cls._are_dependencies_met(task, profile):
                ready.append(task)

        return sorted(ready, key=lambda t: cls._get_priority(t), reverse=True)

    @classmethod
    def _get_blocked_tasks(cls, tasks: List[TaskNode], profile) -> List[TaskNode]:
        """Get tasks blocked by dependencies

        Args:
            tasks: List of pending tasks
            profile: Target profile

        Returns:
            List of blocked tasks
        """
        blocked = []
        for task in tasks:
            if not cls._are_dependencies_met(task, profile):
                blocked.append(task)

        return blocked

    @classmethod
    def _are_dependencies_met(cls, task: TaskNode, profile) -> bool:
        """Check if task dependencies are met

        Args:
            task: Task node
            profile: Target profile

        Returns:
            True if all dependencies are met
        """
        dep_ids = task.metadata.get('depends_on', [])
        if not dep_ids:
            return True

        for dep_id in dep_ids:
            dep_task = profile.get_task(dep_id)
            if not dep_task or dep_task.status != 'completed':
                return False

        return True

    @classmethod
    def _select_next_task(cls, quick_wins: List[TaskNode], ready: List[TaskNode], parallel: List[TaskNode]) -> Optional[TaskNode]:
        """Select the next recommended task

        Priority:
        1. Quick wins
        2. Ready tasks with highest priority
        3. Parallel tasks

        Args:
            quick_wins: Quick win tasks
            ready: Ready tasks
            parallel: Parallel tasks

        Returns:
            Next task to execute or None
        """
        if quick_wins:
            return quick_wins[0]

        if ready:
            return ready[0]

        if parallel:
            return parallel[0]

        return None

    @classmethod
    def _get_priority(cls, task: TaskNode) -> int:
        """Calculate task priority

        Args:
            task: Task node

        Returns:
            Priority score (higher = more important)
        """
        priority = 0
        tags = task.metadata.get('tags', [])

        # OSCP relevance
        if 'OSCP:HIGH' in tags:
            priority += 100
        elif 'OSCP:MEDIUM' in tags:
            priority += 50
        elif 'OSCP:LOW' in tags:
            priority += 10

        # Quick wins
        if 'QUICK_WIN' in tags:
            priority += 200

        # Manual vs automated
        if 'MANUAL' in tags:
            priority += 30  # Manual tasks often more effective

        # Exploitation tasks
        if 'EXPLOIT' in tags:
            priority += 150

        # Research tasks
        if 'RESEARCH' in tags:
            priority += 20

        return priority

    @classmethod
    def _get_phase_status(cls, profile) -> str:
        """Get phase status message

        Args:
            profile: Target profile

        Returns:
            Status message
        """
        progress = profile.get_progress()
        phase = profile.phase

        total = progress['total']
        completed = progress['completed']
        pending = progress['pending']

        if total == 0:
            return f"Phase: {phase} - No tasks yet"

        completion_pct = (completed / total) * 100 if total > 0 else 0

        return f"Phase: {phase} - {completed}/{total} tasks completed ({completion_pct:.0f}%)"

    @classmethod
    def _generate_commands(cls, next_task: Optional[TaskNode], parallel_tasks: List[TaskNode]) -> List[str]:
        """Generate command suggestions

        Args:
            next_task: Next recommended task
            parallel_tasks: Tasks that can run in parallel

        Returns:
            List of command strings
        """
        commands = []

        if next_task and next_task.metadata.get('command'):
            commands.append(next_task.metadata['command'])

        for task in parallel_tasks:
            if task.metadata.get('command') and task != next_task:
                commands.append(task.metadata['command'])

        return commands[:5]  # Max 5 commands

    @classmethod
    def get_phase_suggestions(cls, profile) -> List[str]:
        """Get phase-specific suggestions

        Args:
            profile: Target profile

        Returns:
            List of suggestion strings
        """
        phase = profile.phase
        suggestions = []

        if phase == 'discovery':
            if not profile.ports:
                suggestions.append("Run port scan to discover open ports")
                suggestions.append("Use: nmap -p- --min-rate 1000 <TARGET> -oA port_scan")
            else:
                suggestions.append(f"Discovered {len(profile.ports)} open ports")
                suggestions.append("Run service detection scan on open ports")

        elif phase == 'service-detection':
            if not any(p.get('service') for p in profile.ports.values()):
                suggestions.append("Run service version detection")
                ports_str = ','.join(str(p) for p in profile.ports.keys())
                suggestions.append(f"Use: nmap -sV -sC -p {ports_str} <TARGET> -oA service_scan")
            else:
                suggestions.append("Services detected! Import results to auto-generate enumeration tasks")

        elif phase == 'service-specific':
            suggestions.append("Enumerate each discovered service")
            suggestions.append("Multiple tasks can run in parallel for faster enumeration")

        elif phase == 'exploitation':
            suggestions.append("Review findings and prioritize exploitation targets")
            if profile.findings:
                suggestions.append(f"Found {len(profile.findings)} findings to investigate")

        elif phase == 'post-exploitation':
            suggestions.append("Enumerate for privilege escalation")
            suggestions.append("Check for lateral movement opportunities")

        return suggestions
